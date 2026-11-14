"""Refusal tests for public-byte acquisition and untrusted archive inspection."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile

import pytest

from tools.managed_image import (
    Budget, DIGEST, LIMITS, PLATFORM, RECIPE, SOURCE_FILES, Refused,
    digest, inspect_archive, json_bytes, read_json, release_indexes,
    safe_relative, tar_add_bytes, validate_inputs, verify_file,
)


def archive(tmp_path, *, platform="amd64", duplicate=False, changed_layer=False,
            extra=None, layer_name="layer/layer.tar"):
    layer = b"a retained layer fixture"
    config = json_bytes({"os": "linux", "architecture": platform,
                         "rootfs": {"type": "layers", "diff_ids": [digest(layer)]}})
    result = tmp_path / "image.tar"
    with tarfile.open(result, "w") as output:
        tar_add_bytes(output, "config.json", config)
        tar_add_bytes(output, "manifest.json", json_bytes([
            {"Config": "config.json", "RepoTags": [], "Layers": [layer_name]}]))
        tar_add_bytes(output, layer_name, b"changed" if changed_layer else layer)
        if duplicate:
            tar_add_bytes(output, "config.json", config)
        if extra is not None:
            output.addfile(extra)
    return result


def manifest():
    return {
        "format": "openjules-managed-image-inputs-v1", "platform": PLATFORM,
        "builder": {"kind": "docker-classic", "network": "none", "package_mode": "sealed"},
        "snapshot": "20261113T000000Z", "source_repository": "https://github.com/niklas-olsson/OpenJules", "apt": {},
        "base_manifest_sha256": "sha256:" + "a" * 64, "base_config_id": "sha256:" + "b" * 64,
        "source_commit": "a" * 40, "recipe_commit": "b" * 40,
        "inputs": [{"path": "base/manifest.json", "url": "https://registry-1.docker.io/v2/library/python/manifests/sha256:" + "a" * 64,
                    "size": 100, "sha256": "sha256:" + "a" * 64}],
        "source_files": [{"path": path, "commit": ("b" if path == RECIPE else "a") * 40,
                          "size": 10, "sha256": "sha256:" + "c" * 64} for path in (*SOURCE_FILES, RECIPE)],
    }


def test_archive_distinguishes_config_archive_and_layer_identities(tmp_path):
    path = archive(tmp_path)
    result = inspect_archive(path)
    assert result["archive"]["sha256"] != result["image_id"]
    assert result["image_id"] == result["config_sha256"]
    assert result["layers"][0]["diff_id"] == digest(b"a retained layer fixture")
    assert result["registry_manifest_digest"] is None
    assert inspect_archive(path, expected=result) == result


def test_corrupt_archive_refuses_before_any_import(tmp_path):
    path = archive(tmp_path)
    expected = inspect_archive(path)
    with path.open("ab") as stream:
        stream.write(b"unapproved bytes")
    with pytest.raises(Refused, match="SHA-256 mismatch"):
        inspect_archive(path, expected=expected)


@pytest.mark.parametrize("kwargs", [
    {"platform": "arm64"}, {"duplicate": True}, {"changed_layer": True},
    {"layer_name": "../layer.tar"}, {"layer_name": "/layer.tar"},
])
def test_wrong_platform_and_unsafe_archive_members_refuse(tmp_path, kwargs):
    with pytest.raises(Refused):
        inspect_archive(archive(tmp_path, **kwargs))


def test_archive_symlinks_refuse_without_extraction(tmp_path):
    link = tarfile.TarInfo("outside")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    with pytest.raises(Refused, match="nonregular"):
        inspect_archive(archive(tmp_path, extra=link))
    assert not (tmp_path / "outside").exists()


def test_wrong_expected_image_refuses(tmp_path):
    path = archive(tmp_path)
    expected = inspect_archive(path)
    expected["image_id"] = expected["config_sha256"] = "sha256:" + "e" * 64
    with pytest.raises(Refused, match="approved image"):
        inspect_archive(path, expected=expected)


def test_oversized_archive_refuses_without_reading(tmp_path):
    path = tmp_path / "oversized.tar"
    with path.open("wb") as stream:
        stream.truncate(LIMITS["archive_bytes"] + 1)
    with pytest.raises(Refused, match="larger than"):
        inspect_archive(path)


def test_input_transfer_ceiling_reserves_before_acquisition(tmp_path):
    budget = Budget(tmp_path)
    budget.reserve(LIMITS["transfer_bytes"], "declared first candidate")
    with pytest.raises(Refused, match="transfer ceiling"):
        budget.reserve(1, "over limit")
    assert budget.transfer == LIMITS["transfer_bytes"]
    ledger = read_json((tmp_path / "acquisition-ledger.json").read_bytes())
    assert ledger["entries"] == [{"description": "declared first candidate", "reserved_bytes": LIMITS["transfer_bytes"]}]


def test_approved_manifest_rejects_invented_sources_or_origins():
    validate_inputs(manifest())
    for mutate in (
        lambda value: value["source_files"].append({"path": ".git/config"}),
        lambda value: value["inputs"][0].update(url="http://snapshot.debian.org/file/x"),
        lambda value: value["inputs"][0].update(url="https://user:password@snapshot.debian.org/file/x"),
        lambda value: value["inputs"][0].update(size=True),
        lambda value: value["inputs"].append(value["inputs"][0].copy()),
        lambda value: value["builder"].update(network="host"),
        lambda value: value.update(platform={"os": "linux", "architecture": "arm64", "variant": None}),
    ):
        changed = copy.deepcopy(manifest())
        mutate(changed)
        with pytest.raises(Refused):
            validate_inputs(changed)


def test_input_hash_and_size_are_independent_checks(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"package")
    record = {"size": 7, "sha256": digest(b"package")}
    verify_file(path, record)
    path.write_bytes(b"corrupt")
    with pytest.raises(Refused):
        verify_file(path, record)


def test_signed_index_requires_sha256_section():
    data = b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSHA256:\n " + b"a" * 64 + b" 12 main/binary-amd64/Packages.xz\nOther: x\n"
    assert release_indexes(data)["main/binary-amd64/Packages.xz"] == {"size": 12, "sha256": "sha256:" + "a" * 64}
    with pytest.raises(Refused):
        release_indexes(b"MD5Sum:\n abc 12 path\n")


def test_ambiguous_json_and_relative_paths_refuse():
    with pytest.raises(Refused):
        read_json(b'{"size": 1, "size": 2}')
    for path in ("../secret", "/absolute", "x/../secret", "x\\secret", "x//y"):
        with pytest.raises(Refused):
            safe_relative(path)


def test_owned_command_reaps_descendant_after_leader_returns(tmp_path):
    import os
    import sys
    budget = Budget(tmp_path)
    output = budget.run([sys.executable, "-c", "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print(p.pid)"])
    child = int(output)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_docker_environment_cannot_inherit_foreign_context(tmp_path, monkeypatch):
    from tools.managed_image import Daemon
    monkeypatch.setenv("DOCKER_CONTEXT", "foreign")
    monkeypatch.setenv("DOCKER_HOST", "tcp://foreign:2376")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    monkeypatch.setenv("DOCKER_CERT_PATH", "/private/certificates")
    monkeypatch.setenv("DOCKER_CONFIG", "/private/docker")
    monkeypatch.setenv("OPENAI_API_KEY", "host-only-fixture")
    daemon = Daemon(tmp_path, Budget(tmp_path), "owned")
    assert not any(key in daemon.env for key in (
        "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_CONFIG", "OPENAI_API_KEY"))


def test_extra_unreferenced_archive_payload_refuses(tmp_path):
    extra = tarfile.TarInfo("index.json")
    extra.size = 0
    with pytest.raises(Refused, match="unreferenced"):
        inspect_archive(archive(tmp_path, extra=extra))


def test_expected_config_must_equal_image_id(tmp_path):
    path = archive(tmp_path)
    expected = inspect_archive(path)
    expected["config_sha256"] = "sha256:" + "d" * 64
    with pytest.raises(Refused, match="expected archive contract"):
        inspect_archive(path, expected=expected)


def test_actual_apt_security_rows_need_no_legacy_checksum():
    from tools.managed_image import parse_apt_selection
    rows = """'file:/inputs/repos/debian-security/pool/updates/main/p/perl/perl-modules-5.36_5.36.0-7%2bdeb12u4_all.deb' perl-modules-5.36_5.36.0-7+deb12u4_all.deb 2817356
'file:/inputs/repos/debian/pool/main/g/git/git_2.39.5-0%2bdeb12u3_amd64.deb' git_1%3a2.39.5-0+deb12u3_amd64.deb 7264380 MD5Sum:b493c1ad123361900c2e3686921c8f39
"""
    result = parse_apt_selection(rows)
    assert result[0]["path"].endswith("perl-modules-5.36_5.36.0-7+deb12u4_all.deb")
    assert result[0]["size"] == 2817356
    assert result[1]["path"].endswith("git_2.39.5-0+deb12u3_amd64.deb")
    assert "1%3a" not in result[1]["path"]
    with pytest.raises(Refused):
        parse_apt_selection("'https://unapproved.invalid/pkg.deb' pkg.deb 123")


def test_qualification_executes_committed_source_without_checkout_mutations(tmp_path):
    import subprocess
    from tools.managed_image import TESTS, qualification_source
    repository = tmp_path / "repository"
    repository.mkdir()
    for path in (*TESTS, "src/worker/example.py", "pytest.ini"):
        target = repository / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# committed\n")
    git = ["git", "-C", str(repository)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "source"], check=True)
    revision = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    (repository / TESTS[0]).write_text("raise RuntimeError('dirty checkout')\n")
    (repository / "tests/conftest.py").write_text("raise RuntimeError('untracked checkout')\n")
    root = tmp_path / "owned"
    (root / "qualification").mkdir(parents=True)
    source, record = qualification_source(repository, root, Budget(root))
    assert record["revision"] == revision
    assert (source / TESTS[0]).read_text() == "# committed\n"
    assert not (source / "tests/conftest.py").exists()
    assert record["files"] == 5


def oci_archive(tmp_path, mutation=None):
    payloads = [b"first-layer", b"second-layer"]
    layer_ids = [digest(value) for value in payloads]
    config = {"os": "linux", "architecture": "amd64", "created": "2026-01-01T00:00:00Z",
              "container_config": {}, "config": {"User": "65532"},
              "rootfs": {"type": "layers", "diff_ids": layer_ids}}
    config_bytes = json_bytes(config)
    config_name = "blobs/sha256/" + digest(config_bytes).split(":")[1]
    descriptors = [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": identity, "size": len(data)}
                   for identity, data in zip(layer_ids, payloads)]
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                           "digest": digest(config_bytes), "size": len(config_bytes)},
                "layers": copy.deepcopy(descriptors)}
    if mutation:
        mutation(manifest)
    manifest_bytes = json_bytes(manifest)
    files = {config_name: config_bytes, "oci-layout": json_bytes({"imageLayoutVersion": "1.0.0"}),
             "blobs/sha256/" + digest(manifest_bytes).split(":")[1]: manifest_bytes,
             "index.json": json_bytes({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                                       "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                                      "digest": digest(manifest_bytes), "size": len(manifest_bytes)}]})}
    paths = ["blobs/sha256/" + identity.split(":")[1] for identity in layer_ids]
    files.update(zip(paths, payloads))
    files["manifest.json"] = json_bytes([{"Config": config_name, "RepoTags": None, "Layers": paths,
                                         "LayerSources": dict(zip(layer_ids, descriptors))}])
    for value in ({"id": "a" * 64, "created": "1970-01-01T00:00:00Z", "container_config": {}, "os": "linux"},
                  {**{key: value for key, value in config.items() if key != "rootfs"},
                   "id": "b" * 64, "parent": "a" * 64}):
        data = json_bytes(value)
        files["blobs/sha256/" + digest(data).split(":")[1]] = data
    target = tmp_path / "oci.tar"
    with tarfile.open(target, "w") as output:
        for name, data in files.items():
            tar_add_bytes(output, name, data)
    return target


def test_moby_oci_and_compatibility_metadata_share_one_image(tmp_path):
    diagnostic = tmp_path / "inventory.json"
    record = inspect_archive(oci_archive(tmp_path), diagnostic=diagnostic)
    assert record["layout"] == "moby-docker-save-oci-v1"
    assert len(record["metadata"]) == 5
    assert record["registry_manifest_digest"] is None
    assert any(item["path"] == "index.json" for item in read_json(diagnostic.read_bytes()))


@pytest.mark.parametrize("mutation", [
    lambda manifest: manifest["config"].update(digest="sha256:" + "f" * 64),
    lambda manifest: manifest["layers"].reverse(),
    lambda manifest: manifest["layers"][0].update(size=999),
    lambda manifest: manifest["layers"][0].update(urls=["https://unexpected.invalid/layer"]),
])
def test_oci_graph_cannot_disagree_with_docker_save(tmp_path, mutation):
    with pytest.raises(Refused, match="identities disagree"):
        inspect_archive(oci_archive(tmp_path, mutation))


def test_sparse_outer_layer_refuses_before_expanded_hash_read(tmp_path, monkeypatch):
    target = tmp_path / "sparse.tar"
    config = json_bytes({"os": "linux", "architecture": "amd64",
                         "rootfs": {"type": "layers", "diff_ids": [digest(b"x")]}})
    with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as output:
        tar_add_bytes(output, "config.json", config)
        tar_add_bytes(output, "manifest.json", json_bytes([
            {"Config": "config.json", "RepoTags": [], "Layers": ["layer/layer.tar"]}]))
        entry = tarfile.TarInfo("layer/layer.tar")
        entry.size = 1
        entry.pax_headers = {"GNU.sparse.map": "0,1", "GNU.sparse.size": str(1 << 40)}
        output.addfile(entry, io.BytesIO(b"x"))
    original = hashlib.file_digest

    def guard(stream, *args, **kwargs):
        assert not isinstance(stream, tarfile.ExFileObject), "expanded layer hash was reached"
        return original(stream, *args, **kwargs)

    monkeypatch.setattr(hashlib, "file_digest", guard)
    with pytest.raises(Refused, match="sparse"):
        inspect_archive(target)
