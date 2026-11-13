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
