"""Real private files and fresh-process checks for the offline refusal context."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from src.worker import execution_context as context


@pytest.fixture
def installation(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(context, "_managed_process", False)
    monkeypatch.setattr(context, "_selector_observed", False)
    config = tmp_path / "openjules.json"
    config.write_bytes(b'{"schema_version":1,"profiles":[]}\n')
    config.chmod(0o600)
    return tmp_path, config


def selector(installation, **changes):
    directory, config = installation
    value = {
        "schema_version": 1,
        "managed_config_path": str(config.resolve()),
        "managed_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
    }
    value.update(changes)
    raw = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    path = directory / context.SELECTOR_NAME
    path.write_bytes(raw)
    path.chmod(0o600)
    return path, raw


def fresh_probe(directory):
    # The same real entrypoint is run in a fresh process with a private fixture
    # interpreter prefix. ZPM separately qualifies its actual installed venv.
    code = """
import runpy,sys
sys.prefix=sys.argv[1]
sys.argv=['execution_context','--probe-managed-installation']
runpy.run_module('src.worker.execution_context',run_name='__main__')
"""
    return subprocess.run(
        [sys.executable, "-c", code, str(directory)],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        timeout=5,
        env={key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL"}},
    )


def test_standalone_absence_and_managed_probe_have_different_contracts(installation):
    directory, _ = installation
    assert context.validate_managed_installation() is None
    context.require_legacy_execution()
    result = fresh_probe(directory)
    assert result.returncode == 2
    assert json.loads(result.stdout) == {"error": "managed_installation_unavailable"}

    _, raw = selector(installation)
    expected = {
        "schema_version": 1,
        "selector_sha256": hashlib.sha256(raw).hexdigest(),
        "legacy_execution_allowed": False,
    }
    assert context.probe_managed_installation() == expected
    result = fresh_probe(directory)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == expected
    assert result.stderr == b""
    with pytest.raises(context.LegacyExecutionRefused):
        context.require_legacy_execution()


def test_observed_context_cannot_downgrade_after_removal_or_environment_change(
    installation, monkeypatch
):
    marker, _ = selector(installation)
    with pytest.raises(context.LegacyExecutionRefused):
        context.require_legacy_execution()
    marker.unlink()
    monkeypatch.setenv("OPENJULES_MODE", "standalone")
    monkeypatch.setenv("OPENJULES_MANAGED_CONFIG", "")
    with pytest.raises(context.LegacyExecutionRefused):
        context.require_legacy_execution()
    with pytest.raises(context.ManagedInstallationInvalid):
        context.validate_managed_installation()


def test_explicit_managed_entrypoint_context_never_needs_a_fallback_marker(installation):
    assert context.validate_managed_installation() is None
    context.require_legacy_execution()
    context.enter_managed_context()
    with pytest.raises(context.LegacyExecutionRefused):
        context.require_legacy_execution()
    # Alternate canonical-only configs are not selected by this predicate.
    assert context.validate_managed_installation() is None


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"managed_config_path": "relative/openjules.json"},
        {"managed_config_sha256": "A" * 64},
        {"managed_config_sha256": "0" * 64},
        {"unexpected": "standalone"},
    ],
)
def test_invalid_selector_never_allows_legacy_execution(installation, changes):
    selector(installation, **changes)
    with pytest.raises(context.ManagedInstallationInvalid, match="^managed_installation_unavailable$"):
        context.validate_managed_installation()
    with pytest.raises(context.LegacyExecutionRefused, match="^managed_installation_requires_canonical_ingress$"):
        context.require_legacy_execution()


@pytest.mark.parametrize("raw", [b"null", b"[]", b"{", b"\xff", b'{"schema_version":1,"schema_version":1}'])
def test_invalid_json_and_duplicate_fields_refuse_before_effects(installation, raw):
    marker, _ = selector(installation)
    marker.write_bytes(raw)
    with pytest.raises(context.ManagedInstallationInvalid):
        context.probe_managed_installation()
    with pytest.raises(context.LegacyExecutionRefused):
        context.require_legacy_execution()


@pytest.mark.parametrize("target", ["selector", "config"])
def test_public_permissions_and_symlinks_cannot_replace_private_regular_files(
    installation, target
):
    marker, raw = selector(installation)
    _, config = installation
    path = marker if target == "selector" else config
    path.chmod(0o644)
    with pytest.raises(context.ManagedInstallationInvalid):
        context.validate_managed_installation()
    path.chmod(0o600)
    assert context.validate_managed_installation() == hashlib.sha256(raw).hexdigest()
    saved = path.with_suffix(".saved")
    path.rename(saved)
    path.symlink_to(saved)
    with pytest.raises(context.ManagedInstallationInvalid):
        context.validate_managed_installation()
    path.unlink()
    path.symlink_to(path)
    with pytest.raises(context.ManagedInstallationInvalid, match="^managed_installation_unavailable$"):
        context.validate_managed_installation()


@pytest.mark.parametrize("target", ["selector", "config"])
def test_fifo_refusal_is_bounded_before_a_writer_exists(installation, target):
    marker, _ = selector(installation)
    directory, config = installation
    path = marker if target == "selector" else config
    path.unlink()
    os.mkfifo(path, mode=0o600)
    result = fresh_probe(directory)
    assert result.returncode == 2, result.stderr
    assert json.loads(result.stdout) == {"error": "managed_installation_unavailable"}


@pytest.mark.parametrize("target", ["selector", "config"])
def test_exact_file_byte_bounds_and_changed_binding(installation, target):
    marker, raw = selector(installation)
    _, config = installation
    if target == "selector":
        marker.write_bytes(raw + b" " * (context.SELECTOR_LIMIT - len(raw)))
        assert context.validate_managed_installation() == hashlib.sha256(marker.read_bytes()).hexdigest()
        marker.write_bytes(marker.read_bytes() + b" ")
    else:
        config.write_bytes(b" " * context.CONFIG_LIMIT)
        marker, _ = selector(installation)
        assert context.validate_managed_installation()
        config.write_bytes(config.read_bytes() + b" ")
        # Bind the oversized actual bytes so the size, not digest, is decisive.
        marker, _ = selector(installation)
    with pytest.raises(context.ManagedInstallationInvalid):
        context.validate_managed_installation()


def test_changed_original_config_and_unreadable_marker_are_fixed_refusals(
    installation, monkeypatch
):
    marker, _ = selector(installation)
    _, config = installation
    config.write_bytes(b'{"changed":true}')
    with pytest.raises(context.ManagedInstallationInvalid):
        context.validate_managed_installation()

    original = Path.lstat
    def inaccessible(path, *args, **kwargs):
        if path == marker:
            raise PermissionError("private path must not appear in refusal")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(context, "_selector_observed", False)
    monkeypatch.setattr(Path, "lstat", inaccessible)
    with pytest.raises(context.LegacyExecutionRefused, match="^managed_installation_requires_canonical_ingress$"):
        context.require_legacy_execution()


def test_probe_imports_no_runtime_provider_or_network_dependencies(installation):
    directory, _ = installation
    selector(installation)
    code = """
import builtins,json,runpy,sys
sys.prefix=sys.argv[1]
original=builtins.__import__
def restricted(name,*args,**kwargs):
    if name.split('.')[0] in {'docker','litellm','requests','httpx','fastapi','socket'}:
        raise AssertionError('offline probe imported an effectful dependency')
    return original(name,*args,**kwargs)
builtins.__import__=restricted
sys.argv=['execution_context','--probe-managed-installation']
runpy.run_module('src.worker.execution_context',run_name='__main__')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(directory)],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["legacy_execution_allowed"] is False
