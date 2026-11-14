"""Pinned native semantics and real no-effects CLI, never readiness evidence."""

from copy import deepcopy
from dataclasses import fields, MISSING
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from src.worker import installation_validation as validation
from src.worker import managed_service
from src.worker.managed_configuration import (
    ConfigurationInvalid, MAX_CONFIGURATION_BYTES, parse_configuration_bytes,
    prepare_configuration,
)

ROOT = Path(__file__).resolve().parents[2]
VECTORS_PATH = validation.CONTRACT_PATH.with_name("openjules-installation-v1-vectors.json")
VECTORS = json.loads(VECTORS_PATH.read_bytes())
CONTRACT_DIGEST = hashlib.sha256(validation.contract_bytes()).hexdigest()
CASES = {item["name"]: item for item in VECTORS["vectors"]}


def validate(raw, *, scope=None, **arguments):
    return validation.validate_configuration_bytes(
        raw, expected_contract=validation.CONTRACT,
        expected_contract_digest=CONTRACT_DIGEST,
        scope_declarations_bytes=scope, **arguments,
    )


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda vector: vector["name"])
def test_committed_shared_vectors_and_original_native_fingerprints(vector):
    raw = vector["configuration_utf8"].encode("utf-8")
    scope = vector["scope_declarations_utf8"]
    scope_raw = scope.encode("utf-8") if scope is not None else None
    result = validate(raw, scope=scope_raw)
    assert VECTORS["contract_digest"] == CONTRACT_DIGEST
    assert result == vector["expected"]
    assert validation.encode_receipt(result) == validation.encode_receipt(validate(raw, scope=scope_raw))
    assert len(validation.encode_receipt(result)) <= validation.MAX_RECEIPT_BYTES
    if result["valid"]:
        config = parse_configuration_bytes(raw)
        original = deepcopy(config)
        prepared = prepare_configuration(config)
        assert config == original
        actual = next(iter(prepared.fingerprints().values()))
        assert {key: actual[key] for key in ("docker", "model", "children")} == vector["original_native_fingerprints"]
    else:
        assert result["descriptor"] is None and len(result["errors"]) == 1


def test_artifact_declares_native_defaults_and_closed_receipt_vocabulary():
    from src.worker.docker_runtime import DockerProfile
    from src.worker.model_broker import ModelPolicy
    from src.worker.child_types import ChildPolicy

    artifact = json.loads(validation.contract_bytes())
    assert artifact["input_bounds"]["configuration_bytes"] == MAX_CONFIGURATION_BYTES == 1_000_000
    assert artifact["input_bounds"]["configuration_bytes"] < 1024 * 1024
    for key, constructor in (("docker_profile", DockerProfile), ("model_policy", ModelPolicy), ("child_policy", ChildPolicy)):
        defaults = {}
        for field in fields(constructor):
            if field.default is not MISSING:
                defaults[field.name] = field.default
            elif field.default_factory is not MISSING:
                defaults[field.name] = field.default_factory()
        assert json.loads(json.dumps(defaults)) == artifact["defaults"][key]
    for vector in VECTORS["vectors"]:
        receipt = vector["expected"]
        assert set(receipt) == set(artifact["receipt_fields"])
        assert receipt["host_checks_required"] == artifact["host_checks_required"]
        if receipt["valid"]:
            descriptor = receipt["descriptor"]
            assert set(descriptor) == set(artifact["descriptor"]["fields"])
            for profile in descriptor["profiles"]:
                assert set(profile) == set(artifact["descriptor"]["profile_fields"])
                assert set(profile["features"]) == set(artifact["descriptor"]["feature_values"])
                for peer in profile["required_peer_contracts"]:
                    assert set(peer) == set(artifact["descriptor"]["peer_fields"])
        else:
            assert receipt["errors"][0]["code"] in artifact["errors"]["codes"]


def test_destination_profile_only_api_retains_its_existing_count_bound():
    from src.worker.destination import policy_fingerprints

    template = json.loads(CASES["root"]["configuration_utf8"])["profiles"][0]
    profiles = [dict(template, name=f"profile-{index}") for index in range(256)]
    assert len(policy_fingerprints({"profiles": profiles})) == 256
    profiles.append(dict(template, name="profile-256"))
    with pytest.raises(ValueError, match="destination requires bounded approved profiles"):
        policy_fingerprints({"profiles": profiles})


@pytest.mark.parametrize("name", ["root", "model", "managed_public", "wrong_public_root_socket", "scope_declarations", "token_field_in_scope_declaration"])
def test_actual_cli_cold_import_has_no_runtime_or_secret_effects(tmp_path, name):
    vector = CASES[name]
    config = tmp_path / "explicit-config.json"
    config.write_bytes(vector["configuration_utf8"].encode("utf-8"))
    arguments = ["--config", str(config), "--expected-contract", validation.CONTRACT,
                 "--expected-contract-digest", CONTRACT_DIGEST]
    if vector["scope_declarations_utf8"] is not None:
        scopes = tmp_path / "explicit-scopes.json"
        scopes.write_bytes(vector["scope_declarations_utf8"].encode("utf-8"))
        arguments += ["--scope-declarations", str(scopes)]
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    result = subprocess.run([sys.executable, "-B", str(ROOT / "tests/fixtures/installation_validation_probe.py"),
                             str(ROOT), *arguments], cwd=tmp_path,
                            env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
                            capture_output=True, timeout=15)
    assert result.returncode == (0 if vector["expected"]["valid"] else 2), result.stderr.decode()
    assert result.stderr == b""
    assert result.stdout == validation.encode_receipt(vector["expected"])
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("name", ["boolean_parallelism", "guest_model_credentials", "explicit_null_session", "wrong_public_root_socket"])
def test_startup_and_direct_builder_reject_before_credentials_destination_or_clients(tmp_path, monkeypatch, name):
    from src.worker import destination, docker_runtime, model_broker
    from src.worker.managed_public_types import PublicPolicy

    raw = CASES[name]["configuration_utf8"].encode()
    config = json.loads(raw)
    path = tmp_path / "explicit-config.json"
    path.write_bytes(raw)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("effect before pure configuration refusal")

    original_reader = managed_service._read_object

    def reader(path, *, private=False):
        if private:
            forbidden()
        return original_reader(path, private=False)

    monkeypatch.setattr(managed_service, "_read_object", reader)
    monkeypatch.setattr(destination.DestinationState, "load", forbidden)
    monkeypatch.setattr("src.polyphony.managed_client.ManagedAuthorityClient.__init__", forbidden)
    monkeypatch.setattr(model_broker.ModelBroker, "__init__", forbidden)
    monkeypatch.setattr(docker_runtime.ManagedDockerRuntime, "__init__", forbidden)
    monkeypatch.setattr(PublicPolicy, "check_server", forbidden)
    monkeypatch.setattr(managed_service, "validate_managed_installation", forbidden)
    expected = CASES[name]["expected"]["errors"][0]["code"]
    with pytest.raises(ConfigurationInvalid, match="^" + expected + "$"):
        managed_service.load_configuration(path)
    with pytest.raises(ConfigurationInvalid, match="^" + expected + "$"):
        managed_service.build_app(config, {})
    assert calls == [] and path.read_bytes() == raw


def test_exact_byte_limits_hashes_expected_identity_and_error_redaction(tmp_path):
    raw = CASES["root"]["configuration_utf8"].encode()
    padded = raw + b" " * (MAX_CONFIGURATION_BYTES - len(raw))
    accepted = validate(padded)
    assert accepted["valid"]
    assert accepted["configuration_sha256"] == hashlib.sha256(padded).hexdigest()
    assert accepted["configuration_sha256"] != validate(raw)["configuration_sha256"]
    oversized = validate(padded + b" ")
    assert oversized["configuration_sha256"] is None
    assert oversized["errors"] == [{"code":"configuration_size", "path":"/configuration"}]
    oversized_scopes = validate(raw, scope=b" " * (validation.MAX_SCOPE_BYTES + 1))
    assert oversized_scopes["scope_declarations_sha256"] is None and oversized_scopes["descriptor"] is None
    invalid_utf8 = validate(b"\xff")
    assert invalid_utf8["configuration_sha256"] == hashlib.sha256(b"\xff").hexdigest()
    assert invalid_utf8["descriptor"] is None
    for name, value, code in (("expected_contract", "private-user-canary", "contract_id_mismatch"),
                              ("expected_contract_digest", "private-path-canary", "contract_digest_mismatch")):
        arguments = {"expected_contract":validation.CONTRACT,"expected_contract_digest":CONTRACT_DIGEST,name:value}
        refused = validation.validate_configuration_bytes(raw, **arguments)
        assert refused["contract_digest"] == CONTRACT_DIGEST
        assert refused["validation_contract"] == validation.CONTRACT
        assert refused["descriptor"] is None and refused["errors"] == [{"code":code,"path":"/"+name}]
        assert value not in validation.encode_receipt(refused).decode()
    invalid = json.loads(raw)
    invalid["profiles"][0]["source_path"] = "private-host-path-canary"
    invalid["authority"]["token_ref"] = "private-secret-value-canary"
    receipt = validate(json.dumps(invalid).encode())
    assert receipt["descriptor"] is None
    assert "canary" not in validation.encode_receipt(receipt).decode()


def test_bounded_failure_receipt_and_cli_exit_agree(tmp_path, monkeypatch, capfd):
    config = json.loads(CASES["root"]["configuration_utf8"])
    template = config["profiles"][0]
    config["profiles"] = [dict(template, name=f"profile-{index}") for index in range(10)]
    path = tmp_path / "explicit-config.json"
    path.write_bytes(json.dumps(config).encode())
    # Exercise the output boundary without allocating a maximum-size receipt.
    monkeypatch.setattr(validation, "MAX_RECEIPT_BYTES", 2048)
    assert validation.main([
        "--config", str(path), "--expected-contract", validation.CONTRACT,
        "--expected-contract-digest", CONTRACT_DIGEST,
    ]) == 2
    captured = capfd.readouterr()
    raw = captured.out.encode("ascii")
    result = json.loads(raw)
    assert len(raw) <= 2048 and raw.endswith(b"\n") and captured.err == ""
    assert not result["valid"] and result["descriptor"] is None
    assert result["errors"] == [{"code": "receipt_size", "path": "/configuration"}]


@pytest.mark.parametrize("name", ["boolean_parallelism", "wrong_public_root_socket"])
def test_actual_service_cli_checks_complete_configuration_before_cold_import_effects(tmp_path, name):
    path = tmp_path / "invalid-config.json"
    path.write_bytes(CASES[name]["configuration_utf8"].encode())
    result = subprocess.run([sys.executable, "-B", str(ROOT / "tests/fixtures/installation_validation_probe.py"),
                             str(ROOT), "managed-service", "--config", str(path)], cwd=tmp_path,
                            env={"PATH":os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE":"1"},
                            capture_output=True, timeout=15)
    assert result.returncode == 2, result.stderr.decode()
    assert result.stdout == b""
    assert b"managed service configuration is invalid" in result.stderr
    assert b"Traceback" not in result.stderr


def test_valid_structure_keeps_credentials_and_host_bindings_unresolved(tmp_path):
    config = json.loads(CASES["root"]["configuration_utf8"])
    config["credentials_file"] = str(tmp_path / "missing-private-credentials.json")
    raw = json.dumps(config).encode()
    receipt = validate(raw)
    assert receipt["valid"] and receipt["host_checks_required"] == list(validation.HOST_CHECKS)
    path = tmp_path / "explicit-config.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="regular file"):
        managed_service.load_configuration(path)
    public = validate(CASES["managed_public"]["configuration_utf8"].encode())
    assert public["valid"]
    assert "public_host_bindings_when_selected" in public["host_checks_required"]


def test_invalid_managed_command_still_latches_legacy_refusal(tmp_path, monkeypatch, capsys):
    from src.worker import execution_context as context

    monkeypatch.setattr(context, "_managed_process", False)
    monkeypatch.setattr(context, "_selector_observed", False)
    path = tmp_path / "invalid-config.json"
    path.write_bytes(CASES["boolean_parallelism"]["configuration_utf8"].encode())
    monkeypatch.setattr(sys, "argv", ["managed-service", "--config", str(path)])
    with pytest.raises(SystemExit) as stopped:
        managed_service.main()
    assert stopped.value.code == 2
    with pytest.raises(context.LegacyExecutionRefused):
        context.require_legacy_execution()
    assert "managed service configuration is invalid" in capsys.readouterr().err


@pytest.mark.parametrize("case", [
    "unknown_flag", "unknown_flag_value", "extra_positional", "missing_required",
    "missing_value", "empty",
])
def test_actual_cli_usage_errors_are_fixed_bounded_and_do_not_echo(tmp_path, case):
    arguments = [
        "--config", "/private/CONFIG_PATH_CANARY",
        "--expected-contract", validation.CONTRACT,
        "--expected-contract-digest", CONTRACT_DIGEST,
    ]
    if case == "unknown_flag":
        arguments += ["--PRIVATE_FLAG_CANARY"]
    elif case == "unknown_flag_value":
        arguments += ["--PRIVATE_FLAG_CANARY", "PRIVATE_VALUE_CANARY" * 1024]
    elif case == "extra_positional":
        arguments += ["PRIVATE_POSITIONAL_CANARY"]
    elif case == "missing_required":
        arguments = arguments[:2]
    elif case == "missing_value":
        arguments += ["--scope-declarations"]
    else:
        arguments = []
    # Run the actual CLI under the existing cold-import no-effects guards.
    # Argument refusal must precede even the attempted read of the private path.
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "tests/fixtures/installation_validation_probe.py"),
         str(ROOT), *arguments], cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, timeout=15,
    )
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr == b"installation_arguments_invalid\n"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("argument", ["--help", "-h"])
def test_actual_cli_help_remains_available_without_inputs(tmp_path, argument):
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "tests/fixtures/installation_validation_probe.py"),
         str(ROOT), argument], cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, timeout=15,
    )
    assert result.returncode == 0 and result.stderr == b""
    assert b"usage:" in result.stdout
    for option in (b"--config", b"--expected-contract", b"--expected-contract-digest", b"--scope-declarations"):
        assert option in result.stdout
    assert list(tmp_path.iterdir()) == []
