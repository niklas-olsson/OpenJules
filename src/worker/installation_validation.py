"""Private no-effects schema-1 validation after explicit isolated bootstrap.

Supported invocation: python -B -m src.worker.installation_validation --help
The caller binds producer source identity independently; this receipt is no
attestation, permission, live readiness, or portable policy equivalence.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from .managed_configuration import (
    ConfigurationInvalid, MAX_CONFIGURATION_BYTES, checked,
    parse_configuration_bytes, prepare_configuration,
)

CONTRACT = "openjules-installation-v1"
CONTRACT_PATH = Path(__file__).parent / "contracts" / (CONTRACT + ".json")
MAX_SCOPE_BYTES = 65536
MAX_RECEIPT_BYTES = 8_000_000
HOST_CHECKS = (
    "worker_credentials", "environment_credentials", "source_and_image",
    "destination_state", "managed_installation_context",
    "public_host_bindings_when_selected", "live_authority_and_canonical_permission",
    "runtime_readiness", "provider_qualification_when_selected",
)


class ContractUnavailable(ValueError):
    pass


def contract_bytes():
    try:
        with CONTRACT_PATH.open("rb") as source:
            raw = source.read(65537)
        value = json.loads(raw.decode("utf-8"))
        if (
            len(raw) > 65536 or value["validation_contract"] != CONTRACT
            or type(value["artifact_schema_version"]) is not int
            or value["artifact_schema_version"] != 1
        ):
            raise ValueError()
        return raw
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise ContractUnavailable("installation_contract_unavailable") from None


def _hash(raw, limit):
    # A prefix is never represented as the digest of the original input.
    return hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) and len(raw) <= limit else None


def _scope_declarations(raw, prepared):
    from .lifecycle import WorkerScope

    if not isinstance(raw, bytes) or len(raw) > MAX_SCOPE_BYTES:
        raise ConfigurationInvalid("scope_declarations_size", "/scope_declarations")

    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError()
            result[name] = value
        return result

    value = checked("scope_declarations_json", "/scope_declarations", lambda: json.loads(
        raw.decode("utf-8"), object_pairs_hook=pairs,
    ))
    if (
        not isinstance(value, dict) or set(value) != {"schema_version", "scopes"}
        or type(value["schema_version"]) is not int or value["schema_version"] != 1
        or not isinstance(value["scopes"], list) or not 1 <= len(value["scopes"]) <= 256
    ):
        raise ConfigurationInvalid("scope_declarations_invalid", "/scope_declarations")
    scopes = set()
    for index, item in enumerate(value["scopes"]):
        path = f"/scope_declarations/scopes/{index}"
        if not isinstance(item, dict) or set(item) != {"deployment_id", "repository"}:
            raise ConfigurationInvalid("scope_declarations_invalid", path)
        scope = checked("scope_declarations_invalid", path, lambda: WorkerScope(**item))
        if scope in scopes:
            raise ConfigurationInvalid("scope_declarations_duplicate", path)
        scopes.add(scope)
    if any(profile.scope not in scopes for profile in prepared.profiles):
        raise ConfigurationInvalid("scope_declarations_missing_profile", "/scope_declarations/scopes")


def descriptor(config, prepared):
    profiles = []
    for key, profile in sorted(prepared.profile_by_scope.items()):
        child = prepared.child_policies.get(key)
        public = key in prepared.public_policies
        capabilities = {"managed_dispatch": True, "external_root": True, "profile_supported": True}
        if child is not None:
            capabilities["child_grants"] = True
            if child.outcome_protocol is not None:
                capabilities["child_initial_outcome"] = 1
        peers = [{"contract": "keystone-polyphony/managed-runtime-v1", "required_capabilities": capabilities}]
        if public:
            peers.append({
                "contract": "keystone-polyphony/polyphony-public-conversation-v1",
                "required_capabilities": {"schema_version": 1, "profile": "polyphony-public-conversation", "execution_authorized": False},
            })
        profiles.append({
            "deployment_id": profile.deployment_id, "repository": profile.repository,
            "profile": profile.name, "base_commit": profile.base_commit, "image": profile.image,
            "features": {
                "model_broker": 1 if key in prepared.model_policies else None,
                "children": "bounded-children-v1" if child is not None else None,
                "child_outcome": child.outcome_protocol if child is not None else None,
                "child_session": child.session_protocol if child is not None else None,
                "public_discussion": "managed-public-pull-v1" if public else None,
            },
            "required_peer_contracts": peers,
        })
    return {
        "configuration_schema_version": 1,
        "execution_destination_identity": 1 if "execution_destination" in config else 0,
        "profiles": profiles,
    }


def _receipt(raw, scope_raw):
    return {
        "schema_version": 1, "service": "openjules", "validation_contract": CONTRACT,
        "contract_digest": hashlib.sha256(contract_bytes()).hexdigest(),
        "configuration_sha256": _hash(raw, MAX_CONFIGURATION_BYTES),
        "scope_declarations_sha256": _hash(scope_raw, MAX_SCOPE_BYTES),
        "valid": False, "errors": [], "descriptor": None,
        "host_checks_required": list(HOST_CHECKS),
    }


def validate_configuration_bytes(
    raw, *, expected_contract, expected_contract_digest, scope_declarations_bytes=None,
):
    """Read only supplied bytes and the installed static artifact, never a host probe."""
    result = _receipt(raw, scope_declarations_bytes)
    try:
        if expected_contract != CONTRACT:
            raise ConfigurationInvalid("contract_id_mismatch", "/expected_contract")
        if expected_contract_digest != result["contract_digest"]:
            raise ConfigurationInvalid("contract_digest_mismatch", "/expected_contract_digest")
        if raw is None:
            raise ConfigurationInvalid("configuration_input_unavailable", "/configuration")
        try:
            config = parse_configuration_bytes(raw)
            if type(config.get("schema_version")) is not int or config["schema_version"] != 1:
                raise ConfigurationInvalid("configuration_schema_unsupported", "/schema_version")
            prepared = prepare_configuration(config)
        except ConfigurationInvalid as error:
            raise ConfigurationInvalid(error.code, "/configuration" + error.path) from None
        if scope_declarations_bytes is not None:
            _scope_declarations(scope_declarations_bytes, prepared)
        result["descriptor"] = descriptor(config, prepared)
        result["valid"] = True
    except ConfigurationInvalid as error:
        result["errors"] = [{"code": error.code, "path": error.path}]
    return result


def _encoded_receipt(result):
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if len(encoded) > MAX_RECEIPT_BYTES:
        # Valid configuration bytes bound this projection, but fail closed if a
        # future projection change ever violates the supported receipt limit.
        result = result | {"valid": False, "descriptor": None,
                           "errors": [{"code": "receipt_size", "path": "/configuration"}]}
        encoded = (json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    return encoded, result["valid"]


def encode_receipt(result):
    return _encoded_receipt(result)[0]


def _read_input(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError()
        return source.read(limit + 1)


class _ValidationArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse's default diagnostics echo unknown arguments and their values.
        self.exit(2, "installation_arguments_invalid\n")


def main(argv=None):
    parser = _ValidationArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--expected-contract", required=True)
    parser.add_argument("--expected-contract-digest", required=True)
    parser.add_argument("--scope-declarations")
    args = parser.parse_args(argv)
    raw, scope_raw, input_error = None, None, None
    try:
        raw = _read_input(args.config, MAX_CONFIGURATION_BYTES)
    except (OSError, ValueError):
        input_error = ConfigurationInvalid("configuration_input_unavailable", "/configuration")
    if args.scope_declarations is not None:
        try:
            scope_raw = _read_input(args.scope_declarations, MAX_SCOPE_BYTES)
        except (OSError, ValueError):
            input_error = ConfigurationInvalid("scope_declarations_input_unavailable", "/scope_declarations")
    try:
        if input_error is not None:
            result = _receipt(raw, scope_raw)
            result["errors"] = [{"code": input_error.code, "path": input_error.path}]
        else:
            result = validate_configuration_bytes(raw, expected_contract=args.expected_contract,
                expected_contract_digest=args.expected_contract_digest, scope_declarations_bytes=scope_raw)
        encoded, valid = _encoded_receipt(result)
        sys.stdout.buffer.write(encoded)
        return 0 if valid else 2
    except ContractUnavailable:
        sys.stderr.write("installation_contract_unavailable\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
