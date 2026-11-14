"""Public execution requirements for an explicitly approved schema-2 destination.

The restricted canonical encoding is the contract adopted in issue #47. It is
not a general JCS encoder, a host attestation or canonical task authority.
Private native policy fingerprints keep their existing encoders.
"""

from dataclasses import fields
import hashlib
import json
import re

MAX_INTEGER = (1 << 53) - 1
MAX_MANIFEST_BYTES = 65536
MAX_APPROVAL_BYTES = 131072
QUALIFICATION_FIELDS = frozenset({
    "contract_version", "execution_manifest_sha256", "admission_revision",
})
BASE_PROTOCOLS = {
    "worker-lifecycle-v2", "destination-identity-v1", "execution-contract-v1",
    "local-admission-v1", "never-admitted-v1",
}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
REPOSITORY = re.compile(r"github:github\.com/[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_.-]+\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def integer(value, minimum=0, maximum=MAX_INTEGER):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("execution contract requires an exact bounded integer")
    return value


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("invalid execution contract identifier")
    return value


def repository(value):
    if (not isinstance(value, str) or not REPOSITORY.fullmatch(value)
            or value.rsplit("/", 1)[-1] in {".", ".."}):
        raise ValueError("execution contract repository must already be canonical")
    return value


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _scalars(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        integer(value)
    elif type(value) is str:
        if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("execution contract requires Unicode scalar strings")
    elif type(value) is list:
        for item in value:
            _scalars(item)
    elif type(value) is dict:
        for name, item in value.items():
            if type(name) is not str or not name.isascii():
                raise ValueError("execution contract uses fixed ASCII field names")
            _scalars(item)
    else:
        raise ValueError("execution contract contains an unsupported value")


def canonical_bytes(value):
    """Encode validated scalar values without changing strings or array order."""
    try:
        _scalars(value)
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (RecursionError, UnicodeError):
        raise ValueError("invalid execution contract encoding") from None
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("execution manifest exceeds its bound")
    return raw


def parse_approval(raw):
    from .destination import parse_binding

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_APPROVAL_BYTES:
        raise ValueError("invalid execution approval size")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate execution approval field")
            result[key] = value
        return result

    def invalid_number(_):
        raise ValueError("execution approval requires integer numbers")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_float=invalid_number, parse_constant=invalid_number)
        if type(value) is not dict or set(value) != {
            "approval_version", "deployment_id", "repository", "profile",
            "destination_binding", "manifest", "execution_manifest_sha256",
        }:
            raise ValueError()
        integer(value["approval_version"], 1, 1)
        identifier(value["deployment_id"])
        identifier(value["profile"])
        repository(value["repository"])
        parse_binding(value["destination_binding"])
        encoded = canonical_bytes(value["manifest"])
        if (value["execution_manifest_sha256"] != digest(encoded)
                or value["manifest"]["source"]["repository"] != value["repository"]):
            raise ValueError()
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise ValueError("invalid execution approval document") from None
    return value


def qualification(value):
    if type(value) is not dict or set(value) != QUALIFICATION_FIELDS:
        raise ValueError("complete original execution qualification is required")
    integer(value["contract_version"], 1, 1)
    integer(value["admission_revision"], 1)
    if not isinstance(value["execution_manifest_sha256"], str) or not DIGEST.fullmatch(value["execution_manifest_sha256"]):
        raise ValueError("invalid execution manifest digest")
    return dict(value)


def normalize_configuration(config):
    """Convert declared primary integer durations once, before native policies.

    Return a separate schema-1-shaped native input. The original schema-2 bytes
    and primary values remain with the caller and immutable destination record.
    """
    from .managed_configuration import ALLOWED, REQUIRED

    if (type(config) is not dict or type(config.get("schema_version")) is not int
            or config["schema_version"] != 2
            or not REQUIRED | {"execution_destination", "execution_contract"} <= set(config)
            or not set(config) <= ALLOWED | {"execution_contract"}):
        raise ValueError("invalid schema-2 configuration fields")
    selected = config["execution_contract"]
    if (type(selected) is not dict or set(selected) != {
            "version", "mode", "initial_worker_ceiling", "public_profiles"}
            or selected.get("mode") != "full"):
        raise ValueError("invalid full execution contract configuration")
    integer(selected["version"], 1, 1)
    integer(selected["initial_worker_ceiling"])
    public = selected["public_profiles"]
    if type(public) is not list or not 1 <= len(public) <= 256:
        raise ValueError("full execution contract requires bounded public profiles")
    declared = {}
    for item in public:
        if type(item) is not dict or set(item) != {"deployment_id", "repository", "profile", "model_service_policy_id"}:
            raise ValueError("invalid public profile declaration")
        key = (identifier(item["deployment_id"]), repository(item["repository"]), identifier(item["profile"]))
        if key in declared:
            raise ValueError("duplicate public profile declaration")
        declared[key] = item["model_service_policy_id"]
        if declared[key] is not None:
            identifier(declared[key])
    native = {key: value for key, value in config.items() if key != "execution_contract"}
    native["schema_version"] = 1
    profiles = config.get("profiles")
    if type(profiles) is not list or not 1 <= len(profiles) <= 256:
        raise ValueError("invalid full execution profiles")
    native["profiles"] = []
    keys = set()
    for item in profiles:
        if type(item) is not dict or "max_seconds" in item or "root_timeout_ms" not in item:
            raise ValueError("full root policy requires primary milliseconds")
        duration = integer(item["root_timeout_ms"], 1000, 86400000)
        if duration % 1000:
            raise ValueError("root milliseconds must represent whole native seconds")
        key = (identifier(item["deployment_id"]), repository(item["repository"]), identifier(item["name"]))
        if key in keys or item.get("environment_refs"):
            raise ValueError("unsupported full execution profile")
        keys.add(key)
        native["profiles"].append({name: value for name, value in item.items()
                                   if name != "root_timeout_ms"} | {"max_seconds": duration // 1000})
    if keys != set(declared):
        raise ValueError("public profiles must cover the exact configured scope set")
    models = set()
    for category, primary, previous, maximum in (
        ("models", "request_timeout_ms", "request_timeout_seconds", 120000),
        ("children", "max_child_ms", "max_child_seconds", 86400000),
    ):
        if category not in config:
            continue
        if type(config[category]) is not list:
            raise ValueError("invalid full policy list")
        native[category] = []
        for item in config[category]:
            if type(item) is not dict or type(item.get("policy")) is not dict:
                raise ValueError("invalid full policy")
            policy = item["policy"]
            if primary not in policy or previous in policy:
                raise ValueError("full policy requires primary milliseconds")
            if category == "children" and policy.get("public_discussion") is not None:
                raise ValueError("public discussion has no full execution projection")
            duration = integer(policy[primary], 1, maximum)
            key = (item.get("deployment_id"), item.get("repository"), item.get("profile"))
            if category == "models":
                models.add(key)
            converted = {name: value for name, value in policy.items() if name != primary}
            converted[previous] = duration / 1000
            native[category].append(item | {"policy": converted})
    if any((key in models) != (policy is not None) for key, policy in declared.items()):
        raise ValueError("model service policy must match the selected native model")
    return native


def primary_configuration(config):
    """Original public identifiers/durations, never reconstructed from floats."""
    normalize_configuration(config)
    return {
        "initial_worker_ceiling": config["execution_contract"]["initial_worker_ceiling"],
        "public_profiles": sorted(config["execution_contract"]["public_profiles"],
                                  key=lambda p: (p["deployment_id"], p["repository"], p["profile"])),
        "root_durations": sorted([[p["deployment_id"], p["repository"], p["name"], p["root_timeout_ms"]]
                                  for p in config["profiles"]]),
        "model_durations": sorted([[p["deployment_id"], p["repository"], p["profile"], p["policy"]["request_timeout_ms"]]
                                   for p in config.get("models", [])]),
        "child_durations": sorted([[p["deployment_id"], p["repository"], p["profile"], p["policy"]["max_child_ms"]]
                                   for p in config.get("children", [])]),
    }


def project(config, prepared, key, image):
    """Project every native field, using actually inspected image metadata."""
    from .docker_profile import DockerProfile
    from .model_broker import ModelPolicy
    from .child_types import ChildPolicy

    classified = {
        DockerProfile: "name deployment_id repository source_path image command base_commit uid memory_bytes cpu_quota pids_limit max_seconds max_archive_bytes environment_refs",
        ModelPolicy: "endpoint model token_ref max_calls max_output_tokens max_total_output_tokens request_timeout_seconds max_request_bytes max_response_bytes token_parameter",
        ChildPolicy: "max_children max_child_seconds max_child_turns capabilities uid_start command verify_argv max_result_bytes outcome_protocol session_protocol public_discussion",
    }
    for native_type, names in classified.items():
        if {field.name for field in fields(native_type)} != set(names.split()):
            raise ValueError("native policy contains an unclassified field")
    primary = primary_configuration(config)
    root_ms = {tuple(item[:3]): item[3] for item in primary["root_durations"]}
    model_ms = {tuple(item[:3]): item[3] for item in primary["model_durations"]}
    child_ms = {tuple(item[:3]): item[3] for item in primary["child_durations"]}
    service_ids = {(p["deployment_id"], p["repository"], p["profile"]): p["model_service_policy_id"]
                   for p in primary["public_profiles"]}
    profile = prepared.profile_by_scope[key]
    model = prepared.model_policies.get(key)
    child = prepared.child_policies.get(key)
    if profile.environment_refs or (child is not None and child.public_discussion is not None):
        raise ValueError("selected policy has no portable projection")
    if (type(image) is not dict or set(image) != {"config_digest", "os", "architecture", "variant"}
            or not isinstance(image["config_digest"], str) or not DIGEST.fullmatch(image["config_digest"])
            or any(type(image[name]) is not str or not image[name] for name in ("os", "architecture"))
            or (image["variant"] is not None and type(image["variant"]) is not str)):
        raise ValueError("invalid inspected image identity")
    protocols = set(BASE_PROTOCOLS)
    child_public = None
    if child is not None:
        protocols.add("bounded-children-v1")
        protocols.update(p for p in (child.outcome_protocol, child.session_protocol) if p is not None)
        child_public = {
            "protocol": "bounded-children-v1", "max_children": child.max_children,
            "max_child_ms": child_ms[key], "max_child_turns": child.max_child_turns,
            "capabilities": list(child.capabilities), "uid_start": child.uid_start,
            "child_argv": list(child.command), "verify_argv": list(child.verify_argv),
            "max_result_bytes": child.max_result_bytes, "outcome_protocol": child.outcome_protocol,
            "session_protocol": child.session_protocol, "public_discussion": None,
        }
    value = {
        "manifest_version": 1,
        "source": {"repository": repository(profile.repository), "base_commit": profile.base_commit},
        "image": dict(image),
        "execution": {"contract_id": "openjules-managed-docker-v1", "root_argv": list(profile.command),
                      "root_uid": profile.uid, "guest_environment_refs": "none"},
        "resources": {"memory_bytes": profile.memory_bytes, "swap_limit_bytes": profile.memory_bytes,
                      "cpu_period_us": 100000, "cpu_quota_us": profile.cpu_quota,
                      "pids_limit": profile.pids_limit, "root_timeout_ms": root_ms[key],
                      "max_archive_bytes": profile.max_archive_bytes},
        "confinement": {"network_mode": "none", "read_only_rootfs": True, "privileged": False,
                        "cap_drop": ["ALL"], "no_new_privileges": True,
                        "source_mount": "approved-snapshot-ro", "work_mount": "owned-volume-rw",
                        "broker_mount": "owned-broker-ro" if model else "absent",
                        "tmpfs_contract": "openjules-tmpfs-v1", "watchdog_uid": 65534,
                        "watchdog_contract": "children-reaping-v1" if child else "root-reaping-v1",
                        "restart_policy": "no"},
        "model": None if model is None else {
            "service_policy_id": service_ids[key], "model": model.model,
            "transport_contract": "host-broker-chat-completions-v1", "token_parameter": model.token_parameter,
            "max_calls": model.max_calls, "max_output_tokens": model.max_output_tokens,
            "max_total_output_tokens": model.max_total_output_tokens, "request_timeout_ms": model_ms[key],
            "max_request_bytes": model.max_request_bytes, "max_response_bytes": model.max_response_bytes,
        },
        "children": child_public, "required_protocols": sorted(protocols),
    }
    canonical_bytes(value)
    return value
