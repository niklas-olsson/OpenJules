"""Pure schema-1 preparation shared by startup and installation validation.

Native policy constructors remain the semantic owners. This module never opens
credentials, host paths or journals, constructs brokers/clients, or runs a probe.
"""

from dataclasses import dataclass
import json
import math
import re
from urllib.parse import urlsplit
from pathlib import Path

MAX_CONFIGURATION_BYTES = 1_000_000
REQUIRED = frozenset({
    "schema_version", "state_directory", "lifecycle_database", "credentials_file",
    "authority", "profiles",
})
ALLOWED = REQUIRED | {
    "host", "port", "poll_interval_seconds", "max_parallel", "models", "children",
    "execution_destination",
}


def validate_authority_configuration(
    endpoint: str, token_ref: str, *, timeout_seconds: float = 10,
    max_response_bytes: int = 5_000_000,
):
    """Pure existing URL/reference/bound checks; never resolve a credential."""
    parts = urlsplit(endpoint)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
        or (
            parts.scheme == "http"
            and parts.hostname not in {"localhost", "127.0.0.1", "::1"}
        )
    ):
        raise ValueError("authority endpoint requires HTTPS or a loopback HTTP root")
    parts.port
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 120
    ):
        raise ValueError("authority timeout must be between zero and 120 seconds")
    if type(max_response_bytes) is not int or not 1024 <= max_response_bytes <= 20_000_000:
        raise ValueError("invalid authority response limit")
    if not isinstance(token_ref, str) or not re.fullmatch(r"env:[A-Za-z_][A-Za-z0-9_]*", token_ref):
        raise ValueError("authority credential must be an environment reference")


def validate_dispatcher_configuration(poll_interval_seconds=1, max_parallel=16):
    """Pure existing scheduler bounds, before journal or thread construction."""
    if (
        isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not math.isfinite(poll_interval_seconds)
        or not 0.1 <= poll_interval_seconds <= 60
    ):
        raise ValueError("invalid dispatcher poll interval")
    if type(max_parallel) is not int or not 1 <= max_parallel <= 256:
        raise ValueError("invalid dispatcher parallelism")


class ConfigurationInvalid(ValueError):
    """A fixed code and schema pointer, never a supplied value or native error."""

    def __init__(self, code, path=""):
        self.code, self.path = code, path
        super().__init__(code)


def checked(code, path, function):
    try:
        return function()
    except ConfigurationInvalid:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, RecursionError):
        raise ConfigurationInvalid(code, path) from None


def parse_configuration_bytes(raw):
    """Preserve schema-1 duplicate handling and the original decimal byte cap."""
    if not isinstance(raw, bytes) or len(raw) > MAX_CONFIGURATION_BYTES:
        raise ConfigurationInvalid("configuration_size")
    duplicate = False

    def pairs(items):
        nonlocal duplicate
        result = {}
        for key, value in items:
            if key in result:
                duplicate = True
            result[key] = value
        return result

    data = checked("configuration_json", "", lambda: json.loads(
        raw.decode("utf-8"), object_pairs_hook=pairs,
    ))
    if not isinstance(data, dict):
        raise ConfigurationInvalid("configuration_object")
    children = data.get("children")
    if duplicate and (data.get("schema_version") == 2 or "execution_destination" in data or (
        isinstance(children, list) and any(
            isinstance(item, dict) and isinstance(item.get("policy"), dict)
            and "public_discussion" in item["policy"] for item in children
        )
    )):
        raise ConfigurationInvalid("configuration_duplicate_fields")
    return data


@dataclass(frozen=True)
class PreparedProfiles:
    profiles: tuple
    profile_by_scope: dict
    model_policies: dict
    child_policies: dict
    public_policies: dict

    def fingerprints(self):
        return {key: {
            "version": 1, "docker": profile.fingerprint,
            "model": self.model_policies[key].fingerprint if key in self.model_policies else None,
            "children": self.child_policies[key].fingerprint if key in self.child_policies else None,
        } for key, profile in self.profile_by_scope.items()}


def prepare_profiles(config):
    """Validate selected runtime/model/child/public semantics without host checks."""
    if type(config.get("schema_version")) is int and config["schema_version"] == 2:
        from .execution_contract import normalize_configuration
        config = checked("execution_contract_invalid", "/execution_contract", lambda: normalize_configuration(config))
    from .docker_profile import DockerProfile
    from .model_broker import ModelPolicy
    from .child_types import ChildPolicy
    from .managed_public_types import PublicPolicy, validate_root_command

    originals = config.get("profiles")
    if not isinstance(originals, list) or not originals:
        raise ConfigurationInvalid("profiles_required", "/profiles")
    if "execution_destination" in config and len(originals) > 256:
        raise ConfigurationInvalid("destination_profile_limit", "/profiles")
    profiles, profile_by_scope = [], {}
    for index, original in enumerate(originals):
        path = f"/profiles/{index}"
        if not isinstance(original, dict):
            raise ConfigurationInvalid("profile_invalid", path)
        # DockerProfile already normalizes command and environment references.
        profile = checked("profile_invalid", path, lambda: DockerProfile(**original))
        checked("profile_invalid", path, lambda: profile.fingerprint)
        key = (profile.deployment_id, profile.repository, profile.name)
        if key in profile_by_scope:
            raise ConfigurationInvalid("profile_duplicate", path)
        profiles.append(profile)
        profile_by_scope[key] = profile

    models, children, public = {}, {}, {}
    for category, constructor, policies in (
        ("models", ModelPolicy, models), ("children", ChildPolicy, children),
    ):
        items = config.get(category, [])
        if not isinstance(items, list) or len(items) > len(profiles):
            raise ConfigurationInvalid("policy_list_invalid", "/" + category)
        for index, item in enumerate(items):
            path = f"/{category}/{index}"
            if (
                not isinstance(item, dict)
                or set(item) != {"deployment_id", "repository", "profile", "policy"}
                or not isinstance(item["policy"], dict)
                or any(not isinstance(item[name], str) for name in ("deployment_id", "repository", "profile"))
            ):
                raise ConfigurationInvalid("policy_binding_invalid", path)
            key = (item["deployment_id"], item["repository"], item["profile"])
            if key not in profile_by_scope or key in policies:
                raise ConfigurationInvalid("policy_binding_unknown_or_duplicate", path)
            source = item["policy"]
            if category == "models":
                if profile_by_scope[key].environment_refs:
                    raise ConfigurationInvalid("model_guest_credentials", path + "/policy")
            else:
                if key not in models:
                    raise ConfigurationInvalid("child_model_required", path)
                if "session_protocol" in source and source["session_protocol"] != "cold-clarification-v1":
                    raise ConfigurationInvalid("child_session_unsupported", path + "/policy/session_protocol")
                if "public_discussion" in source and not isinstance(source["public_discussion"], dict):
                    raise ConfigurationInvalid("child_public_unsupported", path + "/policy/public_discussion")
            policy = checked("policy_invalid", path + "/policy", lambda: constructor(**source))
            checked("policy_invalid", path + "/policy", lambda: policy.fingerprint)
            if category == "children":
                profile = profile_by_scope[key]
                checked("child_root_incompatible", path + "/policy", lambda: policy.validate_root(profile.uid, profile.max_seconds))
                if policy.public_discussion is not None:
                    # Host executable/scope-key verification stays at startup.
                    checked("public_root_command", f"/profiles/{profiles.index(profile)}/command",
                            lambda: validate_root_command(profile.command))
                    public[key] = checked("policy_invalid", path + "/policy/public_discussion",
                                          lambda: PublicPolicy.parse(policy.public_discussion))
            policies[key] = policy
    return PreparedProfiles(tuple(profiles), profile_by_scope, models, children, public)


def prepare_configuration(config):
    """Complete pure startup phase, including authority and dispatcher bounds."""
    from .destination import destination_configuration

    if isinstance(config, dict) and type(config.get("schema_version")) is int and config["schema_version"] == 2:
        from .execution_contract import normalize_configuration
        native = checked("execution_contract_invalid", "/execution_contract", lambda: normalize_configuration(config))
        return prepare_configuration(native)

    if not isinstance(config, dict) or not REQUIRED <= set(config) <= ALLOWED:
        raise ConfigurationInvalid("configuration_fields")
    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ConfigurationInvalid("configuration_schema_unsupported", "/schema_version")
    checked("destination_invalid", "/execution_destination", lambda: destination_configuration(config))
    for name in ("state_directory", "lifecycle_database", "credentials_file"):
        if not isinstance(config[name], str) or not Path(config[name]).is_absolute():
            raise ConfigurationInvalid("path_not_absolute", "/" + name)
    if config.get("host", "127.0.0.1") not in ("127.0.0.1", "::1"):
        raise ConfigurationInvalid("host_not_loopback", "/host")
    port = config.get("port", 8000)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigurationInvalid("port_invalid", "/port")
    authority = config["authority"]
    if not isinstance(authority, dict) or set(authority) != {"endpoint", "token_ref"}:
        raise ConfigurationInvalid("authority_fields", "/authority")
    checked("authority_invalid", "/authority", lambda: validate_authority_configuration(**authority))
    checked("dispatcher_poll_interval", "/poll_interval_seconds", lambda: validate_dispatcher_configuration(
        config.get("poll_interval_seconds", 1), 16,
    ))
    checked("dispatcher_parallelism", "/max_parallel", lambda: validate_dispatcher_configuration(
        1, config.get("max_parallel", 16),
    ))
    return prepare_profiles(config)
