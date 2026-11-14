"""One explicitly selected, host-trusted GitHub issue task adapter.

The receipt owner invokes this whole boundary only after its durable callback
claim. Importing this module opens no credentials, clients, storage or queue.
Construction only snapshots selected bounded host credential configuration;
it creates no forge client or executor. This is the legacy host execution
path, including its existing guest Git credential access, not managed runtime
confinement or canonical task authority.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import threading

from src.api.ingress_policy import IngressError

from src.worker.execution_context import require_legacy_execution


class AdapterUnavailable(RuntimeError):
    """A closed diagnostic, never a remote response or credential value."""


def _private_app_key(path):
    """Bounded startup snapshot, with identity and content checked on use."""
    try:
        if type(path) is not str or not 1 <= len(path) <= 4096 or "\x00" in path:
            raise ValueError
        name = Path(path)
        if (not name.is_absolute() or str(name) != path or ".." in name.parts
                or name.parent.resolve(strict=True) != name.parent):
            raise ValueError
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1
                    or not 1 <= info.st_size <= 65536):
                raise ValueError
            raw = source.read(65537)
            if len(raw) > 65536:
                raise ValueError
        return raw.decode("utf-8"), (info.st_dev, info.st_ino, hashlib.sha256(raw).digest())
    except (OSError, ValueError, UnicodeError):
        raise IngressError("execution_credentials_unavailable", 503) from None


class ExecutionSnapshot:
    """Selected host credential configuration frozen for one service epoch.

    This reads only bounded local configuration. It does not mint, instantiate
    a forge/executor client or contact a remote service. Actual credential use
    remains inside the subsequently claimed adapter.
    """

    def __init__(self, bindings, environment, separation_validator=None):
        require_legacy_execution()
        self._environment = environment
        self._mutex = threading.RLock()
        self._revoked = False
        self._separation_validator = separation_validator
        self._bindings = {binding["binding_id"]: dict(binding) for binding in bindings}
        selected = set()
        if any(binding["installation_id"] is None for binding in bindings):
            selected.add("GITHUB_TOKEN")
        if any(binding["installation_id"] is not None for binding in bindings):
            selected.update({"GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH"})
        self._values = {key: environment.get(key) for key in selected}
        self._key_text, self._key_identity = None, None
        if "GITHUB_APP_PRIVATE_KEY_PATH" in selected:
            try:
                self._key_text, self._key_identity = _private_app_key(self._values["GITHUB_APP_PRIVATE_KEY_PATH"])
            except IngressError:
                pass  # Unavailable stays unavailable for this entire epoch.
        self._check_separation()

    def _check_separation(self):
        if self._separation_validator is not None:
            values = dict(self._values)
            values["OPENJULES_SELECTED_APP_KEY_MATERIAL"] = self._key_text
            try:
                self._separation_validator(values)
            except IngressError:
                self._revoked = True
                raise

    def validate_epoch(self):
        require_legacy_execution()
        with self._mutex:
            if self._revoked:
                raise IngressError("execution_credentials_changed", 503)
            self._check_separation()
            if any(self._environment.get(key) != value for key, value in self._values.items()):
                self._revoked = True
                raise IngressError("execution_credentials_changed", 503)
            if "GITHUB_APP_PRIVATE_KEY_PATH" in self._values:
                if self._key_identity is None:
                    raise IngressError("execution_credentials_unavailable", 503)
                try:
                    _text, identity = _private_app_key(self._values["GITHUB_APP_PRIVATE_KEY_PATH"])
                except IngressError:
                    self._revoked = True
                    raise IngressError("execution_credentials_changed", 503) from None
                if identity != self._key_identity:
                    self._revoked = True
                    raise IngressError("execution_credentials_changed", 503)
                app_id = self._values["GITHUB_APP_ID"]
                if (type(app_id) is not str or not 1 <= len(app_id) <= 19
                        or not app_id.isascii() or not app_id.isdecimal() or not 1 <= int(app_id) < 2**63):
                    raise IngressError("execution_credentials_unavailable", 503)
            if "GITHUB_TOKEN" in self._values:
                try:
                    _token(self._values["GITHUB_TOKEN"])
                except AdapterUnavailable:
                    raise IngressError("execution_credentials_unavailable", 503) from None

    def selected(self, binding):
        self.validate_epoch()
        if self._bindings.get(binding.get("binding_id")) != binding:
            raise AdapterUnavailable("selected_binding_changed")
        if binding["installation_id"] is None:
            return {"token": _token(self._values["GITHUB_TOKEN"])}
        return {"app_id": self._values["GITHUB_APP_ID"], "private_key": self._key_text}


def _token(value):
    if (type(value) is not str or not 1 <= len(value) <= 16384
            or any(ord(char) <= 32 or ord(char) >= 127 for char in value)):
        raise AdapterUnavailable("selected_execution_credential_unavailable")
    return value


class GitHubTaskAdapter:
    """Resolve exactly the approved PAT or App route after callback entry."""

    def __init__(self, *, bindings, environ=None, app_token_factory=None, client_factory=None,
                 provider_factory=None, executor_factory=None, separation_validator=None):
        # Dependency injection is a trusted Python construction option. No HTTP
        # field can select any of these factories or an environment variable.
        environment = os.environ if environ is None else environ
        normalized = tuple(binding.effect_input() if hasattr(binding, "effect_input") else dict(binding)
                           for binding in bindings)
        self._snapshot = ExecutionSnapshot(normalized, environment, separation_validator)
        self.app_token_factory = app_token_factory
        self.client_factory = client_factory
        self.provider_factory = provider_factory
        self.executor_factory = executor_factory

    def validate_epoch(self):
        self._snapshot.validate_epoch()

    def _credential(self, binding):
        installation = binding["installation_id"]
        selected = self._snapshot.selected(binding)
        if installation is None:
            return selected["token"]
        if type(installation) is not int or not 1 <= installation < 2**63:
            raise AdapterUnavailable("selected_installation_invalid")
        factory = self.app_token_factory
        if factory is None:
            from src.worker.auth import get_app_installation_token
            factory = get_app_installation_token
        # App-only means the ambient PAT is neither read nor used as fallback.
        return _token(factory(app_id=selected["app_id"], private_key_or_path=selected["private_key"],
                              installation_id=installation, safe_errors=True,
                              private_key_is_content=True))

    def __call__(self, original):
        require_legacy_execution()
        binding, task = original["binding"], original["task"]
        if binding.get("forge") != "github":
            raise AdapterUnavailable("task_adapter_unsupported")
        credential = self._credential(binding)
        client_factory = self.client_factory
        if client_factory is None:
            from github import Auth, Github

            def client_factory(token):
                return Github(auth=Auth.Token(token))

        client = client_factory(credential)
        try:
            # Numeric identity, approved name and issue-not-PR are checked before
            # executor construction or any comment. These reads are effects
            # inside the original attempted boundary, never pre-admission work.
            repository = client.get_repo(binding["repository"])
            if (type(repository.id) is not int
                    or repository.id != binding["repository_id"]
                    or type(repository.full_name) is not str
                    or repository.full_name != binding["repository"]):
                raise AdapterUnavailable("selected_repository_changed")
            issue = repository.get_issue(number=task["issue_id"])
            if (type(issue.number) is not int or issue.number != task["issue_id"]
                    or issue.pull_request is not None):
                raise AdapterUnavailable("selected_issue_unavailable")
            provider_factory = self.provider_factory
            if provider_factory is None:
                from src.forge.github import GitHubProvider
                provider_factory = GitHubProvider
            provider = provider_factory(github_client=client, token=credential,
                                        allow_environment_token=False)
            executor_factory = self.executor_factory
            if executor_factory is None:
                from src.worker.executor import TaskExecutor
                executor_factory = TaskExecutor
            from src.worker.dispatcher import TaskPayload
            payload = TaskPayload(
                forge="github", issue_id=task["issue_id"],
                issue_title=task["issue_title"], issue_body=task["issue_body"],
                repo_full_name=binding["repository"], repo_clone_url=binding["clone_url"],
                default_branch=binding["default_branch"],
                # The selected credential is already resolved. The legacy
                # executor must not derive another installation route.
                installation_id=None, sender="",
            )
            executor = executor_factory(github_provider=provider)
            result = executor.execute_task(payload, git_token=credential)
            if type(result) is not bool:
                raise AdapterUnavailable("task_handler_outcome_invalid")
            return result
        finally:
            client.close()
