"""The whole selected adapter, including credentials, runs after admission."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from src.api.ingress_adapter import AdapterUnavailable, GitHubTaskAdapter
from src.api.ingress_policy import IngressError


def original(installation=None):
    return {
        "principal_id": "operator", "binding_id": "repo", "operation_id": "original",
        "binding": {"binding_id": "repo", "forge": "github", "repository": "owner/repo",
                    "repository_id": 123, "installation_id": installation,
                    "clone_url": "https://github.com/owner/repo.git", "default_branch": "main"},
        "task": {"issue_id": 7, "issue_title": "Small task", "issue_body": "Keep original input."},
    }


class TrackedEnvironment(dict):
    def __init__(self, *args, forbidden=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.forbidden, self.reads = set(forbidden), []

    def get(self, key, default=None):
        assert key not in self.forbidden
        self.reads.append(key)
        return super().get(key, default)


def adapter_fixture(*, environment=None, outcome=True, issue_pr=None, repository_id=123, installation=None):
    calls = []
    issue = SimpleNamespace(number=7, pull_request=issue_pr)

    class Repository:
        id = repository_id
        full_name = "owner/repo"

        def get_issue(self, *, number):
            calls.append(("issue", number))
            return issue

    class Client:
        def get_repo(self, name):
            calls.append(("repository", name))
            return Repository()

        def close(self):
            calls.append(("close",))

    client, provider = Client(), object()

    def mint(**kwargs):
        calls.append(("mint", kwargs))
        return "selected-app-token"

    def clients(token):
        calls.append(("client", token))
        return client

    def providers(**kwargs):
        assert kwargs["github_client"] is client
        assert kwargs["allow_environment_token"] is False
        calls.append(("provider", kwargs["token"]))
        return provider

    class Executor:
        def execute_task(self, payload, *, git_token):
            calls.append(("execute", payload.model_dump(), git_token))
            return outcome

    def executors(**kwargs):
        assert kwargs == {"github_provider": provider}
        calls.append(("executor",))
        return Executor()

    env = {"GITHUB_TOKEN": "selected-pat"} if environment is None else environment
    adapter = GitHubTaskAdapter(bindings=[original(installation)["binding"]], environ=env, app_token_factory=mint,
                                client_factory=clients, provider_factory=providers,
                                executor_factory=executors)
    assert calls == []
    return adapter, calls


def test_pat_route_uses_same_explicit_credential_without_app_or_environment_mutation():
    env = TrackedEnvironment({"GITHUB_TOKEN": "selected-pat"},
                             forbidden={"GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY_PATH"})
    saved = dict(env)
    adapter, calls = adapter_fixture(environment=env)
    value = original()
    before = deepcopy(value)
    assert adapter(value) is True
    assert [call[0] for call in calls] == ["client", "repository", "issue", "provider", "executor", "execute", "close"]
    assert calls[0][1] == calls[3][1] == calls[5][2] == "selected-pat"
    assert calls[5][1]["installation_id"] is None
    assert set(calls[5][1]) == {"forge", "issue_id", "issue_title", "issue_body", "repo_full_name",
                               "repo_clone_url", "default_branch", "installation_id", "sender"}
    assert value == before and dict(env) == saved
    assert set(env.reads) == {"GITHUB_TOKEN"}


def test_app_route_cannot_read_ambient_pat_and_mints_exact_installation_before_reads(tmp_path):
    key = tmp_path / "app.pem"
    key.write_text("synthetic-private-key")
    key.chmod(0o600)
    env = TrackedEnvironment({"GITHUB_TOKEN": "wrong-pat", "GITHUB_APP_ID": "42",
                              "GITHUB_APP_PRIVATE_KEY_PATH": str(key)},
                             forbidden={"GITHUB_TOKEN"})
    adapter, calls = adapter_fixture(environment=env, installation=99)
    assert adapter(original(installation=99)) is True
    assert calls[0] == ("mint", {"app_id": "42", "private_key_or_path": "synthetic-private-key",
                                 "installation_id": 99, "safe_errors": True, "private_key_is_content": True})
    assert calls[1][1] == calls[4][1] == calls[6][2] == "selected-app-token"
    assert calls[6][1]["installation_id"] is None


@pytest.mark.parametrize("installation,environment", [
    (None, {}), (99, {"GITHUB_TOKEN": "not-an-app-fallback"}),
    (None, {"GITHUB_TOKEN": ""}), (None, {"GITHUB_TOKEN": "contains space"}),
])
def test_missing_selected_route_refuses_before_any_client_or_executor(installation, environment):
    adapter, calls = adapter_fixture(environment=environment, installation=installation)
    with pytest.raises(IngressError, match="execution_credentials_unavailable"):
        adapter(original(installation))
    assert calls == []


def test_failed_app_mint_never_uses_present_pat(tmp_path):
    key = tmp_path / "app.pem"
    key.write_text("synthetic-private-key")
    key.chmod(0o600)
    env = {"GITHUB_TOKEN": "unused", "GITHUB_APP_ID": "42", "GITHUB_APP_PRIVATE_KEY_PATH": str(key)}
    adapter, calls = adapter_fixture(environment=env, installation=99)
    adapter.app_token_factory = lambda **_kwargs: None
    with pytest.raises(AdapterUnavailable):
        adapter(original(99))
    assert calls == []


@pytest.mark.parametrize("kwargs,code", [
    ({"repository_id": 456}, "selected_repository_changed"),
    ({"issue_pr": {"url": "https://api.github.com/pulls/7"}}, "selected_issue_unavailable"),
])
def test_identity_or_pr_refusal_precedes_provider_and_executor(kwargs, code):
    adapter, calls = adapter_fixture(**kwargs)
    with pytest.raises(AdapterUnavailable, match=code):
        adapter(original())
    assert not {"provider", "executor", "execute"}.intersection(call[0] for call in calls)
    assert calls[-1] == ("close",)


def test_nonboolean_handler_outcome_is_unknown_not_truthy_success():
    adapter, calls = adapter_fixture(outcome={"success": True})
    with pytest.raises(AdapterUnavailable, match="task_handler_outcome_invalid"):
        adapter(original())
    assert calls[-1] == ("close",)


def test_explicit_provider_does_not_consult_environment(monkeypatch):
    from src.forge.github import GitHubProvider
    monkeypatch.setenv("GITHUB_TOKEN", "ambient")
    client = object()
    provider = GitHubProvider(github_client=client, token="selected", allow_environment_token=False)
    assert provider.client is client and provider.token == "selected"
    assert GitHubProvider(github_client=client, allow_environment_token=False).token is None


def test_observed_pat_rotation_latches_until_a_new_epoch_even_after_restoration():
    environment = {"GITHUB_TOKEN": "original-pat"}
    adapter, calls = adapter_fixture(environment=environment)
    adapter.validate_epoch()
    environment["GITHUB_TOKEN"] = "replacement-pat"
    with pytest.raises(IngressError, match="execution_credentials_changed"):
        adapter.validate_epoch()
    environment["GITHUB_TOKEN"] = "original-pat"
    with pytest.raises(IngressError, match="execution_credentials_changed"):
        adapter(original())
    assert calls == []
    replacement, _calls = adapter_fixture(environment=environment)
    replacement.validate_epoch()


@pytest.mark.parametrize("change", ["content", "identity", "path", "permissions", "missing"])
def test_app_key_rotation_never_rebinds_current_epoch(tmp_path, change):
    key = tmp_path / "app.pem"
    key.write_text("original-key")
    key.chmod(0o600)
    environment = {"GITHUB_APP_ID": "42", "GITHUB_APP_PRIVATE_KEY_PATH": str(key)}
    adapter, calls = adapter_fixture(environment=environment, installation=99)
    adapter.validate_epoch()
    if change == "content":
        key.write_text("changed-key")
    elif change == "identity":
        old = tmp_path / "retained-key.pem"
        key.rename(old)
        key.write_text("original-key")
        key.chmod(0o600)
    elif change == "path":
        environment["GITHUB_APP_PRIVATE_KEY_PATH"] = str(tmp_path / "other.pem")
    elif change == "permissions":
        key.chmod(0o644)
    else:
        key.unlink()
    with pytest.raises(IngressError, match="execution_credentials_changed"):
        adapter.validate_epoch()
    environment["GITHUB_APP_PRIVATE_KEY_PATH"] = str(key)
    key.write_text("original-key")
    key.chmod(0o600)
    with pytest.raises(IngressError, match="execution_credentials_changed"):
        adapter(original(99))
    assert calls == []


@pytest.mark.parametrize("kind", ["oversize", "symlink", "public"])
def test_startup_app_snapshot_refuses_unbounded_or_nonprivate_key(tmp_path, kind):
    key = tmp_path / "app.pem"
    key.write_text("k" * (65537 if kind == "oversize" else 10))
    key.chmod(0o600)
    if kind == "symlink":
        target = tmp_path / "key-target.pem"
        key.rename(target)
        key.symlink_to(target)
    elif kind == "public":
        key.chmod(0o644)
    adapter, calls = adapter_fixture(environment={"GITHUB_APP_ID": "42", "GITHUB_APP_PRIVATE_KEY_PATH": str(key)}, installation=99)
    with pytest.raises(IngressError, match="execution_credentials_unavailable"):
        adapter.validate_epoch()
    assert calls == []


@pytest.mark.parametrize("route", ["pat", "app"])
def test_selected_execution_material_cannot_alias_an_ingress_secret(tmp_path, route):
    from tests.unit.ingress_core_support import host_fixture
    def mutate(document):
        if route == "app":
            document["bindings"][0]["installation_id"] = 99
    policy, _path, environment, _document, _activation = host_fixture(tmp_path, mutate=mutate)
    secret = environment["OPENJULES_INGRESS_BEARER_OPERATOR"]
    if route == "pat":
        execution_environment = {"GITHUB_TOKEN": secret}
    else:
        key = tmp_path / "private-app.pem"
        key.write_text(secret)
        key.chmod(0o600)
        execution_environment = {"GITHUB_APP_ID": "42", "GITHUB_APP_PRIVATE_KEY_PATH": str(key)}
    with pytest.raises(IngressError, match="ingress_execution_secret_alias"):
        GitHubTaskAdapter(bindings=policy.bindings.values(), environ=execution_environment,
                          separation_validator=policy.assert_execution_separation,
                          client_factory=lambda _: pytest.fail("client constructed before credential separation"))
