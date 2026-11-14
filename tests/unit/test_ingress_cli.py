"""Explicit host initialization, enrollment and one-owner serving."""

import argparse
import json
from types import SimpleNamespace

import pytest

from src.cli import handle_ingress_cli, main, serve_dashboard
from src.api.ingress_policy import load_policy
from src.storage.ingress_receipts import ReceiptStore
from tests.unit.ingress_core_support import activation_document, host_fixture, policy_document, write_private


def test_cli_init_enrollment_and_held_owner_refusal_are_explicit(tmp_path, monkeypatch, capsys):
    tmp_path.chmod(0o700)
    store = tmp_path / "receipts.sqlite"
    args = SimpleNamespace(ingress_action="init", store=str(store))
    assert handle_ingress_cli(args) == 0
    initialized = json.loads(capsys.readouterr().out)
    assert set(initialized) == {"schema_version", "journal_id"}
    original = store.read_bytes()
    assert handle_ingress_cli(args) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "receipt_store_exists"}
    assert store.read_bytes() == original
    monkeypatch.setenv("OPENJULES_INGRESS_BEARER_OPERATOR", "test-operator-value")
    monkeypatch.setenv("OPENJULES_INGRESS_HMAC_WEBHOOK", "test-hmac-value")
    path = write_private(tmp_path / "policy.json", policy_document(store, initialized["journal_id"]))
    policy = load_policy(path)
    declaration = write_private(tmp_path / "activation.json", activation_document(policy))
    enroll = SimpleNamespace(ingress_action="enroll-policy", policy=str(path), activation=str(declaration))
    assert handle_ingress_cli(enroll) == 0
    assert json.loads(capsys.readouterr().out)["enrolled"] is True
    enroll.activation = None
    with ReceiptStore(policy):
        assert handle_ingress_cli(enroll) == 2
        assert json.loads(capsys.readouterr().out) == {"error": "receipt_store_owned"}


def test_cli_uses_recorded_activation_declaration_option(monkeypatch):
    import src.cli as cli
    captured = []
    monkeypatch.setattr(cli, "handle_ingress_cli", lambda args: captured.append(args) or 0)
    monkeypatch.setattr("sys.argv", ["openjules", "ingress", "enroll-policy", "--policy", "/host/policy.json",
                                    "--activation-declaration", "/host/declaration.json"])
    with pytest.raises(SystemExit) as exited:
        main()
    assert exited.value.code == 0
    assert captured[0].activation == "/host/declaration.json"


@pytest.mark.parametrize("mode", ["local_only", "remote"])
def test_explicit_serve_selects_policy_single_owner_and_no_proxy_header_trust(tmp_path, monkeypatch, mode):
    def mutate(document):
        if mode == "remote":
            document["mode"] = "remote"
            document["transport"]["external_origin"] = "https://approved.example"
    _policy, path, environment, _document, _activation = host_fixture(tmp_path, mutate=mutate)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("WEB_CONCURRENCY", "8")
    calls = []
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: calls.append((args, kwargs)))
    serve_dashboard("127.0.0.1", 8000, str(path))
    app, = calls[0][0]
    assert app.state.ingress_policy.mode == mode
    assert calls[0][1] == {"host": "127.0.0.1", "port": 8000, "reload": False,
                           "workers": 1, "proxy_headers": False, "access_log": False}
