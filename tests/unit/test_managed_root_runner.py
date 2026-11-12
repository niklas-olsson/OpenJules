"""Root wrapper composes the unchanged agent and closes child admission."""

import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from src.agent import managed_root_runner as runner
from src.agent.child_tools import ControlClient, ControlError
from tests.unit.test_child_tools import CHILD, result, reply, server, spawned


def tool(name, arguments):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "fixture-call-" + name,
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        ],
    }


def test_actual_agent_composes_child_output_and_runs_ordinary_verification(tmp_path):
    legacy = runner._load_sibling("managed_runner")
    ordinary_names = [
        definition["function"]["name"] for definition in legacy.TOOL_DEFINITIONS
    ]
    instructions = {
        "instructions": "Determine the fixture answer.",
        "seconds": 20,
        "max_turns": 4,
        "capabilities": ["python"],
    }
    messages = iter(
        [
            tool("spawn_child", instructions),
            tool("child_status", {"child_id": CHILD}),
            tool("child_result", {"child_id": CHILD, "kind": "log"}),
            tool("write_file", {"path": "answer.py", "content": "answer = 42\n"}),
            tool("finish", {"summary": "Composed and verified child work."}),
        ]
    )
    seen_messages = []

    def complete(history):
        seen_messages.append(list(history))
        return next(messages)

    def handle(request, _):
        if request["operation"] == "spawn":
            return spawned(request)
        if request["operation"] == "status":
            return reply(request, child_id=CHILD, state="exec_returned")
        if request["operation"] == "result":
            return result(request, "answer = 42", "answer = 42")
        assert request["operation"] == "close"
        return reply(request, admission_open=False)

    with server(handle) as fixture:
        status = runner.run_root(
            SimpleNamespace(complete=complete),
            legacy.LocalTools(tmp_path),
            ControlClient(fixture.path),
            "Use a child and compose its result.",
            max_turns=5,
            verify_argv=[
                sys.executable,
                "-c",
                "from answer import answer; assert answer == 42",
            ],
            legacy=legacy,
        )
        assert status == 0
        assert (tmp_path / "answer.py").read_text() == "answer = 42\n"
        assert [request["operation"] for request in fixture.requests] == [
            "spawn",
            "status",
            "result",
            "close",
        ]
        assert any(
            '"final":false' in message["content"]
            for history in seen_messages
            for message in history
            if message["role"] == "tool"
        )
    assert [
        definition["function"]["name"] for definition in legacy.TOOL_DEFINITIONS
    ] == ordinary_names
    assert "spawn_child" not in ordinary_names


@pytest.mark.parametrize("failure", [ValueError("invalid task"), KeyboardInterrupt()])
def test_wrapper_closes_on_agent_error_and_preserves_original_failure(failure):
    operations = []

    def request(operation, **_fields):
        operations.append(operation)
        raise ControlError("uncertain")

    def fail(*_args, **_kwargs):
        raise failure

    with pytest.raises(type(failure)) as caught:
        runner.run_root(
            object(),
            object(),
            SimpleNamespace(request=request),
            "task",
            legacy=SimpleNamespace(run_agent=fail),
        )
    assert caught.value is failure
    assert operations == ["close"]


def test_success_is_not_reported_when_admission_close_is_uncertain():
    with server(lambda *_: None) as fixture:
        with pytest.raises(ControlError, match="uncertain"):
            runner.run_root(
                object(),
                object(),
                ControlClient(fixture.path),
                "task",
                legacy=SimpleNamespace(run_agent=lambda *_args, **_kwargs: 0),
            )
        assert [item["operation"] for item in fixture.requests] == ["close"]


def test_child_control_uncertainty_stops_agent_and_closes_admission():
    legacy = runner._load_sibling("managed_runner")

    def handle(request, _):
        if request["operation"] == "spawn":
            return reply(request, ok=False, error="uncertain")
        return reply(request, admission_open=False)

    model = SimpleNamespace(
        complete=lambda _history: tool(
            "spawn_child",
            {"instructions": "task", "seconds": 10, "max_turns": 2, "capabilities": []},
        )
    )
    with server(handle) as fixture:
        with pytest.raises(ControlError, match="uncertain"):
            runner.run_root(
                model,
                SimpleNamespace(call=lambda *_: "no rules"),
                ControlClient(fixture.path),
                "task",
                legacy=legacy,
            )
        assert [item["operation"] for item in fixture.requests] == ["spawn", "close"]


def test_trusted_image_import_does_not_use_the_working_repository(
    tmp_path, monkeypatch
):
    (tmp_path / "managed_runner.py").write_text(
        "raise RuntimeError('guest replacement loaded')\n"
    )
    monkeypatch.chdir(tmp_path)
    loaded = runner._load_sibling("managed_runner")
    assert (
        Path(loaded.__file__).resolve().parent == Path(runner.__file__).resolve().parent
    )
    assert callable(loaded.run_agent)
    with pytest.raises(ValueError):
        runner._load_sibling("../managed_runner")


def test_main_closes_admission_when_input_validation_fails(monkeypatch):
    operations = []
    control = SimpleNamespace(
        request=lambda operation, **fields: operations.append((operation, fields))
    )
    monkeypatch.setattr(runner, "ControlClient", lambda *_args, **_kwargs: control)
    monkeypatch.setattr(
        runner.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"task"))
    )
    assert (
        runner.main(
            [
                "--socket",
                "/model.sock",
                "--control-socket",
                "/control.sock",
                "--verify-json",
                "invalid-json",
            ]
        )
        == 4
    )
    assert operations == [("close", {"reason": "root runner setup failed"})]


def test_public_root_composes_existing_control_and_ordinary_verification(tmp_path):
    from src.agent.public_tools import PublicClient
    from tests.unit.test_public_tools import actor, history, success

    legacy = runner._load_sibling("managed_runner")
    (tmp_path / "AGENTS.md").write_text("Use the existing child and verification boundaries.\n")
    script = [
        tool("public_read", {"after": 0, "stream_id": None, "watch_seconds": 0}),
        tool("spawn_child", {"instructions": "Ordinary child work.", "seconds": 20,
                             "max_turns": 2, "capabilities": []}),
        tool("finish", {"summary": "Observed public history and retained ordinary controls."}),
    ]
    histories = []

    def complete(messages):
        histories.append(json.loads(json.dumps(messages)))
        assert len(histories) <= len(script), "public observation added an inference"
        return script[len(histories) - 1]

    def private_reply(request, _number):
        if request["operation"] == "spawn":
            return spawned(request)
        assert request["operation"] == "close"
        return reply(request, admission_open=False)

    with server(private_reply) as private:
        with server(lambda request, _: success(request, history(actor("root")))) as public:
            code = runner.run_root(
                SimpleNamespace(complete=complete), legacy.LocalTools(tmp_path),
                ControlClient(private.path), "Use the explicitly approved public observation.",
                max_turns=3, legacy=legacy, public_client=PublicClient(public.path, role="root"),
                verify_argv=[sys.executable, "-c", "open('verified.txt','w').write('checked')"],
            )
            assert code == 0
            assert (tmp_path / "verified.txt").read_text() == "checked"
            assert len(histories) == 3
            assert [r["operation"] for r in public.requests] == ["public_read"]
            assert [r["operation"] for r in private.requests] == ["spawn", "close"]
            assert json.loads([
                m["content"] for m in histories[1] if m["role"] == "tool"
            ][0])["execution_authorized"] is False


@pytest.mark.parametrize("close_uncertain", [False, True])
def test_public_root_uncertainty_preserves_original_error_and_closes_only_private_admission(
    tmp_path, close_uncertain
):
    from src.agent.public_tools import PublicClient, PublicError
    from tests.unit.test_public_tools import refusal, selection

    legacy = runner._load_sibling("managed_runner")
    (tmp_path / "AGENTS.md").write_text("Unknown public effects stop the agent.\n")
    histories, original_errors = [], []

    def complete(messages):
        histories.append(json.loads(json.dumps(messages)))
        assert len(histories) == 1, "uncertain public publication reached another model call"
        return tool("public_turn", selection())

    def private_reply(request, _number):
        assert request["operation"] == "close"
        if close_uncertain:
            return reply(request, ok=False, error="uncertain")
        return reply(request, admission_open=False)

    with server(private_reply) as private:
        with server(lambda request, _: refusal(request, "publication_uncertain")) as public:
            actual = PublicClient(public.path, role="root")

            class ObservedClient:
                role = "root"

                def request(self, *args, **kwargs):
                    try:
                        return actual.request(*args, **kwargs)
                    except PublicError as exc:
                        original_errors.append(exc)
                        raise

            with pytest.raises(PublicError) as error:
                runner.run_root(
                    SimpleNamespace(complete=complete), legacy.LocalTools(tmp_path),
                    ControlClient(private.path), "Use one explicitly selected public turn.",
                    max_turns=3, legacy=legacy, public_client=ObservedClient(),
                )
            assert original_errors == [error.value]
            assert error.value is original_errors[0]
            assert error.value.code == "publication_uncertain"
            assert error.value.request_id == public.requests[0]["request_id"]
            assert len(histories) == 1
            assert [r["operation"] for r in public.requests] == ["public_turn"]
            assert [r["operation"] for r in private.requests] == ["close"]


def test_public_root_main_selects_fixed_role_and_closes_after_uncertainty(
    tmp_path, monkeypatch, capsys
):
    from src.agent import managed_runner as legacy
    from src.agent import public_tools as public_module
    from tests.unit.test_public_tools import refusal, selection

    monkeypatch.chdir(tmp_path)
    (tmp_path / "AGENTS.md").write_text("Root public extension fixture.\n")
    constructors, histories = [], []
    actual_client = public_module.PublicClient

    def create_client(path, **kwargs):
        constructors.append((path, kwargs))
        return actual_client(path, **kwargs)

    def complete(messages):
        histories.append(json.loads(json.dumps(messages)))
        assert len(histories) == 1
        return tool("public_turn", selection())

    def load(name):
        assert name == "managed_runner"
        return legacy

    monkeypatch.setattr(runner, "_load_sibling", load)
    monkeypatch.setattr(runner, "_public", None)
    monkeypatch.setattr(public_module, "PublicClient", create_client)
    monkeypatch.setattr(legacy, "BrokerClient", lambda _path: SimpleNamespace(complete=complete))
    monkeypatch.setattr(runner.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"Approved public root turn")))
    with server(lambda request, _: reply(request, admission_open=False)) as private:
        with server(lambda request, _: refusal(request, "provider_uncertain")) as public:
            assert runner.main([
                "--socket", "/fixture-model.sock", "--control-socket", private.path,
                "--public-socket", public.path, "--max-turns", "3",
            ]) == 4
            assert constructors == [(public.path, {"role": "root"})]
            assert [r["operation"] for r in private.requests] == ["close"]
            assert [r["operation"] for r in public.requests] == ["public_turn"]
            assert len(histories) == 1
    assert [json.loads(line)["event"] for line in capsys.readouterr().out.splitlines()] == [
        "root_agent_failed",
    ]


def test_ordinary_root_omission_never_loads_public_extension(tmp_path, monkeypatch):
    legacy = runner._load_sibling("managed_runner")
    (tmp_path / "AGENTS.md").write_text("Ordinary root profile.\n")

    def forbidden():
        pytest.fail("ordinary root unexpectedly loaded public extension")

    monkeypatch.setattr(runner, "_public_extension", forbidden)
    with server(lambda request, _: reply(request, admission_open=False)) as fixture:
        assert runner.run_root(
            SimpleNamespace(complete=lambda _messages: tool("finish", {"summary": "Ordinary."})),
            legacy.LocalTools(tmp_path), ControlClient(fixture.path),
            "Ordinary root task.", max_turns=1, legacy=legacy,
        ) == 0
        assert [request["operation"] for request in fixture.requests] == ["close"]


def test_public_image_sibling_loading_ignores_repository_module(tmp_path, monkeypatch):
    (tmp_path / "public_tools.py").write_text("raise RuntimeError('guest replacement loaded')\n")
    monkeypatch.chdir(tmp_path)
    loaded = runner._load_sibling("public_tools")
    assert Path(loaded.__file__).resolve().parent == Path(runner.__file__).resolve().parent
    assert callable(loaded.PublicClient)
    assert {item["function"]["name"] for item in loaded.ROOT_PUBLIC_TOOL_DEFINITIONS} == {
        "public_activate", "public_turn", "public_status", "public_read", "public_invite",
    }
