"""Initial child reports through real SQLite/capture code and named runtime fixtures.

These tests do not qualify Docker, kernel peer identity or the external authority.
The corresponding mandatory socket and container tests cover those boundaries.
"""

from dataclasses import replace
import json
from pathlib import Path
import sys
import struct
import time
from types import SimpleNamespace

import pytest

from src.agent.child_outcome import OutcomeClient, OutcomeError, report_value
from src.agent.managed_runner import BrokerError, LocalTools, run_agent
from src.polyphony.managed_client import AuthorityUnavailable
from src.worker.child_journal import ChildJournal
from src.worker.child_outcomes import work_outcome
from src.worker.child_runtime import ChildRuntime
from src.worker.child_supervisor import ChildDenied, ChildSupervisor
from src.worker.child_types import canonical
from src.worker.lifecycle import LifecycleConflict, RuntimeUnavailable
from tests.unit.test_child_authority_contract import context, policy
from tests.unit.test_child_runtime import FixtureEngine, final_receipt
from tests.unit.test_child_supervisor import FixtureAuthority, FixtureLifecycle, spawn
from tests.unit.test_managed_agent import message


class OutcomeAuthority(FixtureAuthority):
    def __init__(self, root):
        super().__init__(root)
        self.fail_once = None
        self.changed_outcome = {}
        self.receipts = {}

    def call(self, operation, scope, attempt_id, **payload):
        result = super().call(operation, scope, attempt_id, **payload)
        if operation == "observe":
            child_id = payload["child_id"]
            manifest = json.loads(self.artifacts[(child_id, "manifest")])
            if "work_outcome" in manifest:
                result["child"]["initial_outcome"] = manifest["work_outcome"] | {
                    "artifacts": payload["artifacts"],
                    "canonical_committed": True,
                    "release_authorized": False,
                }
                if self.changed_outcome:
                    result["child"]["initial_outcome"].update(self.changed_outcome)
            self.receipts[child_id] = result
        step = operation + (":" + payload["kind"] if operation == "capture" else "")
        if self.fail_once == step:
            self.fail_once = None
            raise AuthorityUnavailable("fixture lost reply after persistence")
        return result


def outcome_supervisor(tmp_path, *, uid_start=60000):
    root = replace(
        context(),
        monotonic_deadline=time.monotonic() + 60,
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )
    approved = replace(policy(), uid_start=uid_start, outcome_protocol="initial-v1")
    lifecycle, engine = FixtureLifecycle(root), FixtureEngine()
    supervisor = ChildSupervisor(
        tmp_path / "children",
        {(root.spec.deployment_id, root.spec.repository, root.spec.profile): approved},
        None,
        lifecycle,
        engine,
        None,
        lambda _: 50,
        lambda _: True,
    )
    supervisor.authority = OutcomeAuthority(root)
    supervisor.endpoints = SimpleNamespace(
        prepare_child=lambda *_: None,
        revoke=lambda *_: None,
        close=lambda callback: callback(),
    )
    supervisor.journal.prepare(root.worker_id, root.spec, approved)
    supervisor.journal.bind(root)
    return supervisor, root, lifecycle, engine


@pytest.fixture
def outcomes(tmp_path):
    values = outcome_supervisor(tmp_path)
    yield values
    values[0].close()


def report(
    supervisor,
    root,
    child_id,
    outcome="completed",
    summary="Private result",
    key="report-one",
):
    return supervisor.report_outcome(
        root.worker_id,
        child_id,
        {
            "schema_version": 1,
            "request_id": key,
            "outcome": outcome,
            "summary": summary,
        },
    )


def reopen(supervisor):
    directory = supervisor.journal.root
    supervisor.journal.close()
    supervisor.journal = ChildJournal(directory)


def test_shared_unicode_golden_vector_and_legacy_policy_are_exact():
    path = Path(__file__).parents[1] / "fixtures/child-initial-outcome-v1.json"
    vector = json.loads(path.read_text())
    expected = vector["manifest"]["work_outcome"]
    retained = report_value(
        "report:one", "needs_clarification", "Which behavior should λ preserve?"
    )
    assert work_outcome(vector["binding"], retained) == expected
    assert (
        policy().fingerprint
        == "625a1f00a63e8ce9a349e7a92e40ef24157cd680fb420da8aeb9c5fdd6e131bf"
    )
    assert replace(policy(), outcome_protocol=None).fingerprint == policy().fingerprint
    enabled = replace(policy(), outcome_protocol="initial-v1")
    assert enabled.fingerprint != policy().fingerprint
    capabilities = {"child_grants": True, "child_policy": enabled.canonical_policy}
    policy().validate_capabilities(capabilities)
    enabled.validate_capabilities(capabilities | {"child_initial_outcome": 1})
    for unsupported in (None, True, False, "1", 0, 2):
        with pytest.raises(AuthorityUnavailable):
            enabled.validate_capabilities(
                capabilities | {"child_initial_outcome": unsupported}
            )
    with pytest.raises(ValueError):
        replace(enabled, command=("my-approved-custom-runner",))
    with pytest.raises(ValueError):
        replace(policy(), outcome_protocol="future-version")


def test_fallback_image_context_contains_every_actual_dockerfile_copy_source(
    tmp_path_factory, monkeypatch
):
    from tests.integration.test_managed_agent_container import agent_image

    monkeypatch.delenv("OPENJULES_MANAGED_AGENT_IMAGE_ID", raising=False)
    repository = Path(__file__).parents[2]
    builds, closed = [], []

    def build(**options):
        directory = Path(options["path"])
        copies = [
            line.split()[1]
            for line in (directory / "Dockerfile").read_text().splitlines()
            if line.startswith("COPY ")
        ]
        assert "src/agent/child_outcome.py" in copies
        for source in copies:
            if (repository / source).is_dir():
                def contents(root):
                    return {path.relative_to(root).as_posix(): path.read_bytes()
                            for path in root.rglob("*") if path.is_file()}
                assert (directory / source).is_dir()
                assert contents(directory / source) == contents(repository / source)
            else:
                assert (directory / source).read_bytes() == (
                    repository / source
                ).read_bytes()
        builds.append(copies)
        return SimpleNamespace(id="fixture-built-image"), []

    client = SimpleNamespace(
        ping=lambda: None,
        info=lambda: {"SecurityOptions": ["name=seccomp"]},
        images=SimpleNamespace(build=build),
        close=lambda: closed.append(True),
    )
    monkeypatch.setattr(
        "tests.integration.test_managed_agent_container.docker.from_env",
        lambda **_: client,
    )
    fixture = agent_image.__wrapped__(tmp_path_factory)
    try:
        assert next(fixture) == (client, "fixture-built-image")
    finally:
        with pytest.raises(StopIteration):
            next(fixture)
    assert len(builds) == 1 and closed == [True]


@pytest.mark.parametrize(
    "outcome", ["completed", "declined", "needs_clarification", "failed"]
)
def test_all_explicit_reports_remain_private_self_reports_until_final_capture(
    outcomes, tmp_path, outcome
):
    supervisor, root, lifecycle, engine = outcomes
    child_id = spawn(supervisor, root)["child_id"]
    before = len(supervisor.authority.events), len(engine.created), len(engine.started)
    acknowledged = report(supervisor, root, child_id, outcome, "Private λ summary")
    assert acknowledged["report"]["outcome"] == outcome
    assert acknowledged["final"] is acknowledged["canonical_committed"] is False
    assert acknowledged["release_authorized"] is False
    assert before == (
        len(supervisor.authority.events),
        len(engine.created),
        len(engine.started),
    )
    child = supervisor.journal.child(root.worker_id, child_id)
    status = supervisor._status(child)
    assert status["initial_outcome"]["report"] == acknowledged["report"]
    assert status["final"] is False and child_id in lifecycle.active
    assert child["capture"] is None
    supervisor.finalize(root.worker_id, final_receipt(tmp_path, child_id))
    child = supervisor.journal.child(root.worker_id, child_id)
    captured = json.loads(child["capture"])["contents"]
    extension = json.loads(captured["manifest"])["work_outcome"]
    terminal = supervisor.authority.receipts[child_id]["child"]
    assert terminal["initial_outcome"] == extension | {
        "artifacts": json.loads(child["artifacts"]),
        "canonical_committed": True,
        "release_authorized": False,
    }
    assert captured["patch"] == "diff child\n" and captured["log"] == "child output\n"
    assert child["phase"] == "completed" and lifecycle.active == [root.attempt_id]


def test_same_slot_survives_ack_loss_reopen_and_revocation_without_new_effects(
    outcomes,
):
    supervisor, root, _, engine = outcomes
    child_id = spawn(supervisor, root)["child_id"]
    first = report(supervisor, root, child_id, "declined", "Keep existing work")
    original = supervisor.journal.child(root.worker_id, child_id)
    supervisor.mark_retiring(root.worker_id)
    reopen(supervisor)
    assert report(supervisor, root, child_id, "declined", "Keep existing work") == first
    for changes in (
        {"key": "another-key"},
        {"summary": "Changed"},
        {"outcome": "completed"},
    ):
        values = {"outcome": "declined", "summary": "Keep existing work"} | changes
        with pytest.raises(LifecycleConflict):
            report(supervisor, root, child_id, **values)
    assert (
        supervisor.journal.child(root.worker_id, child_id)["exec_id"]
        == original["exec_id"]
    )
    assert len(engine.created) == len(engine.started) == 2
    assert not any(operation == "turn" for operation, _ in supervisor.authority.events)


@pytest.mark.parametrize(
    "change",
    [
        {"actor": "parent"},
        {"child_id": "child_" + "e" * 32},
        {"schema_version": True},
        {"request_id": "/forged"},
        {"outcome": []},
        {"summary": "é" * 4097},
        {"summary": "hidden\0text"},
    ],
)
def test_invalid_or_caller_selected_report_fields_leave_the_slot_empty(
    outcomes, change
):
    supervisor, root, _, _ = outcomes
    child_id = spawn(supervisor, root)["child_id"]
    before = list(supervisor.authority.events)
    with pytest.raises(ChildDenied, match="invalid_request"):
        supervisor.report_outcome(
            root.worker_id,
            child_id,
            {
                "schema_version": 1,
                "request_id": "valid",
                "outcome": "completed",
                "summary": "",
            }
            | change,
        )
    assert supervisor.journal.child(root.worker_id, child_id)["outcome_report"] is None
    assert supervisor.authority.events == before


def test_report_winning_capture_race_is_not_omitted_from_frozen_manifest(
    outcomes, tmp_path
):
    supervisor, root, _, _ = outcomes
    child_id = spawn(supervisor, root)["child_id"]
    child = supervisor.journal.child(root.worker_id, child_id)
    receipt = final_receipt(tmp_path, child_id)
    stale_capture = supervisor.driver.final_capture(root, child, receipt)
    assert json.loads(stale_capture["manifest"])["work_outcome"]["report"] is None
    retained = report(
        supervisor, root, child_id, "needs_clarification", "Which branch?"
    )
    with pytest.raises(RuntimeUnavailable, match="report changed"):
        supervisor.journal.freeze_capture(
            root.worker_id, child_id, stale_capture, "exited", expected_report=None
        )
    assert supervisor.journal.child(root.worker_id, child_id)["capture"] is None
    reopen(supervisor)
    supervisor.finalize(root.worker_id, receipt)
    child = supervisor.journal.child(root.worker_id, child_id)
    frozen = json.loads(json.loads(child["capture"])["contents"]["manifest"])
    assert frozen["work_outcome"]["report"] == retained["report"]
    assert (
        report(supervisor, root, child_id, "needs_clarification", "Which branch?")
        == retained
    )


def test_capture_winning_report_race_stays_unreported_after_reopen(outcomes, tmp_path):
    supervisor, root, _, _ = outcomes
    child_id = spawn(supervisor, root)["child_id"]
    supervisor.finalize(root.worker_id, final_receipt(tmp_path, child_id))
    original = supervisor.journal.child(root.worker_id, child_id)
    reopen(supervisor)
    with pytest.raises(LifecycleConflict, match="already frozen"):
        report(supervisor, root, child_id)
    recovered = supervisor.journal.child(root.worker_id, child_id)
    assert (
        recovered["capture"] == original["capture"]
        and recovered["outcome_report"] is None
    )
    extension = json.loads(json.loads(recovered["capture"])["contents"]["manifest"])[
        "work_outcome"
    ]
    assert extension["source"] == "unreported" and extension["report"] is None


@pytest.mark.parametrize(
    "lost", ["capture:patch", "capture:log", "capture:manifest", "observe"]
)
def test_frozen_report_capture_delivery_recovers_without_relaunch(
    outcomes, tmp_path, lost
):
    supervisor, root, lifecycle, engine = outcomes
    child_id = spawn(supervisor, root)["child_id"]
    report(supervisor, root, child_id, "failed", "Partial work retained")
    supervisor.authority.fail_once = lost
    receipt = final_receipt(tmp_path, child_id)
    with pytest.raises(AuthorityUnavailable):
        supervisor.finalize(root.worker_id, receipt)
    original = supervisor.journal.child(root.worker_id, child_id)
    assert original["capture"] is not None and child_id in lifecycle.active
    reopen(supervisor)
    supervisor.finalize(root.worker_id, receipt)
    recovered = supervisor.journal.child(root.worker_id, child_id)
    assert (
        recovered["capture"] == original["capture"]
        and recovered["phase"] == "completed"
    )
    assert len(engine.created) == len(engine.started) == 2
    assert lifecycle.active == [root.attempt_id]


@pytest.mark.parametrize(
    "changes",
    [
        {"canonical_committed": 1},
        {"release_authorized": 0},
        {"schema_version": True},
        {"ordinal": True},
        {"requirements_revision": True},
        {"source": "independently_verified"},
        {"report": None},
    ],
)
def test_changed_canonical_outcome_never_clears_execution_reference(
    outcomes, tmp_path, changes
):
    supervisor, root, lifecycle, _ = outcomes
    child_id = spawn(supervisor, root)["child_id"]
    report(supervisor, root, child_id)
    supervisor.authority.changed_outcome = changes
    with pytest.raises(AuthorityUnavailable, match="receipt is incomplete"):
        supervisor.finalize(root.worker_id, final_receipt(tmp_path, child_id))
    assert child_id in lifecycle.active
    assert supervisor.journal.child(root.worker_id, child_id)["phase"] == "captured"


@pytest.mark.parametrize("outcome", ["declined", "needs_clarification", "failed"])
def test_terminal_child_dissent_runs_no_verification_or_extra_model_call(
    tmp_path, outcome
):
    calls, reports = [], []

    def complete(messages):
        calls.append(messages)
        return message("report_outcome", outcome=outcome, summary="Private dissent")

    marker = tmp_path / "verification-ran"
    result = run_agent(
        SimpleNamespace(complete=complete),
        LocalTools(tmp_path),
        "Make a change",
        verify_argv=[sys.executable, "-c", f"open({str(marker)!r},'w').write('ran')"],
        outcome_client=SimpleNamespace(report=lambda *values: reports.append(values)),
    )
    assert result == (2 if outcome == "failed" else 0)
    assert reports == [(outcome, "Private dissent")] and len(calls) == 1
    assert not marker.exists()


def test_completed_self_report_and_later_verification_failure_are_distinct(
    tmp_path, capsys
):
    reports = []
    result = run_agent(
        SimpleNamespace(
            complete=lambda _: message(
                "finish", summary="Child believes it is complete"
            )
        ),
        LocalTools(tmp_path),
        "Make a change",
        verify_argv=[sys.executable, "-c", "raise SystemExit(1)"],
        outcome_client=SimpleNamespace(report=lambda *values: reports.append(values)),
    )
    assert result == 3 and reports == [("completed", "Child believes it is complete")]
    assert '"exit_code": 1' in capsys.readouterr().out


def test_mixed_terminal_call_cannot_write_or_acknowledge_a_report(tmp_path):
    reports = []
    mixed = message(
        "write_file", path="must-not-exist", content="unapproved mixed call"
    )
    mixed["tool_calls"].extend(
        message("report_outcome", outcome="declined", summary="No")["tool_calls"]
    )
    result = run_agent(
        SimpleNamespace(complete=lambda _: mixed),
        LocalTools(tmp_path),
        "A task",
        max_turns=1,
        outcome_client=SimpleNamespace(report=lambda *values: reports.append(values)),
    )
    assert result == 2 and reports == [] and not (tmp_path / "must-not-exist").exists()


def test_unconfirmed_callback_stops_child_without_fabricating_failed_report(tmp_path):
    reports = []

    def fail(*values):
        reports.append(values)
        raise OutcomeError("reply unavailable")

    with pytest.raises(BrokerError, match="outcome remains unconfirmed"):
        run_agent(
            SimpleNamespace(complete=lambda _: message("finish", summary="Done")),
            LocalTools(tmp_path),
            "A task",
            outcome_client=SimpleNamespace(report=fail),
        )
    assert reports == [("completed", "Done")]


def test_client_retries_only_identical_evidence_after_lost_reply(monkeypatch):
    client = OutcomeClient("/fixture/outcome.sock", timeout_seconds=1)
    retained = report_value(client.request_key, "declined", "Private refusal")
    receipt = {
        "schema_version": 1,
        "request_id": client.request_key,
        "ok": True,
        "child_id": "child_" + "d" * 32,
        "work_turn_id": "a" * 64,
        "report": retained,
        "final": False,
        "canonical_committed": False,
        "release_authorized": False,
    }
    encoded = json.dumps(receipt).encode()
    response = struct.pack("!I", len(encoded)) + encoded
    frames = []

    class Connection:
        def __enter__(self):
            self.cursor = 0
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, remaining):
            assert 0 < remaining <= 1

        def connect(self, path):
            assert path == client.socket_path

        def sendall(self, frame):
            frames.append(frame)

        def recv(self, size):
            if len(frames) == 1:
                raise OSError("fixture lost reply after host retention")
            content = response[self.cursor : self.cursor + size]
            self.cursor += len(content)
            return content

    monkeypatch.setattr(
        "src.agent.child_outcome.socket.socket", lambda *_: Connection()
    )
    assert client.report("declined", "Private refusal") == receipt
    assert frames[0] == frames[1] and len(frames) == 2
    deadline = client.deadline
    assert client.report("declined", "Private refusal") == receipt
    assert client.deadline == deadline and len(frames) == 2
    with pytest.raises(OutcomeError, match="cannot change"):
        client.report("completed", "Overwrite")


def test_client_repeated_uncertain_identity_cannot_restart_deadline(monkeypatch):
    attempts = []

    def unavailable(*_):
        attempts.append(True)
        raise OSError("fixture transport remains unavailable")

    monkeypatch.setattr("src.agent.child_outcome.socket.socket", unavailable)
    client = OutcomeClient("/fixture/outcome.sock", timeout_seconds=0.03)
    with pytest.raises(OutcomeError, match="uncertain"):
        client.report("failed", "Uncertain delivery")
    before = len(attempts)
    deadline = client.deadline
    with pytest.raises(OutcomeError, match="uncertain"):
        client.report("failed", "Uncertain delivery")
    assert len(attempts) == before and client.deadline == deadline


@pytest.mark.parametrize("protocol", [None, "initial-v1"])
def test_actual_provider_tool_schema_is_selected_only_for_enabled_children(
    tmp_path, monkeypatch, protocol
):
    from tests.unit.test_child_model_budget import ChildAuthorityFixture, payload
    from tests.unit.test_managed_agent import WORKER, broker_client, provider, response

    def reply(handler, requests):
        answer = message()
        if len(requests) == 2 and protocol is not None:
            answer = message(
                "report_outcome", outcome="declined", summary="Private refusal"
            )
        response(handler, answer)

    with provider(reply) as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint) as (broker, _, _):
            broker.child_supervisor = ChildAuthorityFixture()
            broker.child_supervisor.policy = lambda _: replace(
                policy(), outcome_protocol=protocol
            )
            broker.complete(WORKER, payload("root"))
            broker.complete_child(WORKER, "child-one", payload("child"))
            names = [
                {item["function"]["name"] for item in request["body"]["tools"]}
                for request in requests
            ]
            assert "report_outcome" not in names[0]
            assert ("report_outcome" in names[1]) is (protocol is not None)
            assert "spawn_child" not in names[1] and len(requests) == 2
