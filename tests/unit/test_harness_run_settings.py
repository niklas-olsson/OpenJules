"""Repository harness settings, overlapping runs and host path containment."""

from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.agent.engine import AgentEngine
from src.agent.llm_config import LLMConfig
from src.harness.adaptive_engine import AdaptiveHarness
from src.harness.config import HarnessConfig
from src.harness.experience import ExperienceManager
from src.sandbox.config import OpenJulesConfig, load_config_from_yaml
from src.sandbox.docker_driver import ExecResult, SandboxContext, SandboxManager


class ScriptedModel:
    """Controlled model replies; all planning/action/verification code is real."""

    def __init__(self, planning_barrier=None):
        self.calls = []
        self.options = []
        self.planning_barrier = planning_barrier

    def completion(self, *, messages, **options):
        system = messages[0]["content"]
        if "senior software architect" in system:
            kind, content = "plan", '{"rationale":"fixture plan"}'
        elif "optimize agent harness" in system:
            kind = "adapt"
            task = messages[-1]["content"].split("Task:\n", 1)[1].split("\n", 1)[0]
            content = json.dumps({"targeted_guardrails": ["guard:" + task],
                                  "suggested_helper_commands": ["probe"],
                                  "suggested_strategy": "fixture strategy"})
        elif "distill engineering" in system:
            kind, content = "experience", '{"problem_summary":"verified fixture","solution_pattern":"checked fixture"}'
        elif "Fix the failing tests" in system:
            kind, content = "correction", "No additional tool needed"
        else:
            kind, content = "action", "TASK_COMPLETED"
        self.calls.append((kind, copy.deepcopy(messages)))
        self.options.append((kind, copy.deepcopy(options)))
        if kind == "plan" and self.planning_barrier is not None:
            self.planning_barrier.wait(timeout=5)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content=content, tool_calls=None))])


class ObservedHarness(AdaptiveHarness):
    def __init__(self):
        super().__init__()
        self.sessions = []  # Intentional shared test instrumentation, not task state.

    def for_run(self, config):
        session = super().for_run(config)
        self.sessions.append(session)
        return session


def fixture_engine(*, failures=(), harness=None, model=None):
    sandbox = MagicMock(spec=SandboxManager)

    def execute(container, command):
        failed = command == "verify" and container in failures
        return ExecResult(stdout="failed" if failed else "fixture", stderr="", exit_code=int(failed))

    sandbox.exec_in_sandbox.side_effect = execute
    model = model or ScriptedModel()
    return AgentEngine(sandbox, llm_client=model, adaptive_harness=harness), sandbox, model


def context(root, name, config=None):
    workspace = root / name
    workspace.mkdir()
    return SandboxContext(name, str(workspace), "https://github.com/example/repo.git", "main",
                          config or OpenJulesConfig(test_command="verify"))


def kinds(model, kind):
    return [messages for observed, messages in model.calls if observed == kind]


def test_repository_disables_adaptation_but_retains_bounded_ordinary_fixes(tmp_path):
    config = load_config_from_yaml("""
test_command: verify
harness:
  adaptive: false
  inject_experience: false
  experience_path: notes/experience.md
  max_refinements: 0
""")
    ctx = context(tmp_path, "disabled", config)
    Path(ctx.workspace_dir, "EXPERIENCE.md").write_text("PRIVATE_DEFAULT_EXPERIENCE")
    engine, sandbox, model = fixture_engine(failures={"disabled"})
    result = engine.run(ctx, "disabled task")
    assert not result.success
    assert len(kinds(model, "correction")) == 2
    assert not kinds(model, "adapt") and not kinds(model, "experience")
    assert sum(call.args[1] == "verify" for call in sandbox.exec_in_sandbox.call_args_list) == 3
    assert not any(call.args[1] == "probe" for call in sandbox.exec_in_sandbox.call_args_list)
    assert "PRIVATE_DEFAULT_EXPERIENCE" not in repr(model.calls)
    assert not Path(ctx.workspace_dir, "notes").exists()


def test_disabled_adaptation_does_not_distill_success_but_injection_is_independent(tmp_path):
    cfg = OpenJulesConfig(test_command="verify", harness=HarnessConfig(adaptive=False))
    ctx = context(tmp_path, "readonly", cfg)
    path = Path(ctx.workspace_dir, "EXPERIENCE.md")
    path.write_text("EXISTING_REPOSITORY_MEMORY")
    engine, _, model = fixture_engine()
    assert engine.run(ctx, "readonly task").success
    assert "EXISTING_REPOSITORY_MEMORY" in kinds(model, "plan")[0][0]["content"]
    assert not kinds(model, "adapt") and not kinds(model, "experience")
    assert path.read_text() == "EXISTING_REPOSITORY_MEMORY"


def test_selected_experience_path_is_used_for_injection_and_append(tmp_path):
    cfg = OpenJulesConfig(test_command="verify", harness=HarnessConfig(experience_path="notes/memory.md"))
    ctx = context(tmp_path, "custom", cfg)
    path = Path(ctx.workspace_dir, "notes/memory.md")
    path.parent.mkdir()
    path.write_text("SELECTED_MEMORY")
    default = Path(ctx.workspace_dir, "EXPERIENCE.md")
    default.write_text("UNSELECTED_MEMORY")
    engine, _, model = fixture_engine()
    assert engine.run(ctx, "custom task").success
    assert "SELECTED_MEMORY" in kinds(model, "plan")[0][0]["content"]
    assert "UNSELECTED_MEMORY" not in repr(model.calls)
    assert path.read_text().startswith("SELECTED_MEMORY")
    assert "verified fixture" in path.read_text()
    assert default.read_text() == "UNSELECTED_MEMORY"


@pytest.mark.parametrize("maximum,proposals", [(0, 0), (1, 1), (2, 2), (20, 2)])
def test_refinement_limit_caps_proposals_without_extending_verification(tmp_path, maximum, proposals):
    cfg = OpenJulesConfig(test_command="verify", harness=HarnessConfig(max_refinements=maximum))
    ctx = context(tmp_path, "failed", cfg)
    engine, sandbox, model = fixture_engine(failures={"failed"})
    assert not engine.run(ctx, "failed task").success
    assert len(kinds(model, "adapt")) == proposals
    assert len(kinds(model, "correction")) == 2
    commands = [call.args[1] for call in sandbox.exec_in_sandbox.call_args_list]
    assert commands.count("probe") == proposals
    assert commands.count("verify") == 3
    assert not kinds(model, "experience")


def test_failed_run_guardrails_and_configuration_do_not_reach_next_run(tmp_path):
    template = ObservedHarness()
    template.active_guardrails.append("TEMPLATE_ONLY")
    first = context(tmp_path, "first", OpenJulesConfig(test_command="verify",
        harness=HarnessConfig(experience_path="first.md", max_refinements=1)))
    second = context(tmp_path, "second", OpenJulesConfig(test_command="verify",
        harness=HarnessConfig(adaptive=False, inject_experience=False, experience_path="second.md")))
    engine, _, model = fixture_engine(failures={"first"}, harness=template)
    assert not engine.run(first, "first task").success
    assert engine.run(second, "second task").success
    first_run, second_run = template.sessions
    assert first_run.active_guardrails == ["guard:first task"]
    assert second_run.active_guardrails == []
    assert first_run.config.experience_path == "first.md"
    assert second_run.config.experience_path == "second.md"
    assert first_run.config is not first.config.harness
    assert first_run.experience_mgr is not second_run.experience_mgr
    assert template.active_guardrails == ["TEMPLATE_ONLY"]
    assert template.config.experience_path == "EXPERIENCE.md"
    assert engine.harness is template
    second_plan = kinds(model, "plan")[1]
    assert "guard:first task" not in repr(second_plan) and "TEMPLATE_ONLY" not in repr(model.calls)


def test_overlapping_runs_on_one_engine_keep_their_own_harness(tmp_path):
    template = ObservedHarness()
    model = ScriptedModel(threading.Barrier(2))
    engine, _, _ = fixture_engine(failures={"alpha"}, harness=template, model=model)
    contexts = [context(tmp_path, name, OpenJulesConfig(test_command="verify",
        harness=HarnessConfig(adaptive=name == "alpha", max_refinements=1, experience_path=name + ".md")))
        for name in ("alpha", "beta")]
    for ctx in contexts:
        Path(ctx.workspace_dir, ctx.container_id + ".md").write_text("MEMORY_" + ctx.container_id)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda ctx: engine.run(ctx, ctx.container_id + " task"), contexts))
    assert [result.success for result in results] == [False, True]
    for kind in ("plan", "action"):
        for messages in kinds(model, kind):
            selected = "alpha" if "alpha task" in messages[-1]["content"] else "beta"
            other = "beta" if selected == "alpha" else "alpha"
            assert "MEMORY_" + selected in messages[0]["content"]
            assert "MEMORY_" + other not in messages[0]["content"]
    assert len(template.sessions) == 2
    assert template.sessions[0].config is not template.sessions[1].config
    assert template.sessions[0].active_guardrails is not template.sessions[1].active_guardrails
    sessions = {session.config.experience_path: session for session in template.sessions}
    assert sessions["alpha.md"].active_guardrails == ["guard:alpha task"]
    assert sessions["beta.md"].active_guardrails == []
    assert engine.harness is template


def test_aborted_run_cannot_leave_adaptation_in_the_next_run(tmp_path):
    class InterruptedModel(ScriptedModel):
        def completion(self, *, messages, **options):
            if "Fix the failing tests" in messages[0]["content"]:
                raise RuntimeError("interrupted corrective call")
            return super().completion(messages=messages, **options)

    template = ObservedHarness()
    engine, _, model = fixture_engine(failures={"aborted"}, harness=template, model=InterruptedModel())
    with pytest.raises(RuntimeError, match="interrupted corrective call"):
        engine.run(context(tmp_path, "aborted"), "aborted task")
    assert engine.run(context(tmp_path, "following"), "following task").success
    assert template.sessions[0].active_guardrails == ["guard:aborted task"]
    assert template.sessions[1].active_guardrails == []
    assert "guard:aborted task" not in repr(kinds(model, "plan")[1])


def test_direct_step_preserves_injected_harness_and_explicit_verification_limit(tmp_path):
    harness = AdaptiveHarness(HarnessConfig(adaptive=False, inject_experience=False))
    harness.active_guardrails.append("DIRECT_COMPONENT_GUARD")
    engine, sandbox, model = fixture_engine(failures={"direct"}, harness=harness)
    ctx = context(tmp_path, "direct")
    engine.step_a_planning(ctx, "direct task", MagicMock())
    assert "DIRECT_COMPONENT_GUARD" in kinds(model, "plan")[0][0]["content"]
    assert not engine.step_c_verification(ctx, MagicMock(), fix_attempts=1)
    assert not kinds(model, "adapt") and not kinds(model, "correction")


def test_adaptation_and_distillation_use_selected_engine_route_and_bounds(tmp_path):
    model = ScriptedModel()
    sandbox = MagicMock(spec=SandboxManager)
    attempts = 0

    def execute(_container, command):
        nonlocal attempts
        if command == "verify":
            attempts += 1
        return ExecResult(stdout="fixture", stderr="", exit_code=int(command == "verify" and attempts == 1))

    sandbox.exec_in_sandbox.side_effect = execute
    config = LLMConfig(model="openai/operator-model", api_base="https://operator.example/v1",
                       api_key="fixture-provider-key", max_tokens=321, temperature=0.7)
    engine = AgentEngine(sandbox, llm_client=model, llm_config=config)
    ctx = context(tmp_path, "routed")
    assert engine.run(ctx, "routed task").success
    assert len(kinds(model, "adapt")) == len(kinds(model, "experience")) == 1
    for kind, options in model.options:
        assert options["api_base"] == "https://operator.example/v1"
        assert options["api_key"] == "fixture-provider-key"
        assert options["max_tokens"] == 321
        assert options["model"] == "openai/operator-model"
        if kind in {"adapt", "experience"}:
            assert "tools" not in options and "tool_choice" not in options
            assert options["temperature"] == {"adapt": 0.1, "experience": 0.2}[kind]
    assert config.temperature == engine.llm_config.temperature == 0.7


def test_negative_repository_budget_refuses_before_effects_without_defaulting(tmp_path):
    cfg = load_config_from_yaml("harness:\n  adaptive: false\n  max_refinements: -1\n")
    assert cfg.harness.adaptive is False and cfg.harness.max_refinements == -1
    engine, sandbox, model = fixture_engine()
    with pytest.raises(ValueError, match="nonnegative integer"):
        engine.run(context(tmp_path, "negative", cfg), "negative budget")
    assert not model.calls
    sandbox.exec_in_sandbox.assert_not_called()


@pytest.mark.parametrize("path", ["/tmp/elsewhere", "../elsewhere", "notes/../../elsewhere", "", ".",
                                  "notes//memory.md", "notes/./memory.md", "C:\\elsewhere", "x\0y"])
def test_experience_path_refuses_escape_syntax(path):
    with pytest.raises(ValueError):
        ExperienceManager(path)


@pytest.mark.parametrize("kind", ["leaf_symlink", "parent_symlink", "hardlink", "fifo"])
def test_experience_never_reads_or_writes_host_link_targets(tmp_path, kind):
    workspace, outside = tmp_path / "workspace", tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    secret = outside / "memory.md"
    secret.write_text("HOST_PRIVATE_CONTENT")
    name = "memory.md"
    target = workspace / name
    if kind == "leaf_symlink":
        target.symlink_to(secret)
    elif kind == "parent_symlink":
        (workspace / "notes").symlink_to(outside, target_is_directory=True)
        name = "notes/memory.md"
    elif kind == "hardlink":
        os.link(secret, target)
    else:
        os.mkfifo(target)
    manager = ExperienceManager(name)
    assert manager.load_experience(str(workspace)) == ""
    with pytest.raises((OSError, ValueError)):
        manager.append_experience(str(workspace), "task", "problem", "solution", [])
    assert secret.read_text() == "HOST_PRIVATE_CONTENT"


def test_bad_repository_experience_path_refuses_before_model_or_sandbox(tmp_path):
    cfg = OpenJulesConfig(harness=HarnessConfig(experience_path="../host-private"))
    ctx = context(tmp_path, "escape", cfg)
    engine, sandbox, model = fixture_engine()
    with pytest.raises(ValueError, match="relative workspace"):
        engine.run(ctx, "bad settings")
    assert not model.calls
    sandbox.exec_in_sandbox.assert_not_called()
