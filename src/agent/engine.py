"""Two-stage planner and executor agent loop using LiteLLM/OpenAI format."""

import json
import logging
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

import re
import litellm
from src.agent.agents_rules import AgentsRuleEngine
from src.agent.ast_indexer import ASTSymbolIndexer
from src.agent.ensemble import EnsembleEngine
from src.agent.linter import LinterGuardrail, LintResult
from src.agent.llm_config import LLMConfig, resolve_llm_config
from src.agent.security_scanner import SecurityScanner
from src.agent.tandem import TandemSubagentCoordinator
from src.agent.tdd_synthesizer import TDDSynthesizer
from src.agent.tools import AgentTools, TOOL_DEFINITIONS
from src.agent.visual_verifier import VisualVerifier
from src.git_manager.checkpoints import GitCheckpointManager
from src.harness.adaptive_engine import AdaptiveHarness
from src.polyphony.client import PolyphonyClient
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import SandboxContext, SandboxManager

logger = logging.getLogger(__name__)


class _HarnessCompletion:
    """Keep helper inference on one snapshot of the selected engine route."""

    def __init__(self, engine):
        self._call = engine._call_llm
        self._config = engine.llm_config.model_copy(deep=True)
        self._config.model = engine.model_name

    def completion(self, *, model, messages, temperature):
        if model != self._config.model:
            raise ValueError("harness cannot replace the selected engine model")
        # Proposal/distillation temperatures are purpose-specific overrides;
        # endpoint, credential and token bound stay on the selected route.
        config = self._config.model_copy(update={"temperature": temperature})
        return self._call(messages, active_config=config)


class PlanOutput(BaseModel):
    """Structured plan generated during Step A."""

    rationale: str = Field(description="Problem analysis and approach rationale")
    target_files: List[str] = Field(
        default_factory=list, description="Files intended to be modified or created"
    )
    planned_tests: List[str] = Field(
        default_factory=list, description="Tests to run or create for verification"
    )
    action_steps: List[str] = Field(
        default_factory=list, description="Ordered step-by-step implementation actions"
    )


class AgentResult(BaseModel):
    """Result of agent execution loop."""

    success: bool
    plan: Optional[PlanOutput] = None
    turns_taken: int = 0
    verification_passed: bool = False
    message: str = ""
    error: Optional[str] = None


class AgentEngine:
    """Orchestrates Step A (Planning), Step B (ReAct Loop), and Step C (Verification)."""

    def __init__(
        self,
        sandbox_manager: SandboxManager,
        model_name: Optional[str] = None,
        max_turns: int = 25,
        llm_client: Optional[Any] = None,
        llm_config: Optional[LLMConfig] = None,
        adaptive_harness: Optional[AdaptiveHarness] = None,
    ):
        self.sandbox_manager = sandbox_manager
        self.max_turns = max_turns
        self.llm_client = llm_client or litellm
        self.llm_config = resolve_llm_config(llm_config)
        self.harness = adaptive_harness or AdaptiveHarness()
        self.linter = LinterGuardrail(self.sandbox_manager)
        self.rule_engine = AgentsRuleEngine()
        self.checkpoints = GitCheckpointManager(self.sandbox_manager)
        self.visual_verifier = VisualVerifier(self.sandbox_manager)
        self.ensemble = EnsembleEngine(self.llm_client)
        self.security_scanner = SecurityScanner()
        self.tdd_synthesizer = TDDSynthesizer(self.llm_client)
        self.tandem = TandemSubagentCoordinator(self.llm_client)
        if model_name:
            self.llm_config.model = model_name
        self.model_name = self.llm_config.model

    def _call_llm(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        active_config: Optional[LLMConfig] = None,
    ) -> Any:
        """Invokes LLM with OpenAI/vLLM/llama.cpp compatibility parameters."""
        cfg = active_config or self.llm_config
        kwargs: Dict[str, Any] = {
            "model": cfg.model,
            "messages": messages,
            "temperature": cfg.temperature,
        }
        if cfg.api_base:
            kwargs["api_base"] = cfg.api_base
        if cfg.api_key:
            kwargs["api_key"] = cfg.api_key
        if cfg.max_tokens:
            kwargs["max_tokens"] = cfg.max_tokens

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        try:
            return self.llm_client.completion(**kwargs)
        except Exception as e:
            # If server does not support tools schema (e.g. older llama.cpp server), retry without tools parameter
            err_msg = str(e).lower()
            if tools and ("tool" in err_msg or "schema" in err_msg or "not supported" in err_msg):
                logger.warning(
                    f"LLM server rejected tools parameter ({e}). Retrying with prompt-guided JSON mode..."
                )
                del kwargs["tools"]
                if "tool_choice" in kwargs:
                    del kwargs["tool_choice"]
                # Append tool definition guide to system/user prompt
                fallback_guide = (
                    "\n\nTo call a tool, respond with a JSON codeblock format:\n"
                    "```json\n{\"tool\": \"<tool_name>\", \"arguments\": {<args>}}\n```\n"
                    "Or reply 'TASK_COMPLETED' if done."
                )
                augmented_messages = list(messages)
                augmented_messages[-1] = {
                    "role": augmented_messages[-1]["role"],
                    "content": augmented_messages[-1]["content"] + fallback_guide,
                }
                kwargs["messages"] = augmented_messages
                return self.llm_client.completion(**kwargs)
            raise e

    def step_a_planning(
        self,
        context: SandboxContext,
        task_instruction: str,
        tools: AgentTools,
        *,
        harness: Optional[AdaptiveHarness] = None,
    ) -> PlanOutput:
        """Step A: Inspect repository context and generate structured JSON plan."""
        # Probe directory tree and README
        file_tree = tools.list_files(".", max_depth=2)
        readme_preview = tools.read_file("README.md", offset=1, limit=50)

        planning_prompt = (
            f"You are OpenJules, an autonomous software engineering agent.\n"
            f"Task Instruction:\n{task_instruction}\n\n"
            f"Repository file listing:\n{file_tree}\n\n"
            f"README snippet:\n{readme_preview}\n\n"
            f"Test verification command configured: {context.config.test_command}\n\n"
            f"Formulate a structured JSON plan with the following keys:\n"
            f"- rationale: string\n"
            f"- target_files: list of file paths\n"
            f"- planned_tests: list of verification tests\n"
            f"- action_steps: list of steps to execute\n"
            f"Respond ONLY with valid JSON."
        )

        # Inject accumulated experience and adaptive guardrails from the harness
        selected_harness = self.harness if harness is None else harness
        harness_context = selected_harness.get_system_prompt_extension(context.workspace_dir)
        agents_rules_context = self.rule_engine.get_prompt_context(context.workspace_dir)

        system_content = "You are a senior software architect planning a code change. Always return valid JSON."
        if agents_rules_context:
            system_content += f"\n\n{agents_rules_context}"
        if harness_context:
            system_content += f"\n\n{harness_context}"

        messages = [
            {"role": "system", "content": system_content},
            {"role": "user", "content": planning_prompt},
        ]

        try:
            response = self._call_llm(messages)
            content = response.choices[0].message.content or "{}"
            # Extract json if wrapped in ```json
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            plan_dict = json.loads(content)
            return PlanOutput(**plan_dict)
        except Exception as e:
            logger.warning(f"Failed to parse LLM plan as JSON: {e}. Falling back to default plan.")
            return PlanOutput(
                rationale=f"Plan to execute task: {task_instruction[:100]}",
                target_files=[],
                planned_tests=[context.config.test_command],
                action_steps=["Examine repository", "Make requested changes", "Run tests"],
            )

    def execute_tool(self, tools: AgentTools, tool_name: str, args: Dict[str, Any]) -> str:
        """Dispatches tool call to AgentTools."""
        if tool_name == "read_file":
            return tools.read_file(
                path=args.get("path", ""),
                offset=args.get("offset", 1),
                limit=args.get("limit", 200),
            )
        elif tool_name == "write_file":
            return tools.write_file(
                path=args.get("path", ""),
                content=args.get("content", ""),
            )
        elif tool_name == "apply_patch":
            return tools.apply_patch(
                path=args.get("path", ""),
                patch_str=args.get("patch_str", ""),
            )
        elif tool_name == "run_command":
            return tools.run_command(
                command=args.get("command", ""),
                timeout=args.get("timeout", 120),
            )
        elif tool_name == "list_files":
            return tools.list_files(
                directory=args.get("directory", "."),
                max_depth=args.get("max_depth", 3),
            )
        else:
            return f"Unknown tool: {tool_name}"

    def step_b_action_loop(
        self,
        context: SandboxContext,
        task_instruction: str,
        plan: PlanOutput,
        tools: AgentTools,
        on_progress: Optional[Callable[[str], None]] = None,
        *,
        harness: Optional[AdaptiveHarness] = None,
    ) -> int:
        """Step B: Stateful ReAct loop with max turn limit."""
        system_prompt = (
            "You are OpenJules, an autonomous software engineering agent. "
            "Your goal is to inspect the codebase, edit code, run commands, and verify your changes. "
            "Use the provided tools to inspect files, edit files, and run commands. "
            "Once you have completed all changes and verified them, reply with 'TASK_COMPLETED'."
        )

        plan_summary = (
            f"Approved Plan:\n"
            f"Rationale: {plan.rationale}\n"
            f"Target Files: {plan.target_files}\n"
            f"Steps: {plan.action_steps}\n"
        )

        # Inject accumulated experience and adaptive guardrails from the harness
        selected_harness = self.harness if harness is None else harness
        harness_context = selected_harness.get_system_prompt_extension(context.workspace_dir)
        full_system_prompt = system_prompt
        if harness_context:
            full_system_prompt += f"\n\n{harness_context}"

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": full_system_prompt},
            {"role": "user", "content": f"Task: {task_instruction}\n\n{plan_summary}"},
        ]

        turns = 0
        while turns < self.max_turns:
            turns += 1
            if on_progress:
                on_progress(f"Executing turn {turns}/{self.max_turns}...")

            response = self._call_llm(messages, tools=TOOL_DEFINITIONS)
            msg = response.choices[0].message

            # Add assistant message to history
            assistant_msg_dict: Dict[str, Any] = {
                "role": "assistant",
                "content": msg.content,
            }
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                assistant_msg_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
            messages.append(assistant_msg_dict)

            # Check if finished or fallback JSON tool call in content
            content_text = msg.content or ""
            tool_calls = getattr(msg, "tool_calls", None)

            if not tool_calls:
                if "TASK_COMPLETED" in content_text:
                    break

                # Fallback: check if model generated a JSON tool call block in text
                json_tool_match = re.search(r"```json\s*(\{.*?\})\s*```", content_text, re.DOTALL)
                if not json_tool_match and content_text.strip().startswith("{") and content_text.strip().endswith("}"):
                    json_tool_candidate = content_text.strip()
                elif json_tool_match:
                    json_tool_candidate = json_tool_match.group(1)
                else:
                    json_tool_candidate = None

                if json_tool_candidate:
                    try:
                        parsed_tc = json.loads(json_tool_candidate)
                        t_name = parsed_tc.get("tool") or parsed_tc.get("function") or parsed_tc.get("name")
                        t_args = parsed_tc.get("arguments") or parsed_tc.get("args") or {}
                        if t_name:
                            tool_out = self.execute_tool(tools, t_name, t_args)
                            messages.append(
                                {
                                    "role": "user",
                                    "content": f"[Tool Output for {t_name}]:\n{tool_out}",
                                }
                            )
                            continue
                    except Exception as e:
                        logger.debug(f"Could not parse fallback json tool call: {e}")

                # If no tool calls and no completion keyword, terminate turn loop
                break

            # Execute standard tool calls
            for tc in tool_calls:
                func_name = tc.function.name
                raw_args = tc.function.arguments
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except Exception:
                    args = {}

                tool_output = self.execute_tool(tools, func_name, args)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "name": func_name,
                        "content": str(tool_output),
                    }
                )

        return turns

    def step_c_verification(
        self,
        context: SandboxContext,
        tools: AgentTools,
        task_instruction: str = "",
        fix_attempts: int = 3,
        on_progress: Optional[Callable[[str], None]] = None,
        *,
        harness: Optional[AdaptiveHarness] = None,
        harness_client: Optional[Any] = None,
    ) -> bool:
        """Verify at most fix_attempts times, with separately capped adaptation.

        Disabling adaptation or exhausting its proposal budget still permits
        ordinary corrective model/tool calls within this same attempt limit.
        """
        if type(fix_attempts) is not int or fix_attempts < 1:
            raise ValueError("fix_attempts must be a positive integer")
        selected_harness = self.harness if harness is None else harness
        selected_client = _HarnessCompletion(self) if harness_client is None else harness_client
        test_cmd = context.config.test_command
        if not test_cmd:
            return True

        refinements = 0
        for attempt in range(1, fix_attempts + 1):
            if on_progress:
                on_progress(f"Running verification: '{test_cmd}' (attempt {attempt}/{fix_attempts})...")

            res = self.sandbox_manager.exec_in_sandbox(context.container_id, test_cmd)
            if res.exit_code == 0:
                return True

            if attempt == fix_attempts:
                logger.warning(f"Verification failed on final attempt:\n{res.stdout}\n{res.stderr}")
                return False

            error_trace = f"{res.stdout}\n{res.stderr}".strip()
            probe_results = []
            adaptation_text = ""
            if selected_harness.config.adaptive and refinements < selected_harness.config.max_refinements:
                refinements += 1
                proposal = selected_harness.propose_harness_adaptation(
                    llm_client=selected_client,
                    model_name=self.model_name,
                    task_instruction=task_instruction,
                    failing_command=test_cmd,
                    test_traceback=error_trace,
                )

                # Only an enabled, budgeted proposal can introduce probes.
                for helper_cmd in proposal.suggested_helper_commands:
                    probe_res = self.sandbox_manager.exec_in_sandbox(context.container_id, helper_cmd)
                    probe_results.append(f"$ {helper_cmd}\n{probe_res.stdout or probe_res.stderr}")
                adaptation_text = (
                    f"Adaptive Strategy: {proposal.suggested_strategy}\n"
                    f"Active Guardrails: {proposal.targeted_guardrails}\n"
                )

            probe_text = ("\n\nDiagnostic Probe Results:\n" + "\n".join(probe_results)) if probe_results else ""

            # Feed failure, adapted guardrails, and diagnostic probes back to model
            feedback_prompt = (
                f"The test verification command '{test_cmd}' failed with exit code {res.exit_code}.\n"
                f"[STDOUT]:\n{res.stdout}\n"
                f"[STDERR]:\n{res.stderr}\n\n"
                f"{adaptation_text}"
                f"{probe_text}\n"
                f"Analyze the traceback and fix the code using your tools."
            )
            messages = [
                {"role": "system", "content": "You are OpenJules. Fix the failing tests using your tools."},
                {"role": "user", "content": feedback_prompt},
            ]

            response = self._call_llm(messages, tools=TOOL_DEFINITIONS)
            msg = response.choices[0].message
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments)
                    except Exception:
                        args = {}
                    self.execute_tool(tools, tc.function.name, args)

        return False

    def run(
        self,
        context: SandboxContext,
        task_instruction: str,
        on_progress: Optional[Callable[[str], None]] = None,
        polyphony: Optional[PolyphonyClient] = None,
    ) -> AgentResult:
        """Executes full Step A -> Step B -> Step C workflow with Polyphony coordination."""
        # Explicitly pass run-local state: the same engine may serve overlapping
        # repositories, so temporarily replacing self.harness is not safe.
        harness = self.harness.for_run(context.config.harness)
        harness_client = _HarnessCompletion(self)
        tools = AgentTools(self.sandbox_manager, context.container_id)

        # Step A: Planning
        if on_progress:
            on_progress("Step A: Formulating plan...")
        if polyphony:
            polyphony.set_status("planning")
            polyphony.share_thought("Step A: Formulating plan for repository...")

        plan = self.step_a_planning(context, task_instruction, tools, harness=harness)

        if polyphony:
            polyphony.share_thought(f"Step A plan generated: {plan.rationale[:150]}")
            # Acquire baton locks on planned target files if possible
            for target_file in plan.target_files:
                polyphony.acquire_baton(f"file:{target_file}")

        # Step B: ReAct action loop
        if on_progress:
            on_progress("Step B: Executing action loop...")
        if polyphony:
            polyphony.set_status("busy")
            polyphony.share_thought("Step B: Executing ReAct loop edits inside sandbox...")

        turns = self.step_b_action_loop(context, task_instruction, plan, tools, on_progress, harness=harness)

        # Step C: Optional static analysis linter run before test suite
        if context.config.lint_command:
            if on_progress:
                on_progress(f"Running linter guardrail: '{context.config.lint_command}'...")
            lint_res = self.linter.run_linter(context.container_id, context.config.lint_command)
            if not lint_res.passed and polyphony:
                polyphony.share_thought(f"Linter detected issues ({len(lint_res.diagnostics)} diagnostics)")

        # Step C: Verification
        if on_progress:
            on_progress("Step C: Verifying test suite...")
        if polyphony:
            polyphony.set_status("verifying")
            polyphony.share_thought(f"Step C: Running verification command '{context.config.test_command}'...")

        verified = self.step_c_verification(
            context,
            tools,
            task_instruction=task_instruction,
            on_progress=on_progress,
            harness=harness,
            harness_client=harness_client,
        )

        if polyphony:
            polyphony.share_thought(
                f"Step C verification {'PASSED' if verified else 'FAILED'} after {turns} turns."
            )
            polyphony.set_status("idle")

        # Outer Loop Adaptation: On successful verification, distill learnings into EXPERIENCE.md
        if verified and context.workspace_dir and harness.config.adaptive:
            try:
                harness.record_successful_run(
                    workspace_dir=context.workspace_dir,
                    task_title=task_instruction[:80],
                    task_instruction=task_instruction,
                    llm_client=harness_client,
                    model_name=self.model_name,
                )
            except Exception as e:
                logger.debug(f"Experience recording ignored: {e}")

        return AgentResult(
            success=verified,
            plan=plan,
            turns_taken=turns,
            verification_passed=verified,
            message="Task executed and verified" if verified else "Task executed but verification failed",
        )
