"""Adaptive Agent Harness implementing the Propose-Probe-Compose optimization loop."""

import copy
import json
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.harness.config import HarnessConfig
from src.harness.experience import ExperienceManager

logger = logging.getLogger(__name__)


class HarnessProposal(BaseModel):
    """Refined harness configuration proposed by the adaptation loop."""

    targeted_guardrails: List[str] = Field(
        default_factory=list,
        description="Explicit constraints added to system prompt to prevent repeated errors.",
    )
    suggested_helper_commands: List[str] = Field(
        default_factory=list,
        description="Diagnostic or setup shell commands to probe in the sandbox.",
    )
    suggested_strategy: str = Field(
        default="",
        description="Refined engineering strategy to achieve verification passing.",
    )


class AdaptiveHarness:
    """Manages dynamic harness adaptation (Inner Loop) and cross-task skill compounding (Outer Loop)."""

    def __init__(self, config: Optional[HarnessConfig] = None):
        self.config = config or HarnessConfig()
        self.experience_mgr = ExperienceManager(self.config.experience_path)
        self.active_guardrails: List[str] = []

    def for_run(self, config: HarnessConfig) -> "AdaptiveHarness":
        """Bind repository settings and fresh task state to this behavior template.

        A shallow clone preserves injected subclass methods. Subclasses with
        additional mutable per-run state must override this factory to isolate
        that state too. The template itself is never changed by an engine run.
        """
        # Check at consumption: the legacy repository parser replaces invalid
        # Pydantic models with defaults, which must not turn disabled adaptation
        # back on merely because this newly consumed budget is negative.
        if type(config.max_refinements) is not int or config.max_refinements < 0:
            raise ValueError("max_refinements must be a nonnegative integer")
        session = copy.copy(self)
        session.config = config.model_copy(deep=True)
        session.experience_mgr = ExperienceManager(session.config.experience_path)
        session.active_guardrails = []
        return session

    def get_system_prompt_extension(self, workspace_dir: str) -> str:
        """Constructs context additions including accumulated experience and active guardrails."""
        parts = []

        # 1. Inject accumulated experience from EXPERIENCE.md
        if self.config.inject_experience:
            past_exp = self.experience_mgr.load_experience(workspace_dir)
            if past_exp:
                # Truncate if extremely long to avoid context overflow
                truncated_exp = past_exp[-3000:] if len(past_exp) > 3000 else past_exp
                parts.append(f"### Historical Repository Learnings & Guardrails:\n{truncated_exp}")

        # 2. Inject active dynamic guardrails formulated during this task run
        if self.active_guardrails:
            guardrails_text = "\n".join(f"- {g}" for g in self.active_guardrails)
            parts.append(f"### Adaptive Task Guardrails:\n{guardrails_text}")

        return "\n\n".join(parts)

    def propose_harness_adaptation(
        self,
        llm_client: Any,
        model_name: str,
        task_instruction: str,
        failing_command: str,
        test_traceback: str,
    ) -> HarnessProposal:
        """Inner Loop - Propose: Analyzes failure trace and generates a targeted harness configuration."""
        if not self.config.adaptive:
            return HarnessProposal()
        prompt = (
            f"You are the OpenJules Adaptive Agent Harness optimizer.\n"
            f"A task failed automated verification.\n\n"
            f"Task:\n{task_instruction}\n\n"
            f"Failing Verification Command:\n{failing_command}\n\n"
            f"Error / Traceback Output:\n{test_traceback}\n\n"
            f"Propose an adapted harness configuration to guide the next fix attempt.\n"
            f"Return JSON with:\n"
            f"- targeted_guardrails: list of concrete dos and don'ts to add to the system prompt\n"
            f"- suggested_helper_commands: list of shell commands to run or diagnose\n"
            f"- suggested_strategy: concise diagnosis and fix strategy\n"
            f"Respond ONLY with valid JSON."
        )
        try:
            resp = llm_client.completion(
                model=model_name,
                messages=[
                    {"role": "system", "content": "You optimize agent harness configurations. Return JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
            )
            content = resp.choices[0].message.content or "{}"
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            parsed = json.loads(content)
            proposal = HarnessProposal(**parsed)
            # Compose new active guardrails
            self.active_guardrails.extend(proposal.targeted_guardrails)
            return proposal
        except Exception as e:
            logger.warning(f"Failed to generate adaptive harness proposal: {e}")
            fallback = HarnessProposal(
                targeted_guardrails=["Carefully inspect the stack trace and verify module imports."],
                suggested_helper_commands=[],
                suggested_strategy="Fix syntax or import errors causing test failure.",
            )
            self.active_guardrails.extend(fallback.targeted_guardrails)
            return fallback

    def record_successful_run(
        self,
        workspace_dir: str,
        task_title: str,
        task_instruction: str,
        llm_client: Any,
        model_name: str,
    ) -> Optional[str]:
        """Outer Loop - Compose: Distills learnings from a successful task into EXPERIENCE.md."""
        if not self.config.adaptive:
            return None

        prompt = (
            f"The following task has successfully passed all verification tests:\n"
            f"Task: {task_title}\n\n"
            f"Details: {task_instruction[:300]}\n\n"
            f"Summarize the key architectural insight or repository-specific pattern discovered.\n"
            f"Return JSON with:\n"
            f"- problem_summary: 1 sentence summary\n"
            f"- solution_pattern: 1-2 sentence description of the solution\n"
            f"- discovered_rules: list of 1-3 concise rules for future agents working in this repo\n"
            f"Respond ONLY with valid JSON."
        )

        try:
            resp = llm_client.completion(
                model=model_name,
                messages=[
                    {"role": "system", "content": "You distill engineering experience. Return JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            content = resp.choices[0].message.content or "{}"
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            data = json.loads(content)

            return self.experience_mgr.append_experience(
                workspace_dir=workspace_dir,
                task_title=task_title,
                problem_summary=data.get("problem_summary", "Completed issue requirements."),
                solution_pattern=data.get("solution_pattern", "Applied code changes and verified tests."),
                discovered_rules=data.get("discovered_rules", []),
            )
        except Exception as e:
            logger.warning(f"Failed to distill and record experience: {e}")
            # Non-blocking fallback
            return self.experience_mgr.append_experience(
                workspace_dir=workspace_dir,
                task_title=task_title,
                problem_summary="Automated task implementation.",
                solution_pattern="All tests passed successfully.",
                discovered_rules=[],
            )
