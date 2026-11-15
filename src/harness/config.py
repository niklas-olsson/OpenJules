"""Configuration schema for OpenJules Adaptive Agent Harness."""

from typing import Optional
from pydantic import BaseModel, Field


class HarnessConfig(BaseModel):
    """Configuration for adaptive harness behavior and persistence."""

    adaptive: bool = Field(
        default=True,
        description="Whether to enable dynamic harness adaptation (Propose-Probe-Compose loop).",
    )
    experience_path: str = Field(
        default="EXPERIENCE.md",
        description="Path relative to workspace root where cross-task learnings are persisted.",
    )
    max_refinements: int = Field(
        default=3,
        description="Maximum adaptive proposals after failed verification, within the engine's separate verification-attempt limit.",
    )
    inject_experience: bool = Field(
        default=True,
        description="Whether to inject accumulated experience into the model context during planning and execution.",
    )
