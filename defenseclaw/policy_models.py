"""Shared policy request/decision models for the DefenseClaw demo."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyCheck:
    step_name: str
    step_type: str
    input: dict[str, Any]
    hook_event: str
    client_name: str

    def __post_init__(self) -> None:
        """Give every boundary one stable text field for cross-boundary controls."""
        if "policy_text" in self.input:
            return
        normalized = dict(self.input)
        rendered = json.dumps(normalized, sort_keys=True, default=str)
        normalized["policy_text"] = f"{self.step_name} {rendered}"
        object.__setattr__(self, "input", normalized)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    control_names: tuple[str, ...] = ()
    evaluation_location: str = "none"
    bundle_version: str | None = None
    defenseclaw_action: str = "allow"
    defenseclaw_reason: str = "No DefenseClaw finding."
    defenseclaw_findings: tuple[str, ...] = ()
    action: str = "allow"
    steering_context: str | None = None
