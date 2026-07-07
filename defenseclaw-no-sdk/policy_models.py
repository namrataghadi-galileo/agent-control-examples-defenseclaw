"""Small local models; this example intentionally imports no Agent Control SDK models."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PolicyCheck:
    step_name: str
    step_type: str
    input: dict[str, Any]
    hook_event: str
    client_name: str
    stage: str = "pre"
    output: Any | None = None

    def __post_init__(self) -> None:
        if self.step_type not in {"llm", "tool"}:
            raise ValueError(f"Unsupported step type: {self.step_type}")
        if self.stage not in {"pre", "post"}:
            raise ValueError(f"Unsupported evaluation stage: {self.stage}")
        if "policy_text" in self.input:
            return
        normalized = dict(self.input)
        rendered = json.dumps(normalized, sort_keys=True, default=str)
        normalized["policy_text"] = f"{self.step_name} {rendered}"
        object.__setattr__(self, "input", normalized)


@dataclass(frozen=True)
class ControlExecution:
    control_execution_id: str
    control_id: int
    control_name: str
    action: str
    matched: bool
    confidence: float
    message: str | None = None
    error: str | None = None
    steering_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    is_safe: bool
    confidence: float
    reason: str | None
    matches: tuple[ControlExecution, ...]
    errors: tuple[ControlExecution, ...]
    non_matches: tuple[ControlExecution, ...]
    raw: dict[str, Any]

    @property
    def all_executions(self) -> tuple[ControlExecution, ...]:
        return (*self.matches, *self.errors, *self.non_matches)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    action: str
    reason: str
    source: str
    control_names: tuple[str, ...] = ()
    steering_context: str | None = None
    defenseclaw_action: str = "allow"
    defenseclaw_findings: tuple[str, ...] = ()
    agent_control_called: bool = False
    evaluation: EvaluationResult | None = None
    trace_id: str | None = None
    span_id: str | None = None
