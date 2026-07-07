"""Thin DefenseClaw adapter around the Agent Control SDK policy engine."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol
from uuid import uuid4

import agent_control

from defenseclaw_gateway import (
    DefenseClawGatewayClient,
    DefenseClawUnavailableError,
    DefenseClawVerdict,
)
from policy_models import PolicyCheck, PolicyDecision

DEFAULT_AGENT_NAME = "defenseclaw-sdk-demo"

REGISTERED_STEPS: list[dict[str, Any]] = [
    {"type": "llm", "name": "agent.user_prompt", "input_schema": {"type": "object"}},
    *[
        {"type": "tool", "name": name, "input_schema": {"type": "object"}}
        for name in (
            "Bash",
            "shell",
            "exec_command",
            "Write",
            "Edit",
            "aws.s3.request",
            "filesystem.delete",
        )
    ],
]


class AgentControlSdk(Protocol):
    """The public SDK surface used by the DefenseClaw adapter."""

    def init(self, **kwargs: Any) -> Any: ...

    def get_server_controls(self) -> list[dict[str, Any]] | None: ...

    def refresh_controls(self) -> list[dict[str, Any]] | None: ...

    async def evaluate_controls(self, step_name: str, **kwargs: Any) -> Any: ...

    def shutdown(self) -> None: ...


class DefenseClawGateway(Protocol):
    """The DefenseClaw inspection surface used by the combined guard."""

    def inspect(
        self,
        check: PolicyCheck,
        *,
        trace_id: str,
        session_id: str,
        agent_name: str,
    ) -> DefenseClawVerdict: ...


def _run_sync[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Run an SDK coroutine from both normal and event-loop-owning callers."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="defenseclaw-agent-control") as pool:
        return pool.submit(asyncio.run, coroutine).result()


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _active_trace_context() -> tuple[str, str] | None:
    """Return an external provider's trace context when one is active."""
    context = agent_control.get_trace_context_from_provider()
    if context is None:
        return None
    return context["trace_id"], context["span_id"]


def _bundle_version(controls: list[dict[str, Any]]) -> str:
    encoded = json.dumps(controls, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _control_definition(control: dict[str, Any]) -> dict[str, Any]:
    definition = control.get("control")
    return definition if isinstance(definition, dict) else {}


def _match_name(match: Any) -> str:
    return str(getattr(match, "control_name", "unknown-control"))


def _match_reason(match: Any) -> str:
    result = getattr(match, "result", None)
    detail = (
        getattr(result, "error", None)
        or getattr(result, "message", None)
        or getattr(match, "action", None)
        or "matched"
    )
    return f"{_match_name(match)}: {detail}"


def _steering_message(match: Any) -> str | None:
    context = getattr(match, "steering_context", None)
    message = getattr(context, "message", None)
    return str(message) if message else None


def _evaluation_location(result: Any, controls: list[dict[str, Any]]) -> str:
    """Describe the SDK routes represented in the evaluated-result lists."""
    by_id = {control.get("id"): control for control in controls}
    by_name = {str(control.get("name")): control for control in controls}
    evaluated = [
        *(result.matches or []),
        *(result.non_matches or []),
        *(result.errors or []),
    ]
    executions: set[str] = set()
    for match in evaluated:
        control = by_id.get(getattr(match, "control_id", None)) or by_name.get(_match_name(match))
        if control is None:
            continue
        execution = _control_definition(control).get("execution", "server")
        executions.add(str(execution))

    if executions == {"sdk"}:
        return "local"
    if executions == {"server"}:
        return "remote"
    if executions == {"sdk", "server"}:
        return "local+remote"
    return "none"


class DefenseClawPolicyClient:
    """Apply real DefenseClaw inspection, then Agent Control SDK policy."""

    def __init__(
        self,
        sdk: AgentControlSdk | None = None,
        defenseclaw: DefenseClawGateway | None = None,
    ) -> None:
        self.sdk: AgentControlSdk = sdk or agent_control
        self.defenseclaw = defenseclaw or DefenseClawGatewayClient()
        self.server_url = os.environ.get("AGENT_CONTROL_URL", "").rstrip("/")
        self.api_key = os.environ.get("AGENT_CONTROL_API_KEY") or os.environ.get("GALILEO_API_KEY")
        self.api_key_header = os.environ.get("AGENT_CONTROL_API_KEY_HEADER", "Galileo-API-Key")
        self.agent_name = os.environ.get("AGENT_CONTROL_AGENT_NAME", DEFAULT_AGENT_NAME)
        self.target_type = os.environ.get("AGENT_CONTROL_TARGET_TYPE", "log_stream")
        self.target_id = os.environ.get("AGENT_CONTROL_TARGET_ID", "")
        self.refresh_seconds = int(os.environ.get("DEFENSECLAW_POLICY_REFRESH_SECONDS", "2"))
        self.observability_sink_name = os.environ.get(
            "DEFENSECLAW_AGENT_CONTROL_OBSERVABILITY_SINK",
            "default",
        )
        self.fail_open = _env_bool("DEFENSECLAW_FAILURE_MODE_OPEN", False)
        self._closed = False

        missing: list[str] = []
        if not self.server_url:
            missing.append("AGENT_CONTROL_URL")
        if not self.api_key:
            missing.append("GALILEO_API_KEY or AGENT_CONTROL_API_KEY")
        if not self.target_id:
            missing.append("AGENT_CONTROL_TARGET_ID")
        if missing:
            raise RuntimeError(f"Missing policy configuration: {', '.join(missing)}")
        if self.refresh_seconds < 0:
            raise RuntimeError("DEFENSECLAW_POLICY_REFRESH_SECONDS must be >= 0.")

        self.sdk.init(
            agent_name=self.agent_name,
            agent_description="Claude Code DefenseClaw and Agent Control SDK demo",
            agent_version="1.0.0",
            server_url=self.server_url,
            api_key=self.api_key,
            api_key_header=self.api_key_header,
            steps=REGISTERED_STEPS,
            conflict_mode="overwrite",
            observability_enabled=_env_bool("DEFENSECLAW_AGENT_CONTROL_OBSERVABILITY", True),
            observability_sink_name=self.observability_sink_name,
            policy_refresh_interval_seconds=self.refresh_seconds,
            target_type=self.target_type,
            target_id=self.target_id,
        )
        try:
            self._require_controls()
        except Exception:
            self.sdk.shutdown()
            self._closed = True
            raise

    def _require_controls(self) -> list[dict[str, Any]]:
        controls = self.sdk.get_server_controls()
        if not controls:
            raise RuntimeError(
                "Agent Control SDK did not load any effective controls for this DefenseClaw "
                "target; refusing to evaluate in fail-closed mode."
            )
        return controls

    @property
    def effective_controls(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._require_controls())

    def refresh(self) -> tuple[dict[str, Any], ...]:
        """Ask the SDK to refresh while retaining its last-known-good snapshot on failure."""
        self.sdk.refresh_controls()
        return self.effective_controls

    def evaluate(self, check: PolicyCheck) -> PolicyDecision:
        controls = self._require_controls()
        external_context = _active_trace_context()
        trace_id = external_context[0] if external_context else uuid4().hex
        span_id = external_context[1] if external_context else uuid4().hex[:16]
        session_id = f"s3-guard-{trace_id[:12]}"
        try:
            defenseclaw = self.defenseclaw.inspect(
                check,
                trace_id=trace_id,
                session_id=session_id,
                agent_name=self.agent_name,
            )
        except DefenseClawUnavailableError as exc:
            if not self.fail_open:
                return PolicyDecision(
                    False,
                    f"DefenseClaw inspection failed closed: {exc}",
                    ("defenseclaw-unavailable",),
                    evaluation_location="defenseclaw",
                    bundle_version=_bundle_version(controls),
                    defenseclaw_action="error",
                    defenseclaw_reason=str(exc),
                    action="deny",
                )
            defenseclaw = DefenseClawVerdict(
                action="allow",
                reason=f"DefenseClaw unavailable; fail-open configured: {exc}",
            )

        if defenseclaw.action in {"block", "confirm", "ask"}:
            requires_approval = defenseclaw.action in {"confirm", "ask"}
            verb = "requires confirmation for" if requires_approval else "blocked"
            names = tuple(f"defenseclaw:{finding}" for finding in defenseclaw.findings)
            return PolicyDecision(
                False,
                f"DefenseClaw {verb} the operation: {defenseclaw.reason}",
                names or ("defenseclaw",),
                evaluation_location="defenseclaw",
                bundle_version=_bundle_version(controls),
                defenseclaw_action=defenseclaw.action,
                defenseclaw_reason=defenseclaw.reason,
                defenseclaw_findings=defenseclaw.findings,
                action="deny",
            )

        result = _run_sync(
            self.sdk.evaluate_controls(
                check.step_name,
                input=check.input,
                context={
                    "hook_event": check.hook_event,
                    "client_name": check.client_name,
                    "security_gateway": "defenseclaw",
                    "defenseclaw_action": defenseclaw.action,
                    "defenseclaw_severity": defenseclaw.severity,
                    "session_id": session_id,
                },
                step_type=check.step_type,
                stage="pre",
                agent_name=self.agent_name,
                trace_id=trace_id,
                span_id=span_id,
            )
        )

        errors = list(result.errors or [])
        matches = list(result.matches or [])
        blocking_matches = [
            match for match in matches if getattr(match, "action", None) in {"deny", "steer"}
        ]
        location = _evaluation_location(result, controls)
        version = _bundle_version(controls)

        if errors:
            return PolicyDecision(
                False,
                "Agent Control evaluation failed closed: "
                + "; ".join(_match_reason(match) for match in errors),
                tuple(_match_name(match) for match in errors),
                evaluation_location=location,
                bundle_version=version,
                defenseclaw_action=defenseclaw.action,
                defenseclaw_reason=defenseclaw.reason,
                defenseclaw_findings=defenseclaw.findings,
                action="deny",
            )

        if not result.is_safe or blocking_matches:
            deny_matches = [
                match for match in blocking_matches if getattr(match, "action", None) == "deny"
            ]
            steer_matches = [
                match for match in blocking_matches if getattr(match, "action", None) == "steer"
            ]
            selected = deny_matches or steer_matches or matches
            action = "deny" if deny_matches or not steer_matches else "steer"
            steering_context = (
                _steering_message(steer_matches[0]) if action == "steer" and steer_matches else None
            )
            details = "; ".join(_match_reason(match) for match in selected)
            reason = result.reason or details
            if result.reason and details and details not in result.reason:
                reason = f"{result.reason} Details: {details}"
            if action == "steer" and steering_context:
                reason = f"Agent Control steering required: {steering_context}"
            return PolicyDecision(
                False,
                reason or "Agent Control denied the operation.",
                tuple(_match_name(match) for match in selected),
                evaluation_location=location,
                bundle_version=version,
                defenseclaw_action=defenseclaw.action,
                defenseclaw_reason=defenseclaw.reason,
                defenseclaw_findings=defenseclaw.findings,
                action=action,
                steering_context=steering_context,
            )

        return PolicyDecision(
            True,
            result.reason or "No Agent Control policy denied the operation.",
            tuple(_match_name(match) for match in matches),
            evaluation_location=location,
            bundle_version=version,
            defenseclaw_action=defenseclaw.action,
            defenseclaw_reason=defenseclaw.reason,
            defenseclaw_findings=defenseclaw.findings,
        )

    def close(self) -> None:
        if self._closed:
            return
        self.sdk.shutdown()
        self._closed = True

    def __enter__(self) -> DefenseClawPolicyClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
