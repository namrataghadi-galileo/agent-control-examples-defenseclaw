"""DefenseClaw-first enforcement followed by server-only Agent Control REST evaluation."""

from __future__ import annotations

import sys
from typing import Protocol
from uuid import uuid4

from agent_control_http import AgentControlHttpError, AgentControlRestClient
from defenseclaw_gateway import (
    DefenseClawGatewayClient,
    DefenseClawUnavailableError,
    DefenseClawVerdict,
)
from demo_config import CONTROL_PREFIX, DemoSettings
from policy_models import EvaluationResult, PolicyCheck, PolicyDecision


class DefenseClawInspector(Protocol):
    def inspect(
        self,
        check: PolicyCheck,
        *,
        trace_id: str,
        session_id: str,
        agent_name: str,
    ) -> DefenseClawVerdict: ...


def _execution_reason(execution: object) -> str:
    name = str(getattr(execution, "control_name", "unknown-control"))
    detail = (
        getattr(execution, "error", None)
        or getattr(execution, "message", None)
        or getattr(execution, "action", None)
        or "matched"
    )
    return f"{name}: {detail}"


class DefenseClawNoSdkPolicyClient:
    """Keep local DefenseClaw safety, then evaluate Agent Control remotely."""

    def __init__(
        self,
        settings: DemoSettings | None = None,
        rest: AgentControlRestClient | None = None,
        defenseclaw: DefenseClawInspector | None = None,
        *,
        validate_controls: bool = True,
    ) -> None:
        self.settings = settings or DemoSettings.from_env()
        self.rest = rest or AgentControlRestClient(self.settings)
        self._owns_rest = rest is None
        self.defenseclaw = defenseclaw or DefenseClawGatewayClient()
        self._should_validate_controls = validate_controls
        self._controls_validated = False

    def _validate_server_controls(self) -> None:
        if self._controls_validated or not self._should_validate_controls:
            return
        controls = self.rest.list_effective_controls()
        demo_controls = [
            item for item in controls if str(item.get("name", "")).startswith(CONTROL_PREFIX)
        ]
        if not demo_controls:
            raise AgentControlHttpError(
                f"No enabled {CONTROL_PREFIX} controls resolved for this target. "
                "Run setup_controls.py first."
            )
        non_server = [
            str(item.get("name"))
            for item in demo_controls
            if not isinstance(item.get("control"), dict)
            or item["control"].get("execution") != "server"
        ]
        if non_server:
            raise AgentControlHttpError(
                "The no-SDK runtime cannot execute SDK-local controls. Change these to "
                "execution='server': " + ", ".join(non_server)
            )
        self._controls_validated = True

    def evaluate(
        self,
        check: PolicyCheck,
        *,
        trace_id: str | None = None,
        span_id: str | None = None,
    ) -> PolicyDecision:
        resolved_trace_id = trace_id or uuid4().hex
        resolved_span_id = span_id or uuid4().hex[:16]
        session_id = f"no-sdk-{resolved_trace_id.replace('-', '')[:12]}"

        try:
            dc = self.defenseclaw.inspect(
                check,
                trace_id=resolved_trace_id,
                session_id=session_id,
                agent_name=self.settings.agent_name,
            )
        except DefenseClawUnavailableError as exc:
            if not self.settings.fail_open:
                return PolicyDecision(
                    allowed=False,
                    action="deny",
                    reason=f"DefenseClaw inspection failed closed: {exc}",
                    source="defenseclaw",
                    control_names=("defenseclaw-unavailable",),
                    defenseclaw_action="error",
                    agent_control_called=False,
                    trace_id=resolved_trace_id,
                    span_id=resolved_span_id,
                )
            dc = DefenseClawVerdict(
                action="allow", reason=f"DefenseClaw unavailable; fail-open configured: {exc}"
            )

        if dc.action in {"block", "confirm", "ask"}:
            verb = "requires confirmation" if dc.action in {"confirm", "ask"} else "blocked"
            return PolicyDecision(
                allowed=False,
                action="deny",
                reason=f"DefenseClaw {verb} this event locally: {dc.reason}",
                source="defenseclaw",
                control_names=tuple(f"defenseclaw:{item}" for item in dc.findings)
                or ("defenseclaw",),
                defenseclaw_action=dc.action,
                defenseclaw_findings=dc.findings,
                agent_control_called=False,
                trace_id=resolved_trace_id,
                span_id=resolved_span_id,
            )

        # Control discovery is intentionally lazy. A DefenseClaw-local block
        # above performs no Agent Control request at all.
        self._validate_server_controls()
        evaluation = self.rest.evaluate(
            check,
            trace_id=resolved_trace_id,
            span_id=resolved_span_id,
            session_id=session_id,
            defenseclaw_action=dc.action,
            defenseclaw_severity=dc.severity,
        )
        try:
            self.rest.ingest_control_events(
                check,
                evaluation,
                trace_id=resolved_trace_id,
                span_id=resolved_span_id,
            )
        except AgentControlHttpError as exc:
            # Telemetry is deliberately non-authoritative; enforcement still uses
            # the successfully returned evaluation result.
            print(f"Agent Control observability upload failed: {exc}", file=sys.stderr)

        if evaluation.errors:
            return self._server_decision(
                check,
                evaluation,
                allowed=False,
                action="deny",
                reason="Agent Control evaluation failed closed: "
                + "; ".join(_execution_reason(item) for item in evaluation.errors),
                selected=evaluation.errors,
                dc=dc,
                trace_id=resolved_trace_id,
                span_id=resolved_span_id,
            )

        deny = tuple(item for item in evaluation.matches if item.action == "deny")
        steer = tuple(item for item in evaluation.matches if item.action == "steer")
        if deny:
            details = "; ".join(_execution_reason(item) for item in deny)
            return self._server_decision(
                check,
                evaluation,
                allowed=False,
                action="deny",
                reason=evaluation.reason or details or "Agent Control denied the event.",
                selected=deny,
                dc=dc,
                trace_id=resolved_trace_id,
                span_id=resolved_span_id,
            )
        if steer:
            guidance = next(
                (item.steering_message for item in steer if item.steering_message),
                evaluation.reason or "Choose a safer action before retrying.",
            )
            return self._server_decision(
                check,
                evaluation,
                allowed=False,
                action="steer",
                reason=f"Agent Control steering required: {guidance}",
                selected=steer,
                dc=dc,
                trace_id=resolved_trace_id,
                span_id=resolved_span_id,
                steering_context=guidance,
            )
        if not evaluation.is_safe:
            return self._server_decision(
                check,
                evaluation,
                allowed=False,
                action="deny",
                reason=evaluation.reason or "Agent Control returned an unsafe decision.",
                selected=evaluation.matches,
                dc=dc,
                trace_id=resolved_trace_id,
                span_id=resolved_span_id,
            )
        return self._server_decision(
            check,
            evaluation,
            allowed=True,
            action="allow",
            reason=evaluation.reason or "No server-side Agent Control control denied the event.",
            selected=evaluation.matches,
            dc=dc,
            trace_id=resolved_trace_id,
            span_id=resolved_span_id,
        )

    def _server_decision(
        self,
        check: PolicyCheck,
        evaluation: EvaluationResult,
        *,
        allowed: bool,
        action: str,
        reason: str,
        selected: tuple[object, ...],
        dc: DefenseClawVerdict,
        trace_id: str,
        span_id: str,
        steering_context: str | None = None,
    ) -> PolicyDecision:
        del check
        return PolicyDecision(
            allowed=allowed,
            action=action,
            reason=reason,
            source="agent-control-server",
            control_names=tuple(str(getattr(item, "control_name")) for item in selected),
            steering_context=steering_context,
            defenseclaw_action=dc.action,
            defenseclaw_findings=dc.findings,
            agent_control_called=True,
            evaluation=evaluation,
            trace_id=trace_id,
            span_id=span_id,
        )

    def close(self) -> None:
        if self._owns_rest:
            self.rest.close()

    def __enter__(self) -> DefenseClawNoSdkPolicyClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
