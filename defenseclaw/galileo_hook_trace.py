"""Galileo tracing for Claude Code policy-hook evaluations."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from galileo import GalileoLogger

from policy_models import PolicyCheck, PolicyDecision


def _enabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _configured_events() -> set[str]:
    value = os.environ.get(
        "DEFENSECLAW_GALILEO_HOOK_EVENTS",
        "UserPromptSubmit,PreToolUse",
    )
    return {item.strip() for item in value.split(",") if item.strip()}


def _log_stream_url(project_id: str, log_stream_id: str) -> str | None:
    console_url = os.environ.get("GALILEO_CONSOLE_URL", "").rstrip("/")
    if not console_url:
        return None
    return f"{console_url}/multitenant/project/{project_id}/log-streams/{log_stream_id}"


@dataclass
class GalileoHookTrace:
    logger: GalileoLogger
    bridge: object
    trace_id: str
    project_id: str
    log_stream_id: str

    def finish(
        self,
        *,
        decision: PolicyDecision | None = None,
        error: Exception | None = None,
    ) -> None:
        """Conclude and flush without ever changing the enforcement decision."""
        try:
            if decision is not None:
                output = {
                    "decision": decision.action.upper(),
                    "controls": list(decision.control_names),
                    "reason": decision.reason,
                    "steering_context": decision.steering_context,
                    "defenseclaw_action": decision.defenseclaw_action,
                }
                status_code = 200
            else:
                output = {"decision": "ERROR", "error": str(error or "unknown error")}
                status_code = 500

            self.logger.conclude(output=output, status_code=status_code)
            self.logger.conclude(
                output={**output, "operation_executed": False},
                status_code=status_code,
            )
            uploaded = self.logger.flush()
            print(f"Galileo trace ID: {self.trace_id}", file=sys.stderr)
            print(f"Galileo uploaded traces: {len(uploaded)}", file=sys.stderr)
            if url := _log_stream_url(self.project_id, self.log_stream_id):
                print(f"Galileo log stream: {url}", file=sys.stderr)
        except Exception as exc:  # observability must not override policy enforcement
            print(f"Galileo hook tracing failed: {exc}", file=sys.stderr)
        finally:
            unregister = getattr(self.bridge, "unregister", None)
            if callable(unregister):
                unregister()


def start_hook_trace(check: PolicyCheck) -> GalileoHookTrace | None:
    """Start a real hook trace when opt-in configuration is complete."""
    if not _enabled(os.environ.get("DEFENSECLAW_GALILEO_HOOK_TRACING")):
        return None
    if check.hook_event not in _configured_events():
        return None

    project_id = os.environ.get("GALILEO_PROJECT_ID", "")
    log_stream_id = os.environ.get("AGENT_CONTROL_TARGET_ID", "")
    if not project_id or not log_stream_id or not os.environ.get("GALILEO_API_KEY"):
        print(
            "Galileo hook tracing skipped: set GALILEO_PROJECT_ID, "
            "AGENT_CONTROL_TARGET_ID, and GALILEO_API_KEY.",
            file=sys.stderr,
        )
        return None

    try:
        # Select Galileo's registered Agent Control bridge before SDK init.
        os.environ["DEFENSECLAW_AGENT_CONTROL_OBSERVABILITY_SINK"] = "registered"
        os.environ["DEFENSECLAW_AGENT_CONTROL_OBSERVABILITY"] = "true"

        logger = GalileoLogger(project_id=project_id, log_stream_id=log_stream_id)
        bridge = logger.enable_agent_control()
        trace = logger.start_trace(
            input={
                "hook_event": check.hook_event,
                "step": check.step_name,
                "input": check.input,
            },
            name=f"Claude Code policy hook: {check.hook_event}:{check.step_name}",
            metadata={
                "client": check.client_name,
                "agent_control_target_id": log_stream_id,
                "operation_executed": False,
            },
            tags=["claude-code", "defenseclaw", "agent-control", "policy-hook"],
        )
        logger.add_workflow_span(
            input=str(check.input),
            name="DefenseClaw + Agent Control enforcement",
            metadata={
                "hook_event": check.hook_event,
                "step_name": check.step_name,
            },
            tags=["security-policy", check.hook_event.lower()],
        )
        return GalileoHookTrace(
            logger=logger,
            bridge=bridge,
            trace_id=str(trace.id),
            project_id=project_id,
            log_stream_id=log_stream_id,
        )
    except Exception as exc:
        print(f"Galileo hook tracing could not start: {exc}", file=sys.stderr)
        return None
