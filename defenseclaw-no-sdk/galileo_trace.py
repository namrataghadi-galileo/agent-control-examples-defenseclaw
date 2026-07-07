"""Direct Galileo traces and control spans without the Agent Control SDK bridge."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from uuid import UUID

from demo_config import DemoSettings
from policy_models import PolicyCheck, PolicyDecision


def _enabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _valid_uuid(value: str) -> str | None:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        return None


@dataclass
class GalileoHookTrace:
    logger: object
    trace_id: str
    span_id: str
    log_stream_url: str | None
    step_type: str
    stage: str

    def finish(
        self,
        decision: PolicyDecision | None = None,
        error: Exception | None = None,
    ) -> None:
        try:
            from galileo import ControlAppliesTo, ControlCheckStage, ControlResult

            if decision and decision.evaluation:
                for execution in decision.evaluation.all_executions:
                    kwargs = {
                        "input": execution.message or "Agent Control server evaluation",
                        "output": ControlResult(
                            action=execution.action,
                            matched=execution.matched,
                            confidence=execution.confidence,
                            error_message=execution.error,
                        ),
                        "name": execution.control_name,
                        "metadata": {
                            "control_execution_id": execution.control_execution_id,
                            "evaluation_location": "server",
                            "integration": "defenseclaw-no-sdk",
                        },
                        "tags": ["agent_control", "control", "no-sdk", "server"],
                        "status_code": 500 if execution.error else 200,
                        "control_id": execution.control_id,
                        "agent_name": os.environ.get(
                            "AGENT_CONTROL_AGENT_NAME", "defenseclaw-no-sdk-demo"
                        ),
                        "check_stage": ControlCheckStage(self.stage),
                        "applies_to": ControlAppliesTo(
                            "tool_call" if self.step_type == "tool" else "llm_call"
                        ),
                    }
                    if span_uuid := _valid_uuid(execution.control_execution_id):
                        kwargs["id"] = span_uuid
                    self.logger.add_control_span(**kwargs)

            if decision is not None:
                output = {
                    "decision": decision.action.upper(),
                    "source": decision.source,
                    "controls": list(decision.control_names),
                    "reason": decision.reason,
                    "agent_control_called": decision.agent_control_called,
                    "operation_allowed": decision.allowed,
                    "operation_executed": False,
                }
                status = 200
            else:
                output = {"decision": "ERROR", "error": str(error or "unknown error")}
                status = 500
            self.logger.conclude(output=output, status_code=status)
            self.logger.conclude(output=output, status_code=status)
            uploaded = self.logger.flush()
            print(f"Galileo trace ID: {self.trace_id}", file=sys.stderr)
            print(f"Galileo uploaded traces: {len(uploaded)}", file=sys.stderr)
            if self.log_stream_url:
                print(f"Galileo log stream: {self.log_stream_url}", file=sys.stderr)
        except Exception as exc:  # observability never changes policy enforcement
            print(f"Galileo tracing failed: {exc}", file=sys.stderr)


def start_hook_trace(check: PolicyCheck, settings: DemoSettings) -> GalileoHookTrace | None:
    if not _enabled(os.environ.get("DEFENSECLAW_GALILEO_HOOK_TRACING")):
        return None
    if not settings.project_id:
        print("Galileo tracing skipped: GALILEO_PROJECT_ID is not set.", file=sys.stderr)
        return None
    try:
        from galileo import GalileoLogger

        logger = GalileoLogger(project_id=settings.project_id, log_stream_id=settings.target_id)
        trace = logger.start_trace(
            input={
                "hook_event": check.hook_event,
                "step": check.step_name,
                "input": check.input,
            },
            name=f"Claude Code no-SDK policy hook: {check.hook_event}:{check.step_name}",
            metadata={
                "client": check.client_name,
                "agent_control_target_id": settings.target_id,
                "agent_control_sdk": False,
            },
            tags=["claude-code", "defenseclaw", "agent-control", "no-sdk"],
        )
        workflow = logger.add_workflow_span(
            input=str(check.input),
            name="DefenseClaw local + Agent Control server enforcement",
            metadata={"hook_event": check.hook_event, "step_name": check.step_name},
            tags=["security-policy", "no-sdk"],
        )
        return GalileoHookTrace(
            logger=logger,
            trace_id=str(trace.id),
            span_id=str(workflow.id),
            log_stream_url=settings.log_stream_url,
            step_type=check.step_type,
            stage=check.stage,
        )
    except Exception as exc:
        print(f"Galileo tracing could not start: {exc}", file=sys.stderr)
        return None
