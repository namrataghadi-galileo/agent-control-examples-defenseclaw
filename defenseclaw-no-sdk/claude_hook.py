#!/usr/bin/env python3
"""Claude Code hook: DefenseClaw local inspection, then Agent Control REST evaluation."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from demo_config import DemoSettings
from galileo_trace import start_hook_trace
from policy_models import PolicyCheck
from policy_runtime import DefenseClawNoSdkPolicyClient


def _string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _tool_input(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("tool_input", payload.get("input", {}))
    return value if isinstance(value, dict) else {"raw": value}


def policy_check_from_hook(payload: dict[str, Any]) -> PolicyCheck | None:
    hook_event = _string(payload.get("hook_event_name") or payload.get("event_name"))
    client_name = _string(payload.get("client_name") or payload.get("source") or "claude-code")
    if hook_event == "UserPromptSubmit":
        prompt = _string(payload.get("prompt") or payload.get("user_prompt"))
        return PolicyCheck(
            step_name="agent.user_prompt",
            step_type="llm",
            input={"text": prompt},
            hook_event=hook_event,
            client_name=client_name,
        )
    if hook_event != "PreToolUse":
        return None

    tool_name = _string(payload.get("tool_name") or payload.get("tool"))
    raw_input = _tool_input(payload)
    if tool_name in {"Bash", "shell", "exec_command"}:
        command = _string(raw_input.get("command") or raw_input.get("cmd") or raw_input.get("raw"))
        normalized = {"command": command, "raw_tool_input": raw_input}
    elif tool_name in {"Write", "Edit"}:
        content = _string(
            raw_input.get("content")
            or raw_input.get("new_string")
            or raw_input.get("patch")
            or raw_input.get("raw")
        )
        normalized = {
            "path": _string(raw_input.get("file_path") or raw_input.get("path")),
            "content": content,
            "raw_tool_input": raw_input,
        }
    else:
        normalized = dict(raw_input)
        normalized["tool_name"] = tool_name
    return PolicyCheck(
        step_name=tool_name,
        step_type="tool",
        input=normalized,
        hook_event=hook_event,
        client_name=client_name,
    )


def main() -> int:
    trace = None
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("Hook input must be a JSON object.")
        check = policy_check_from_hook(payload)
        if check is None:
            return 0
        settings = DemoSettings.from_env()
        trace = start_hook_trace(check, settings)
        with DefenseClawNoSdkPolicyClient(settings=settings) as policy:
            decision = policy.evaluate(
                check,
                trace_id=trace.trace_id if trace else None,
                span_id=trace.span_id if trace else None,
            )
    except Exception as exc:
        if trace:
            trace.finish(error=exc)
        if os.environ.get("DEFENSECLAW_FAILURE_MODE_OPEN", "").lower() in {"1", "true"}:
            print(
                f"No-SDK policy integration unavailable; fail-open configured: {exc}",
                file=sys.stderr,
            )
            return 0
        print(f"No-SDK policy integration failed closed: {exc}", file=sys.stderr)
        return 2

    if trace:
        trace.finish(decision=decision)
    if decision.allowed:
        return 0
    if decision.source == "defenseclaw":
        print(
            f"DefenseClaw blocked locally; Agent Control evaluation skipped: {decision.reason}",
            file=sys.stderr,
        )
    elif decision.action == "steer":
        print(
            "Agent Control server control blocked this attempt and supplied guidance: "
            f"{decision.steering_context or decision.reason}",
            file=sys.stderr,
        )
    else:
        print(
            f"Agent Control server control blocked this attempt: {decision.reason}",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
