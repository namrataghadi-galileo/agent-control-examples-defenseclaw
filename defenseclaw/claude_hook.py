#!/usr/bin/env python3
"""Claude Code hook bridge for DefenseClaw plus the Agent Control SDK.

The hook reads one lifecycle-event JSON object from stdin. It exits with code 2
when either policy layer denies the event, which blocks PreToolUse and
UserPromptSubmit in Claude Code.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from defenseclaw_runtime import DefenseClawPolicyClient
from galileo_hook_trace import start_hook_trace
from policy_models import PolicyCheck


def _string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _tool_input(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("tool_input", payload.get("input", {}))
    if isinstance(value, dict):
        return value
    return {"raw": value}


def policy_check_from_hook(payload: dict[str, Any]) -> PolicyCheck | None:
    """Normalize Claude Code hook payloads into Agent Control steps."""
    hook_event = _string(payload.get("hook_event_name") or payload.get("event_name"))
    client_name = _string(payload.get("client_name") or payload.get("source") or "coding-agent")

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


def _fail_open() -> bool:
    return os.environ.get("DEFENSECLAW_FAILURE_MODE_OPEN", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def main() -> int:
    hook_trace = None
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("Hook input must be a JSON object.")
        check = policy_check_from_hook(payload)
        if check is None:
            return 0
        hook_trace = start_hook_trace(check)
        with DefenseClawPolicyClient() as policy_client:
            decision = policy_client.evaluate(check)
    except Exception as exc:
        if hook_trace is not None:
            hook_trace.finish(error=exc)
        if _fail_open():
            print(
                f"DefenseClaw + Agent Control SDK unavailable; fail-open configured: {exc}",
                file=sys.stderr,
            )
            return 0
        print(
            "DefenseClaw + Agent Control SDK blocked the action because policy evaluation "
            f"failed: {exc}",
            file=sys.stderr,
        )
        return 2

    if hook_trace is not None:
        hook_trace.finish(decision=decision)
    if decision.allowed:
        return 0
    if decision.action == "steer":
        print(
            "Agent Control blocked this attempt and supplied corrective guidance: "
            f"{decision.steering_context or decision.reason}",
            file=sys.stderr,
        )
        return 2
    print(decision.reason, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
