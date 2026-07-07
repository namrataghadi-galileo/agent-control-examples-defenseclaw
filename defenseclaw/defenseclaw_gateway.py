"""Authenticated client for the real DefenseClaw gateway inspection API."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from policy_models import PolicyCheck


class DefenseClawUnavailableError(RuntimeError):
    """Raised when the DefenseClaw gateway cannot provide a usable verdict."""


@dataclass(frozen=True)
class DefenseClawVerdict:
    action: str
    reason: str
    severity: str = "NONE"
    findings: tuple[str, ...] = ()
    mode: str = "unknown"
    raw_action: str | None = None
    would_block: bool = False


def _read_dotenv_value(path: Path, key: str) -> str | None:
    try:
        content = path.read_text()
    except OSError:
        return None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        candidate, value = stripped.split("=", 1)
        if candidate.strip() == key:
            return value.strip().strip("'\"") or None
    return None


def _resolve_token(home: Path) -> str | None:
    for name in ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"):
        value = os.environ.get(name) or _read_dotenv_value(home / ".env", name)
        if value:
            return value
    return None


class DefenseClawGatewayClient:
    """Send normalized DefenseClaw events to the local gateway sidecar."""

    def __init__(self) -> None:
        self.url = os.environ.get("DEFENSECLAW_URL", "http://127.0.0.1:18970").rstrip("/")
        self.home = Path(os.path.expanduser(os.environ.get("DEFENSECLAW_HOME", "~/.defenseclaw")))
        self.token = _resolve_token(self.home)
        self.connector = os.environ.get("DEFENSECLAW_CONNECTOR", "").strip()
        self.timeout = float(os.environ.get("DEFENSECLAW_TIMEOUT_SECONDS", "3"))

    def _headers(self, *, trace_id: str, session_id: str, agent_name: str) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-DefenseClaw-Client": "defenseclaw-sdk-demo",
            "X-DefenseClaw-Agent-Id": agent_name,
            "X-DefenseClaw-Agent-Name": agent_name,
            "X-DefenseClaw-Session-Id": session_id,
            "X-DefenseClaw-Run-Id": session_id,
            "X-DefenseClaw-Trace-Id": trace_id,
        }
        if self.connector:
            headers["X-DefenseClaw-Connector"] = self.connector
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def health(self) -> dict[str, Any]:
        try:
            response = httpx.get(f"{self.url}/health", timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DefenseClawUnavailableError(str(exc)) from exc
        if not isinstance(payload, dict):
            raise DefenseClawUnavailableError("DefenseClaw health response was not an object.")
        return payload

    def _inspection_request(
        self,
        check: PolicyCheck,
        *,
        session_id: str,
        agent_name: str,
    ) -> tuple[str, dict[str, Any]]:
        """Build the connector-native hook request when one is available.

        DefenseClaw's generic inspection endpoints use the process-wide
        guardrail mode. Connector-native endpoints apply the connector's
        effective mode, including a Claude Code ``action`` override.
        """
        connector = self.connector.lower().replace("_", "-")
        native_endpoints = {
            "claude-code": "/api/v1/claude-code/hook",
            "claudecode": "/api/v1/claude-code/hook",
        }
        if connector in native_endpoints:
            payload: dict[str, Any] = {
                "hook_event_name": check.hook_event,
                "session_id": session_id,
                "agent_id": agent_name,
                "agent_name": agent_name,
                "agent_type": connector,
                "source": "defenseclaw-sdk-demo",
                "cwd": str(Path.cwd()),
            }
            if check.step_type == "llm":
                text = check.input.get("text")
                payload["prompt"] = (
                    text if isinstance(text, str) else json.dumps(check.input, sort_keys=True)
                )
            else:
                payload["tool_name"] = check.step_name
                payload["tool_input"] = check.input
            return native_endpoints[connector], payload

        if check.step_type == "llm":
            text = check.input.get("text")
            content = text if isinstance(text, str) else json.dumps(check.input, sort_keys=True)
            return "/api/v1/inspect/request", {
                "content": content,
                "session_id": session_id,
            }

        payload = {
            "tool": check.step_name,
            "args": check.input,
            "session_id": session_id,
        }
        if self.connector:
            payload["connector"] = self.connector
        return "/api/v1/inspect/tool", payload

    def inspect(
        self,
        check: PolicyCheck,
        *,
        trace_id: str,
        session_id: str,
        agent_name: str,
    ) -> DefenseClawVerdict:
        endpoint, payload = self._inspection_request(
            check,
            session_id=session_id,
            agent_name=agent_name,
        )

        try:
            response = httpx.post(
                f"{self.url}{endpoint}",
                headers=self._headers(
                    trace_id=trace_id,
                    session_id=session_id,
                    agent_name=agent_name,
                ),
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise DefenseClawUnavailableError(str(exc)) from exc

        if not isinstance(result, dict) or not isinstance(result.get("action"), str):
            raise DefenseClawUnavailableError("DefenseClaw returned an invalid inspection verdict.")
        findings = result.get("findings") or []
        return DefenseClawVerdict(
            action=result["action"].strip().lower(),
            raw_action=(str(result["raw_action"]) if result.get("raw_action") else None),
            severity=str(result.get("severity", "NONE")),
            reason=str(result.get("reason") or "No DefenseClaw finding."),
            findings=tuple(str(item) for item in findings),
            mode=str(result.get("mode", "unknown")),
            would_block=bool(result.get("would_block", False)),
        )
