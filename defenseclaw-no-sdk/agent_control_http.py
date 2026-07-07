"""Direct Agent Control REST client with no dependency on agent-control-sdk."""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from demo_config import DemoSettings
from policy_models import ControlExecution, EvaluationResult, PolicyCheck


class AgentControlHttpError(RuntimeError):
    """Raised for transport, authentication, or response-contract failures."""


def _parse_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _safe_error_body(response: httpx.Response) -> str:
    text = response.text.strip().replace("\n", " ")
    return text[:600] if text else "no response body"


def _parse_execution(item: object) -> ControlExecution:
    if not isinstance(item, dict):
        raise AgentControlHttpError("Agent Control returned a non-object control result.")
    result = item.get("result")
    if not isinstance(result, dict):
        raise AgentControlHttpError("Agent Control control result is missing 'result'.")
    steering = item.get("steering_context")
    steering_message = steering.get("message") if isinstance(steering, dict) else None
    metadata = result.get("metadata")
    return ControlExecution(
        control_execution_id=str(item.get("control_execution_id") or ""),
        control_id=int(item["control_id"]),
        control_name=str(item["control_name"]),
        action=str(item["action"]),
        matched=bool(result.get("matched", False)),
        confidence=float(result.get("confidence", 0.0)),
        message=str(result["message"]) if result.get("message") is not None else None,
        error=str(result["error"]) if result.get("error") is not None else None,
        steering_message=str(steering_message) if steering_message else None,
        metadata=dict(metadata) if isinstance(metadata, dict) else {},
    )


def parse_evaluation_response(payload: object) -> EvaluationResult:
    if not isinstance(payload, dict):
        raise AgentControlHttpError("Agent Control evaluation response was not an object.")
    try:
        is_safe = bool(payload["is_safe"])
        confidence = float(payload["confidence"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AgentControlHttpError(
            "Agent Control evaluation response is missing decision fields."
        ) from exc

    def executions(name: str) -> tuple[ControlExecution, ...]:
        value = payload.get(name) or []
        if not isinstance(value, list):
            raise AgentControlHttpError(f"Agent Control response field {name!r} was not a list.")
        return tuple(_parse_execution(item) for item in value)

    reason = payload.get("reason")
    return EvaluationResult(
        is_safe=is_safe,
        confidence=confidence,
        reason=str(reason) if reason is not None else None,
        matches=executions("matches"),
        errors=executions("errors"),
        non_matches=executions("non_matches"),
        raw=dict(payload),
    )


class JsonFileCache:
    """Small cross-process cache used by short-lived Claude hook processes."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> dict[str, Any] | None:
        try:
            payload = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True))
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


class AgentControlRestClient:
    """Implement the Agent Control runtime contract with plain HTTP calls."""

    def __init__(
        self,
        settings: DemoSettings,
        client: httpx.Client | None = None,
    ) -> None:
        self.settings = settings
        self._owns_client = client is None
        self.client = client or httpx.Client(
            base_url=settings.server_url,
            timeout=settings.timeout_seconds,
            headers={"Accept": "application/json"},
        )
        cache_key = hashlib.sha256(
            f"{settings.server_url}|{settings.target_type}|{settings.target_id}".encode()
        ).hexdigest()[:16]
        self._token_cache = JsonFileCache(settings.cache_dir / f"runtime-token-{cache_key}.json")
        self._controls_cache = JsonFileCache(
            settings.cache_dir / f"effective-controls-{cache_key}.json"
        )

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> AgentControlRestClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _raise_for_status(self, response: httpx.Response, operation: str) -> None:
        if response.is_success:
            return
        raise AgentControlHttpError(
            f"{operation} failed with HTTP {response.status_code}: {_safe_error_body(response)}"
        )

    def health(self) -> dict[str, Any]:
        try:
            response = self.client.get("/health")
        except httpx.HTTPError as exc:
            raise AgentControlHttpError(f"Agent Control health request failed: {exc}") from exc
        self._raise_for_status(response, "Agent Control health request")
        payload = response.json()
        if not isinstance(payload, dict):
            raise AgentControlHttpError("Agent Control health response was not an object.")
        return payload

    def management_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        headers.update(self.settings.api_key_headers)
        try:
            return self.client.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise AgentControlHttpError(f"Agent Control management request failed: {exc}") from exc

    def register_agent(self, steps: list[dict[str, Any]]) -> dict[str, Any]:
        response = self.management_request(
            "POST",
            "/api/v1/agents/initAgent",
            json={
                "agent": {
                    "agent_name": self.settings.agent_name,
                    "agent_description": (
                        "Claude Code protected by DefenseClaw and server-only Agent Control"
                    ),
                    "agent_version": "1.0.0",
                },
                "steps": steps,
                "conflict_mode": "overwrite",
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
            },
        )
        self._raise_for_status(response, "Agent registration")
        payload = response.json()
        if not isinstance(payload, dict):
            raise AgentControlHttpError("Agent registration response was not an object.")
        return payload

    def list_effective_controls(self, *, refresh: bool = False) -> list[dict[str, Any]]:
        if not refresh and self.settings.control_cache_seconds > 0:
            cached = self._controls_cache.read()
            cache_age = time.time() - float((cached or {}).get("cached_at", 0))
            if cached and cache_age < self.settings.control_cache_seconds:
                controls = cached.get("controls")
                if isinstance(controls, list) and all(isinstance(item, dict) for item in controls):
                    return controls

        response = self.management_request(
            "GET",
            f"/api/v1/agents/{self.settings.agent_name}/controls",
            params={
                "rendered_state": "rendered",
                "enabled_state": "enabled",
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
            },
        )
        self._raise_for_status(response, "Effective-control discovery")
        payload = response.json()
        controls = payload.get("controls") if isinstance(payload, dict) else None
        if not isinstance(controls, list) or not all(isinstance(item, dict) for item in controls):
            raise AgentControlHttpError(
                "Effective-control response did not contain a control list."
            )
        self._controls_cache.write({"cached_at": time.time(), "controls": controls})
        return controls

    def _cached_runtime_token(self) -> str | None:
        payload = self._token_cache.read()
        if not payload:
            return None
        if payload.get("target_type") != self.settings.target_type:
            return None
        if payload.get("target_id") != self.settings.target_id:
            return None
        token = payload.get("token")
        expires_at = payload.get("expires_at")
        if not isinstance(token, str) or not isinstance(expires_at, str):
            return None
        try:
            expiry = _parse_datetime(expires_at)
        except ValueError:
            return None
        if expiry <= datetime.now(UTC) + timedelta(seconds=30):
            return None
        return token

    def exchange_runtime_token(self, *, force: bool = False) -> str:
        if not force and (cached := self._cached_runtime_token()):
            return cached
        response = self.management_request(
            "POST",
            "/api/v1/auth/runtime-token-exchange",
            json={
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
            },
        )
        self._raise_for_status(response, "Runtime-token exchange")
        payload = response.json()
        if not isinstance(payload, dict):
            raise AgentControlHttpError("Runtime-token response was not an object.")
        token = payload.get("token")
        expires_at = payload.get("expires_at")
        if not isinstance(token, str) or not isinstance(expires_at, str):
            raise AgentControlHttpError("Runtime-token response omitted token or expiry.")
        self._token_cache.write(
            {
                "token": token,
                "expires_at": expires_at,
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
            }
        )
        return token

    def _runtime_headers(self, *, force_refresh: bool = False) -> dict[str, str]:
        if self.settings.runtime_auth_mode == "api-key":
            return self.settings.api_key_headers
        return {"Authorization": f"Bearer {self.exchange_runtime_token(force=force_refresh)}"}

    def evaluate(
        self,
        check: PolicyCheck,
        *,
        trace_id: str,
        span_id: str,
        session_id: str,
        defenseclaw_action: str,
        defenseclaw_severity: str,
    ) -> EvaluationResult:
        step: dict[str, Any] = {
            "type": check.step_type,
            "name": check.step_name,
            "input": check.input,
            "context": {
                "hook_event": check.hook_event,
                "client_name": check.client_name,
                "security_gateway": "defenseclaw",
                "defenseclaw_action": defenseclaw_action,
                "defenseclaw_severity": defenseclaw_severity,
                "session_id": session_id,
                "trace_id": trace_id,
                "span_id": span_id,
            },
        }
        if check.output is not None:
            step["output"] = check.output
        payload = {
            "agent_name": self.settings.agent_name,
            "stage": check.stage,
            "target_type": self.settings.target_type,
            "target_id": self.settings.target_id,
            "step": step,
        }

        for attempt in range(2):
            try:
                response = self.client.post(
                    "/api/v1/evaluation",
                    headers=self._runtime_headers(force_refresh=attempt == 1),
                    json=payload,
                )
            except httpx.HTTPError as exc:
                raise AgentControlHttpError(
                    f"Agent Control evaluation request failed: {exc}"
                ) from exc
            if response.status_code not in {401, 403} or self.settings.runtime_auth_mode != "jwt":
                break
            self._token_cache.clear()
        self._raise_for_status(response, "Agent Control evaluation")
        try:
            return parse_evaluation_response(response.json())
        except ValueError as exc:
            raise AgentControlHttpError("Agent Control evaluation returned invalid JSON.") from exc

    def ingest_control_events(
        self,
        check: PolicyCheck,
        evaluation: EvaluationResult,
        *,
        trace_id: str,
        span_id: str,
    ) -> int:
        """Reconstruct the events normally emitted by the Agent Control SDK."""
        if not self.settings.ingest_observability_events:
            return 0
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        applies_to = "tool_call" if check.step_type == "tool" else "llm_call"
        events: list[dict[str, Any]] = []
        for execution in evaluation.all_executions:
            metadata = dict(execution.metadata)
            metadata.update(
                {
                    "hook_event": check.hook_event,
                    "client_name": check.client_name,
                    "target_type": self.settings.target_type,
                    "target_id": self.settings.target_id,
                    "integration": "defenseclaw-no-sdk",
                }
            )
            events.append(
                {
                    "control_execution_id": execution.control_execution_id,
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "agent_name": self.settings.agent_name,
                    "control_id": execution.control_id,
                    "control_name": execution.control_name,
                    "check_stage": check.stage,
                    "applies_to": applies_to,
                    "action": execution.action,
                    "matched": execution.matched,
                    "confidence": execution.confidence,
                    "timestamp": timestamp,
                    "error_message": execution.error,
                    "metadata": metadata,
                }
            )
        if not events:
            return 0
        response = self.management_request(
            "POST", "/api/v1/observability/events", json={"events": events}
        )
        self._raise_for_status(response, "Agent Control observability ingestion")
        return len(events)
