"""Plain-HTTP Agent Control management client; no Agent Control SDK dependency."""

from __future__ import annotations

from typing import Any

import httpx

from demo_config import DemoSettings


class AgentControlHttpError(RuntimeError):
    """Raised when Agent Control management calls fail or return invalid data."""


def _error_body(response: httpx.Response) -> str:
    body = response.text.strip().replace("\n", " ")
    return body[:600] if body else "no response body"


class AgentControlManagementClient:
    """Use Agent Control only as a policy catalog and target-binding control plane."""

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

    def __enter__(self) -> AgentControlManagementClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        headers.update(self.settings.api_key_headers)
        try:
            return self.client.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise AgentControlHttpError(f"Agent Control request failed: {exc}") from exc

    @staticmethod
    def _raise(response: httpx.Response, operation: str) -> None:
        if response.is_success:
            return
        raise AgentControlHttpError(
            f"{operation} failed with HTTP {response.status_code}: {_error_body(response)}"
        )

    def health(self) -> dict[str, Any]:
        response = self._request("GET", "/health")
        self._raise(response, "Agent Control health check")
        payload = response.json()
        if not isinstance(payload, dict):
            raise AgentControlHttpError("Agent Control health response was not an object.")
        return payload

    def register_agent(self, steps: list[dict[str, Any]]) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/api/v1/agents/initAgent",
            json={
                "agent": {
                    "agent_name": self.settings.agent_name,
                    "agent_description": (
                        "Agent Control-managed policies enforced by the DefenseClaw gateway"
                    ),
                    "agent_version": "1.0.0",
                },
                "steps": steps,
                "conflict_mode": "overwrite",
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
            },
        )
        self._raise(response, "Agent registration")
        payload = response.json()
        if not isinstance(payload, dict):
            raise AgentControlHttpError("Agent registration response was not an object.")
        return payload

    def find_control(self, name: str) -> dict[str, Any] | None:
        response = self._request(
            "GET", "/api/v1/controls", params={"name": name, "limit": 20}
        )
        self._raise(response, f"Read control {name}")
        payload = response.json()
        controls = payload.get("controls", []) if isinstance(payload, dict) else []
        return next(
            (
                item
                for item in controls
                if isinstance(item, dict) and str(item.get("name")) == name
            ),
            None,
        )

    def ensure_control(self, name: str, definition: dict[str, Any]) -> int:
        """Create a control or replace its definition when it already exists."""
        response = self._request(
            "PUT", "/api/v1/controls", json={"name": name, "data": definition}
        )
        if response.status_code != 409:
            self._raise(response, f"Create control {name}")
            return int(response.json()["control_id"])

        existing = self.find_control(name)
        if existing is None:
            raise AgentControlHttpError(f"Control {name!r} exists but could not be read.")
        control_id = int(existing["id"])
        response = self._request(
            "PUT",
            f"/api/v1/controls/{control_id}/data",
            json={"data": definition},
        )
        self._raise(response, f"Update control {name}")
        return control_id

    def delete_control(self, control_id: int, *, force: bool = False) -> None:
        response = self._request(
            "DELETE",
            f"/api/v1/controls/{control_id}",
            params={"force": str(force).lower()},
        )
        self._raise(response, "Delete control")

    def bind_control(self, control_id: int, *, enabled: bool = True) -> None:
        """Use a target binding as the authoritative per-target toggle."""
        response = self._request(
            "DELETE",
            f"/api/v1/agents/{self.settings.agent_name}/controls/{control_id}",
        )
        self._raise(response, "Remove legacy direct-agent association")
        response = self._request(
            "PUT",
            "/api/v1/control-bindings/by-key",
            json={
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
                "control_id": control_id,
                "enabled": enabled,
            },
        )
        self._raise(response, "Upsert target control binding")

    def set_binding_enabled(self, control_id: int, *, enabled: bool) -> None:
        response = self._request(
            "PUT",
            "/api/v1/control-bindings/by-key",
            json={
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
                "control_id": control_id,
                "enabled": enabled,
            },
        )
        self._raise(response, "Update target control binding")

    def list_effective_controls(self) -> list[dict[str, Any]]:
        """Fetch the enabled, target-resolved bundle used for translation."""
        response = self._request(
            "GET",
            f"/api/v1/agents/{self.settings.agent_name}/controls",
            params={
                "rendered_state": "rendered",
                "enabled_state": "enabled",
                "target_type": self.settings.target_type,
                "target_id": self.settings.target_id,
            },
        )
        self._raise(response, "Effective-control discovery")
        payload = response.json()
        controls = payload.get("controls") if isinstance(payload, dict) else None
        if not isinstance(controls, list) or not all(isinstance(item, dict) for item in controls):
            raise AgentControlHttpError(
                "Effective-control response did not contain an object list."
            )
        return controls
