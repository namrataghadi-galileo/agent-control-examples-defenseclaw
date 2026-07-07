"""Environment configuration for the no-SDK DefenseClaw example."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_AGENT_CONTROL_URL = "https://console.multitenant.galileocloud.io/api/agent-control"
DEFAULT_CONSOLE_URL = "https://console.multitenant.galileocloud.io"
DEFAULT_AGENT_NAME = "defenseclaw-no-sdk-demo"
CONTROL_PREFIX = "demo-no-sdk-"


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class DemoSettings:
    server_url: str
    api_key: str
    api_key_header: str
    agent_name: str
    target_type: str
    target_id: str
    console_url: str
    project_id: str | None
    timeout_seconds: float
    runtime_auth_mode: str
    control_cache_seconds: int
    fail_open: bool
    ingest_observability_events: bool

    @classmethod
    def from_env(cls) -> DemoSettings:
        api_key = os.environ.get("GALILEO_API_KEY") or os.environ.get(
            "AGENT_CONTROL_API_KEY", ""
        )
        settings = cls(
            server_url=os.environ.get("AGENT_CONTROL_URL", DEFAULT_AGENT_CONTROL_URL).rstrip("/"),
            api_key=api_key,
            api_key_header=os.environ.get(
                "AGENT_CONTROL_API_KEY_HEADER", "Galileo-API-Key"
            ),
            agent_name=os.environ.get("AGENT_CONTROL_AGENT_NAME", DEFAULT_AGENT_NAME),
            target_type=os.environ.get("AGENT_CONTROL_TARGET_TYPE", "log_stream"),
            target_id=os.environ.get("AGENT_CONTROL_TARGET_ID", ""),
            console_url=os.environ.get("GALILEO_CONSOLE_URL", DEFAULT_CONSOLE_URL).rstrip("/"),
            project_id=os.environ.get("GALILEO_PROJECT_ID"),
            timeout_seconds=float(os.environ.get("AGENT_CONTROL_TIMEOUT_SECONDS", "35")),
            runtime_auth_mode=os.environ.get(
                "AGENT_CONTROL_RUNTIME_AUTH_MODE", "jwt"
            ).strip().lower(),
            control_cache_seconds=int(
                os.environ.get("DEFENSECLAW_CONTROL_CACHE_SECONDS", "15")
            ),
            fail_open=_env_bool("DEFENSECLAW_FAILURE_MODE_OPEN", False),
            ingest_observability_events=_env_bool(
                "AGENT_CONTROL_INGEST_OBSERVABILITY_EVENTS", True
            ),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        missing: list[str] = []
        if not self.api_key:
            missing.append("GALILEO_API_KEY or AGENT_CONTROL_API_KEY")
        if not self.target_id:
            missing.append("AGENT_CONTROL_TARGET_ID")
        if missing:
            raise RuntimeError("Missing configuration: " + ", ".join(missing))
        if self.runtime_auth_mode not in {"jwt", "api-key"}:
            raise RuntimeError("AGENT_CONTROL_RUNTIME_AUTH_MODE must be 'jwt' or 'api-key'.")
        if self.control_cache_seconds < 0:
            raise RuntimeError("DEFENSECLAW_CONTROL_CACHE_SECONDS must be >= 0.")

    @property
    def api_key_headers(self) -> dict[str, str]:
        return {self.api_key_header: self.api_key}

    @property
    def cache_dir(self) -> Path:
        configured = os.environ.get("DEFENSECLAW_NO_SDK_CACHE_DIR")
        if configured:
            return Path(configured).expanduser()
        return Path.home() / ".cache" / "defenseclaw-no-sdk"

    @property
    def log_stream_url(self) -> str | None:
        if not self.project_id:
            return None
        return (
            f"{self.console_url}/multitenant/project/{self.project_id}"
            f"/log-streams/{self.target_id}"
        )
