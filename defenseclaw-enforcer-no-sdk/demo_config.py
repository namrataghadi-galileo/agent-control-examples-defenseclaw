"""Environment configuration for the DefenseClaw-enforcer demo."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_AGENT_CONTROL_URL = "https://console.multitenant.galileocloud.io/api/agent-control"
DEFAULT_AGENT_NAME = "defenseclaw-enforcer-no-sdk"


@dataclass(frozen=True)
class DemoSettings:
    """Configuration shared by setup and the policy synchronizer."""

    server_url: str
    api_key: str
    api_key_header: str
    agent_name: str
    target_type: str
    target_id: str
    timeout_seconds: float
    refresh_seconds: float
    defenseclaw_url: str
    defenseclaw_home: Path
    rule_pack_dir: Path
    state_dir: Path
    cisco_endpoint: str
    cisco_api_key_env: str

    @classmethod
    def from_env(cls, *, require_api_key: bool = True) -> DemoSettings:
        root = Path(__file__).resolve().parent
        api_key = os.environ.get("GALILEO_API_KEY") or os.environ.get(
            "AGENT_CONTROL_API_KEY", ""
        )
        settings = cls(
            server_url=os.environ.get("AGENT_CONTROL_URL", DEFAULT_AGENT_CONTROL_URL).rstrip("/"),
            api_key=api_key,
            api_key_header=os.environ.get("AGENT_CONTROL_API_KEY_HEADER", "Galileo-API-Key"),
            agent_name=os.environ.get("AGENT_CONTROL_AGENT_NAME", DEFAULT_AGENT_NAME),
            target_type=os.environ.get("AGENT_CONTROL_TARGET_TYPE", "log_stream"),
            target_id=os.environ.get("AGENT_CONTROL_TARGET_ID", ""),
            timeout_seconds=float(os.environ.get("AGENT_CONTROL_TIMEOUT_SECONDS", "35")),
            refresh_seconds=float(os.environ.get("DEFENSECLAW_POLICY_REFRESH_SECONDS", "5")),
            defenseclaw_url=os.environ.get(
                "DEFENSECLAW_URL", "http://127.0.0.1:18970"
            ).rstrip("/"),
            defenseclaw_home=Path(
                os.path.expanduser(os.environ.get("DEFENSECLAW_HOME", "~/.defenseclaw"))
            ),
            rule_pack_dir=Path(
                os.environ.get("DEFENSECLAW_MANAGED_RULE_PACK", root / "generated-rule-pack")
            ).expanduser(),
            state_dir=Path(
                os.environ.get("DEFENSECLAW_ENFORCER_STATE_DIR", root / ".state")
            ).expanduser(),
            cisco_endpoint=os.environ.get(
                "CISCO_AI_DEFENSE_ENDPOINT",
                "https://us.api.inspect.aidefense.security.cisco.com",
            ),
            cisco_api_key_env=os.environ.get(
                "CISCO_AI_DEFENSE_API_KEY_ENV", "CISCO_AI_DEFENSE_API_KEY"
            ),
        )
        settings.validate(require_api_key=require_api_key)
        return settings

    def validate(self, *, require_api_key: bool) -> None:
        missing: list[str] = []
        if require_api_key and not self.api_key:
            missing.append("GALILEO_API_KEY or AGENT_CONTROL_API_KEY")
        if require_api_key and (
            not self.target_id or self.target_id == "replace-with-log-stream-uuid"
        ):
            missing.append("AGENT_CONTROL_TARGET_ID")
        if missing:
            raise RuntimeError("Missing configuration: " + ", ".join(missing))
        if self.refresh_seconds <= 0:
            raise RuntimeError("DEFENSECLAW_POLICY_REFRESH_SECONDS must be greater than zero.")

    @property
    def api_key_headers(self) -> dict[str, str]:
        return {self.api_key_header: self.api_key}

    @property
    def defenseclaw_config_path(self) -> Path:
        return self.defenseclaw_home / "config.yaml"

    @property
    def sync_state_path(self) -> Path:
        return self.state_dir / "sync-state.json"
