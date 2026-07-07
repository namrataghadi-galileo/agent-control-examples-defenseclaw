#!/usr/bin/env python3
"""Launch Claude Code through DefenseClaw with fail-safe demo executables."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import httpx

from demo_config import DemoSettings
from policy_translator import current_bundle_digest

ROOT = Path(__file__).resolve().parent


def _without_management_credentials(
    environment: dict[str, str], *, cisco_api_key_env: str
) -> dict[str, str]:
    """Keep control-plane and remote-scanner secrets out of the agent process."""
    sanitized = dict(environment)
    for name in {
        "GALILEO_API_KEY",
        "AGENT_CONTROL_API_KEY",
        cisco_api_key_env,
    }:
        sanitized.pop(name, None)
    return sanitized


def main() -> None:
    executable = shutil.which("claude")
    if executable is None:
        raise SystemExit("'claude' is not installed or not on PATH.")
    if importlib.util.find_spec("agent_control") is not None:
        raise SystemExit(
            "agent-control-sdk is installed in this environment; recreate .venv with uv sync."
        )

    settings = DemoSettings.from_env(require_api_key=False)
    if current_bundle_digest(settings.rule_pack_dir) is None:
        raise SystemExit("No generated DefenseClaw bundle. Run sync_controls.py first.")
    try:
        response = httpx.get(f"{settings.defenseclaw_url}/health", timeout=2.0)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise SystemExit(f"DefenseClaw gateway is not healthy: {exc}") from exc

    environment = _without_management_credentials(
        dict(os.environ), cisco_api_key_env=settings.cisco_api_key_env
    )
    environment.update(
        {
            "PATH": f"{ROOT / 'demo_bin'}{os.pathsep}{environment.get('PATH', '')}",
            "DEFENSECLAW_CONNECTOR": "claudecode",
            "DEFENSECLAW_URL": settings.defenseclaw_url,
        }
    )
    print("Launching Claude Code with:", flush=True)
    print("  Sole enforcement point: DefenseClaw gateway", flush=True)
    print("  Local policy source: Agent Control-translated rule pack", flush=True)
    print("  Remote findings: Cisco AI Defense through DefenseClaw", flush=True)
    print("  Agent Control runtime /evaluation calls: none", flush=True)
    print("  Agent Control SDK: not installed", flush=True)
    print("  Destructive demo commands: fail-safe simulators", flush=True)
    os.chdir(ROOT)
    os.execvpe(executable, [executable, *sys.argv[1:]], environment)


if __name__ == "__main__":
    main()
