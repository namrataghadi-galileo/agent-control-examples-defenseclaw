#!/usr/bin/env python3
"""Launch Claude Code with the no-SDK hook and simulation executables."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import httpx

from demo_config import DemoSettings

ROOT = Path(__file__).resolve().parent


def main() -> None:
    settings = DemoSettings.from_env()
    executable = shutil.which("claude")
    if executable is None:
        raise SystemExit("'claude' is not installed or is not on PATH.")
    if importlib.util.find_spec("agent_control") is not None:
        raise SystemExit(
            "agent-control-sdk is installed in this environment. Recreate this project's "
            ".venv with 'uv sync' so the no-SDK claim remains demonstrable."
        )
    hook = ROOT / ".claude" / "settings.json"
    if not hook.is_file():
        raise SystemExit(f"Missing Claude hook configuration: {hook}")

    defenseclaw_url = os.environ.get("DEFENSECLAW_URL", "http://127.0.0.1:18970").rstrip("/")
    try:
        response = httpx.get(f"{defenseclaw_url}/health", timeout=2.0)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise SystemExit(
            "DefenseClaw gateway is not healthy. Start it with "
            f"'defenseclaw-gateway start': {exc}"
        ) from exc

    environment = dict(os.environ)
    environment.update(
        {
            "PATH": f"{ROOT / 'demo_bin'}{os.pathsep}{environment.get('PATH', '')}",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL_S3": "http://127.0.0.1:9",
            "AGENT_CONTROL_AGENT_NAME": settings.agent_name,
            "AGENT_CONTROL_TARGET_TYPE": settings.target_type,
            "AGENT_CONTROL_RUNTIME_AUTH_MODE": settings.runtime_auth_mode,
            "DEFENSECLAW_URL": defenseclaw_url,
            "DEFENSECLAW_CONNECTOR": "claudecode",
            "DEFENSECLAW_GALILEO_HOOK_TRACING": environment.get(
                "DEFENSECLAW_GALILEO_HOOK_TRACING",
                "true" if settings.project_id else "false",
            ),
        }
    )
    if not environment.get("AGENT_CONTROL_API_KEY"):
        environment["AGENT_CONTROL_API_KEY"] = settings.api_key

    print("Launching Claude Code with:", flush=True)
    print("  DefenseClaw local enforcement: enabled", flush=True)
    print("  DefenseClaw demo rules: S3 and filesystem deletion", flush=True)
    print("  Agent Control transport: direct REST (no SDK)", flush=True)
    print("  Agent Control advanced controls: Terraform, Luna, control tampering", flush=True)
    print(f"  Agent Control target: {settings.target_type}:{settings.target_id}", flush=True)
    print("  AWS/filesystem/network demo executables: simulation only", flush=True)
    os.chdir(ROOT)
    os.execvpe(executable, [executable, *sys.argv[1:]], environment)


if __name__ == "__main__":
    main()
