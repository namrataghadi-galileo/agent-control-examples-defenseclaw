#!/usr/bin/env python3
"""Launch Claude Code with safe DefenseClaw demo isolation."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent
BEDROCK_PROFILE_OPT_IN = "DEMO_ALLOW_BEDROCK_AWS_PROFILE"


def _enabled(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _claude_user_environment() -> dict[str, str]:
    """Read only Claude's configured environment keys, never logging values."""
    settings_path = Path.home() / ".claude" / "settings.json"
    try:
        payload: Any = json.loads(settings_path.read_text())
    except (OSError, ValueError):
        return {}
    configured = payload.get("env") if isinstance(payload, dict) else None
    if not isinstance(configured, dict):
        return {}
    return {str(key): str(value) for key, value in configured.items()}


def _sanitize_aws_environment(
    environment: dict[str, str],
    *,
    keep_bedrock_api_key: bool,
    allow_bedrock_profile: bool,
) -> dict[str, str]:
    """Remove general AWS credentials while retaining explicitly safe Bedrock inputs."""
    allowed = {"AWS_REGION", "AWS_DEFAULT_REGION"}
    if keep_bedrock_api_key:
        # Amazon Bedrock API keys authorize Bedrock, not general AWS services.
        allowed.add("AWS_BEARER_TOKEN_BEDROCK")
    if allow_bedrock_profile:
        # Profile credentials are an explicit opt-in and require an IAM/SCP S3 deny.
        allowed.add("AWS_PROFILE")
    return {
        name: value
        for name, value in environment.items()
        if not name.startswith("AWS_") or name in allowed
    }


def main() -> None:
    executable = shutil.which("claude")
    if executable is None:
        raise SystemExit("'claude' is not installed or not on PATH.")

    required = [
        "AGENT_CONTROL_URL",
        "AGENT_CONTROL_AGENT_NAME",
        "AGENT_CONTROL_TARGET_ID",
    ]
    missing = [name for name in required if not os.environ.get(name)]
    if not (os.environ.get("GALILEO_API_KEY") or os.environ.get("AGENT_CONTROL_API_KEY")):
        missing.append("GALILEO_API_KEY or AGENT_CONTROL_API_KEY")
    if missing:
        raise SystemExit(f"Missing required environment variables: {', '.join(missing)}")

    expected_configs = [ROOT / ".claude" / "settings.json"]
    missing_configs = [
        str(path.relative_to(ROOT)) for path in expected_configs if not path.exists()
    ]
    if missing_configs:
        raise SystemExit(
            "Install the demo client configuration first; missing: " + ", ".join(missing_configs)
        )

    environment = dict(os.environ)
    claude_environment = _claude_user_environment()
    bedrock_enabled = _enabled(
        environment.get("CLAUDE_CODE_USE_BEDROCK")
        or claude_environment.get("CLAUDE_CODE_USE_BEDROCK")
    )
    bedrock_api_key = bool(
        environment.get("AWS_BEARER_TOKEN_BEDROCK")
        or claude_environment.get("AWS_BEARER_TOKEN_BEDROCK")
    )
    allow_bedrock_profile = bedrock_enabled and _enabled(environment.get(BEDROCK_PROFILE_OPT_IN))
    if bedrock_enabled and not bedrock_api_key and not allow_bedrock_profile:
        raise SystemExit(
            "Claude Code is configured for Amazon Bedrock with general AWS profile "
            "credentials. This demo does not expose those credentials by default. "
            "Recommended: run plain 'claude', use /setup-bedrock, and select an Amazon "
            "Bedrock API key. If your organization requires an AWS profile, first attach "
            "an explicit s3:DeleteBucket IAM/SCP deny, then export "
            f"{BEDROCK_PROFILE_OPT_IN}=1 before launching."
        )

    environment = _sanitize_aws_environment(
        environment,
        keep_bedrock_api_key=bedrock_api_key,
        allow_bedrock_profile=allow_bedrock_profile,
    )
    environment.update(
        {
            "PATH": f"{ROOT / 'demo_bin'}{os.pathsep}{environment.get('PATH', '')}",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL_S3": "http://127.0.0.1:9",
            "DEFENSECLAW_FAILURE_MODE_OPEN": "false",
            "AGENT_CONTROL_TARGET_TYPE": environment.get("AGENT_CONTROL_TARGET_TYPE", "log_stream"),
            "AGENT_CONTROL_API_KEY_HEADER": environment.get(
                "AGENT_CONTROL_API_KEY_HEADER", "Galileo-API-Key"
            ),
            "AGENT_CONTROL_RUNTIME_AUTH_MODE": environment.get(
                "AGENT_CONTROL_RUNTIME_AUTH_MODE", "jwt"
            ),
            "DEFENSECLAW_POLICY_REFRESH_SECONDS": environment.get(
                "DEFENSECLAW_POLICY_REFRESH_SECONDS", "2"
            ),
            "DEFENSECLAW_URL": environment.get("DEFENSECLAW_URL", "http://127.0.0.1:18970"),
            "DEFENSECLAW_CONNECTOR": environment.get("DEFENSECLAW_CONNECTOR", "claudecode"),
            "DEFENSECLAW_GALILEO_HOOK_TRACING": environment.get(
                "DEFENSECLAW_GALILEO_HOOK_TRACING",
                "true" if environment.get("GALILEO_PROJECT_ID") else "false",
            ),
            "DEFENSECLAW_GALILEO_HOOK_EVENTS": environment.get(
                "DEFENSECLAW_GALILEO_HOOK_EVENTS",
                "UserPromptSubmit,PreToolUse",
            ),
        }
    )
    if not allow_bedrock_profile:
        environment.update(
            {
                "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                "AWS_CONFIG_FILE": "/dev/null",
            }
        )
    if not environment.get("AGENT_CONTROL_API_KEY") and environment.get("GALILEO_API_KEY"):
        environment["AGENT_CONTROL_API_KEY"] = environment["GALILEO_API_KEY"]

    try:
        response = httpx.get(
            f"{environment['DEFENSECLAW_URL'].rstrip('/')}/health",
            timeout=2.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise SystemExit(
            "DefenseClaw gateway is not healthy. Start it with "
            f"'defenseclaw-gateway start' before launching Claude Code: {exc}"
        ) from exc

    if bedrock_enabled:
        auth_mode = "Bedrock API key" if bedrock_api_key else "AWS profile with IAM/SCP deny"
        print(f"Claude authentication: {auth_mode}", flush=True)

    print("Launching Claude Code with:", flush=True)
    print("  DefenseClaw local enforcement: enabled", flush=True)
    print("  DefenseClaw demo rules: S3 and filesystem deletion", flush=True)
    print("  Agent Control transport: SDK", flush=True)
    print("  Agent Control advanced controls: Terraform, Luna, control tampering", flush=True)
    print("  AWS/filesystem/network demo executables: simulation only", flush=True)
    os.chdir(ROOT)
    os.execvpe(executable, [executable, *sys.argv[1:]], environment)


if __name__ == "__main__":
    main()
