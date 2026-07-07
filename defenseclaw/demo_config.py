"""Environment configuration for the standalone DefenseClaw example."""

from __future__ import annotations

import os

DEFAULT_AGENT_CONTROL_URL = os.environ.get(
    "AGENT_CONTROL_URL",
    "https://console.multitenant.galileocloud.io/api/agent-control",
)
DEFAULT_CONSOLE_URL = os.environ.get(
    "GALILEO_CONSOLE_URL",
    "https://console.multitenant.galileocloud.io",
)
DEFAULT_API_URL = os.environ.get(
    "GALILEO_API_URL",
    "https://api.multitenant.galileocloud.io",
)
DEFAULT_PROJECT = os.environ.get("GALILEO_PROJECT", "defenseclaw-demo")
DEFAULT_LOG_STREAM = os.environ.get("GALILEO_LOG_STREAM", "defenseclaw-demo")


def resolve_agent_control_api_key() -> str | None:
    api_key = os.environ.get("GALILEO_API_KEY") or os.environ.get("AGENT_CONTROL_API_KEY")
    if api_key:
        os.environ["AGENT_CONTROL_API_KEY"] = api_key
    return api_key


def resolve_agent_control_api_key_header() -> str:
    header = os.environ.get("AGENT_CONTROL_API_KEY_HEADER", "Galileo-API-Key")
    os.environ["AGENT_CONTROL_API_KEY_HEADER"] = header
    return header
