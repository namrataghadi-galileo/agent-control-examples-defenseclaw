"""Agent Control-protected operations used by the Streamlit demo."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

import agent_control
from agent_control import control

AGENT_NAME = "openclaw-safety-demo"
AGENT_DESCRIPTION = (
    "OpenClaw-style safety demo for dangerous commands and high-value transfers"
)
SERVER_URL = os.getenv("AGENT_CONTROL_URL", "http://localhost:8000")
TRANSFER_LIMIT = 10_000.0

F = TypeVar("F", bound=Callable[..., Awaitable[dict[str, Any]]])


def protected_tool(name: str) -> Callable[[F], F]:
    """Mark an async function as a named tool and protect it with Agent Control."""

    def decorator(func: F) -> F:
        setattr(func, "tool_name", name)
        return cast(F, control(step_name=name)(func))

    return decorator


@protected_tool("execute_shell_command")
async def execute_shell_command(command: str) -> dict[str, Any]:
    """Simulate a shell-command tool without executing anything on the host."""
    return {
        "status": "simulated",
        "command": command,
        "message": "Command passed Agent Control. No real shell command was executed.",
    }


@protected_tool("transfer_funds")
async def transfer_funds(
    amount: float,
    recipient: str,
    purpose: str,
) -> dict[str, Any]:
    """Simulate a funds-transfer tool without moving real money."""
    return {
        "status": "completed",
        "transaction_id": f"DEMO-{uuid.uuid4().hex[:8].upper()}",
        "amount": amount,
        "recipient": recipient,
        "purpose": purpose,
        "message": "Simulated transfer completed. No real money was moved.",
    }


def initialize_agent() -> None:
    """Initialize the SDK and load controls associated with the demo agent."""
    agent_control.init(
        agent_name=AGENT_NAME,
        agent_description=AGENT_DESCRIPTION,
        agent_version="1.0.0",
        server_url=SERVER_URL,
        observability_enabled=True,
        policy_refresh_interval_seconds=15,
    )


def refresh_controls() -> list[dict[str, Any]]:
    """Refresh the agent's effective controls from the server."""
    return agent_control.refresh_controls() or []


def active_controls() -> list[dict[str, Any]]:
    """Return the controls currently cached by the SDK."""
    return agent_control.get_server_controls() or []


def parse_steering_context(context: str) -> dict[str, Any]:
    """Parse JSON steering guidance, falling back to a plain-text reason."""
    try:
        value = json.loads(context)
    except (json.JSONDecodeError, TypeError):
        return {"reason": context}
    return value if isinstance(value, dict) else {"reason": context}


def suggested_amount(context: str, fallback: float = TRANSFER_LIMIT) -> float:
    """Extract a positive numeric amount from a steering-context message."""
    data = parse_steering_context(context)
    for key in ("suggested_amount", "maximum_amount", "max_amount"):
        value = data.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return float(value)
    return fallback
