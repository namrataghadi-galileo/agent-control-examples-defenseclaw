"""Register the demo agent and tool schemas without creating any controls."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from agent_control import Agent, AgentControlClient, agents

from demo_agent import AGENT_DESCRIPTION, AGENT_NAME, SERVER_URL

STEPS: list[dict[str, Any]] = [
    {
        "type": "tool",
        "name": "execute_shell_command",
        "description": "Simulate a shell command proposed by an autonomous agent",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The proposed shell command",
                }
            },
            "required": ["command"],
        },
        "output_schema": {"type": "object"},
    },
    {
        "type": "tool",
        "name": "transfer_funds",
        "description": "Simulate a transfer to a recipient",
        "input_schema": {
            "type": "object",
            "properties": {
                "amount": {"type": "number", "minimum": 0},
                "recipient": {"type": "string"},
                "purpose": {"type": "string"},
            },
            "required": ["amount", "recipient", "purpose"],
        },
        "output_schema": {"type": "object"},
    },
]


async def main() -> None:
    """Register the agent with the local Agent Control server."""
    agent = Agent(
        agent_name=AGENT_NAME,
        agent_description=AGENT_DESCRIPTION,
        agent_created_at=datetime.now(UTC).isoformat(),
        agent_version="1.0.0",
        agent_metadata={"demo": True, "framework": "streamlit"},
    )

    async with AgentControlClient(base_url=SERVER_URL) as client:
        response = await agents.register_agent(client, agent, steps=STEPS)

    state = "created" if response.get("created") else "updated"
    print(f"Agent {state}: {AGENT_NAME}")
    print(f"Server: {SERVER_URL}")
    print("Registered tools:")
    for step in STEPS:
        print(f"  - {step['name']}")
    print("\nNext: open the Agent Control UI and attach the controls in CONTROL_RECIPES.md.")


if __name__ == "__main__":
    asyncio.run(main())
