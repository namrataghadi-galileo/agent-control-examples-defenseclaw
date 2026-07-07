#!/usr/bin/env python3
"""Create and bind the three advanced Agent Control controls for the SDK demo."""

from __future__ import annotations

import argparse
import asyncio
import os
from typing import Any

import httpx

from demo_config import (
    DEFAULT_AGENT_CONTROL_URL,
    resolve_agent_control_api_key,
    resolve_agent_control_api_key_header,
)

DEFAULT_SDK_AGENT_NAME = "defenseclaw-sdk-demo"


def _regex_condition(path: str, pattern: str) -> dict[str, Any]:
    return {
        "selector": {"path": path},
        "evaluator": {
            "name": "regex",
            "config": {"pattern": pattern, "flags": ["IGNORECASE"]},
        },
    }


def control_specs() -> list[tuple[str, dict[str, Any]]]:
    """Return the three advanced controls used after DefenseClaw allows an event."""
    terraform_plan = r"\bterraform\s+(?:-chdir=[^\s]+\s+)?plan\b"
    injection_language = (
        r"(?:ignore|disregard|override|bypass)[\s\S]{0,100}"
        r"(?:instruction|policy|prompt|rule)"
        r"|(?:earlier|previous|prior|hidden|initialization|system)[\s\S]{0,100}"
        r"(?:instruction|policy|prompt|rule)"
    )

    return [
        (
            "demo-steer-terraform-plan-review",
            {
                "description": ("Steer Terraform plan requests to configuration validation first."),
                "enabled": True,
                "execution": "sdk",
                "scope": {
                    "step_types": ["tool"],
                    "step_names": ["Bash", "shell", "exec_command"],
                    "stages": ["pre"],
                },
                "condition": _regex_condition("input.policy_text", terraform_plan),
                "action": {
                    "decision": "steer",
                    "steering_context": {
                        "message": (
                            "Before producing a Terraform plan, run terraform validate in the "
                            "same configuration directory, preserving any -chdir option, and "
                            "report whether the configuration is valid. Do not run terraform "
                            "plan in this step."
                        )
                    },
                },
                "tags": ["demo", "coding-agent", "terraform", "behavioral", "steer", "local"],
            },
        ),
        (
            "demo-deny-prompt-injection-remote-ml",
            {
                "description": (
                    "Deny prompt injection with hosted Luna after a local language prefilter."
                ),
                "enabled": True,
                "execution": "server",
                "scope": {
                    "step_types": ["llm"],
                    "step_names": ["agent.user_prompt"],
                    "stages": ["pre"],
                },
                "condition": {
                    "and": [
                        _regex_condition("input.policy_text", injection_language),
                        {
                            "selector": {"path": "input.policy_text"},
                            "evaluator": {
                                "name": "galileo.luna",
                                "config": {
                                    "scorer_label": "prompt_injection_luna",
                                    "operator": "gte",
                                    "threshold": 0.8,
                                    "timeout_ms": 30000,
                                },
                            },
                        },
                    ]
                },
                "action": {"decision": "deny"},
                "tags": [
                    "demo",
                    "coding-agent",
                    "prompt-injection",
                    "ml",
                    "deny",
                    "prefiltered",
                    "remote",
                ],
            },
        ),
        (
            "demo-deny-policy-control-tampering",
            {
                "description": (
                    "Deny remote API requests that attempt to delete Agent Control controls."
                ),
                "enabled": True,
                "execution": "sdk",
                "scope": {
                    "step_types": ["tool"],
                    "step_names": ["Bash", "shell", "exec_command"],
                    "stages": ["pre"],
                },
                "condition": _regex_condition(
                    "input.policy_text",
                    (
                        r"\bcurl\b[\s\S]{0,240}(?:-X|--request)\s*DELETE"
                        r"[\s\S]{0,320}/api/v1/controls/[A-Za-z0-9_-]+"
                    ),
                ),
                "action": {"decision": "deny"},
                "tags": [
                    "demo",
                    "coding-agent",
                    "tamper-protection",
                    "agent-control",
                    "deny",
                    "local",
                ],
            },
        ),
    ]


async def _ensure_agent(
    client: httpx.AsyncClient,
    *,
    agent_name: str,
    target_type: str | None,
    target_id: str | None,
) -> None:
    payload: dict[str, Any] = {
        "agent": {
            "agent_name": agent_name,
            "agent_description": "Claude Code DefenseClaw and Agent Control SDK demo",
        },
        "steps": [],
        "conflict_mode": "overwrite",
    }
    if target_type is not None and target_id is not None:
        payload["target_type"] = target_type
        payload["target_id"] = target_id
    response = await client.post("/api/v1/agents/initAgent", json=payload)
    response.raise_for_status()


async def _find_control(client: httpx.AsyncClient, name: str) -> dict[str, Any] | None:
    response = await client.get("/api/v1/controls", params={"name": name, "limit": 20})
    response.raise_for_status()
    for control in response.json().get("controls", []):
        if control.get("name") == name:
            return control
    return None


async def _ensure_control(client: httpx.AsyncClient, name: str, data: dict[str, Any]) -> int:
    response = await client.put("/api/v1/controls", json={"name": name, "data": data})
    if response.status_code != 409:
        response.raise_for_status()
        return int(response.json()["control_id"])

    existing = await _find_control(client, name)
    if existing is None:
        raise RuntimeError(f"Control {name!r} exists but could not be read back.")
    control_id = int(existing["id"])
    response = await client.put(f"/api/v1/controls/{control_id}/data", json={"data": data})
    response.raise_for_status()
    return control_id


async def _configure_control_assignment(
    client: httpx.AsyncClient,
    *,
    agent_name: str,
    control_id: int,
    target_type: str | None,
    target_id: str | None,
) -> None:
    """Use one attachment source so target-binding toggles are authoritative."""
    if target_type is None or target_id is None:
        response = await client.post(f"/api/v1/agents/{agent_name}/controls/{control_id}")
        if response.status_code != 409:
            response.raise_for_status()
        return

    # Older demo versions attached every control directly to the agent as
    # well as to the target. Effective controls are the union of attachment
    # sources, so a disabled target binding could not suppress that direct
    # attachment. This idempotent delete migrates those installations.
    response = await client.delete(f"/api/v1/agents/{agent_name}/controls/{control_id}")
    response.raise_for_status()

    response = await client.put(
        "/api/v1/control-bindings/by-key",
        json={
            "target_type": target_type,
            "target_id": target_id,
            "control_id": control_id,
            "enabled": True,
        },
    )
    response.raise_for_status()


async def ensure_controls(
    *,
    agent_name: str = DEFAULT_SDK_AGENT_NAME,
    server_url: str = DEFAULT_AGENT_CONTROL_URL,
    target_type: str | None = None,
    target_id: str | None = None,
) -> list[int]:
    """Create or update and assign the three advanced Agent Control controls."""
    if (target_type is None) != (target_id is None):
        raise ValueError("target_type and target_id must be supplied together.")

    api_key = resolve_agent_control_api_key()
    if not api_key:
        raise RuntimeError("Set GALILEO_API_KEY or AGENT_CONTROL_API_KEY before setup.")

    headers = {resolve_agent_control_api_key_header(): api_key}
    async with httpx.AsyncClient(
        base_url=server_url.rstrip("/"),
        headers=headers,
        timeout=60.0,
    ) as client:
        health = await client.get("/health")
        health.raise_for_status()
        await _ensure_agent(
            client,
            agent_name=agent_name,
            target_type=target_type,
            target_id=target_id,
        )

        control_ids: list[int] = []
        for name, definition in control_specs():
            control_id = await _ensure_control(client, name, definition)
            control_ids.append(control_id)

            await _configure_control_assignment(
                client,
                agent_name=agent_name,
                control_id=control_id,
                target_type=target_type,
                target_id=target_id,
            )

    return control_ids


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create the coding-agent demo controls.")
    parser.add_argument("--agent-name", default=DEFAULT_SDK_AGENT_NAME)
    parser.add_argument("--server-url", default=DEFAULT_AGENT_CONTROL_URL)
    parser.add_argument("--target-type", default=os.environ.get("AGENT_CONTROL_TARGET_TYPE"))
    parser.add_argument("--target-id", default=os.environ.get("AGENT_CONTROL_TARGET_ID"))
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    control_ids = await ensure_controls(
        agent_name=args.agent_name,
        server_url=args.server_url,
        target_type=args.target_type,
        target_id=args.target_id,
    )
    for (name, _), control_id in zip(control_specs(), control_ids, strict=True):
        print(f"Prepared control: {name} ({control_id})")


if __name__ == "__main__":
    asyncio.run(main())
