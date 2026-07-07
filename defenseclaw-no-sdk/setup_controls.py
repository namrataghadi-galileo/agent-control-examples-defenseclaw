#!/usr/bin/env python3
"""Create, update, and target-bind the three advanced server controls."""

from __future__ import annotations

import argparse
import os
from typing import Any

from agent_control_http import AgentControlHttpError, AgentControlRestClient
from control_definitions import REGISTERED_STEPS, control_specs
from demo_config import DemoSettings


def _find_control(client: AgentControlRestClient, name: str) -> dict[str, Any] | None:
    response = client.management_request(
        "GET", "/api/v1/controls", params={"name": name, "limit": 20}
    )
    client._raise_for_status(response, f"Read control {name}")
    payload = response.json()
    controls = payload.get("controls", []) if isinstance(payload, dict) else []
    return next(
        (item for item in controls if isinstance(item, dict) and item.get("name") == name),
        None,
    )


def _ensure_control(
    client: AgentControlRestClient,
    name: str,
    definition: dict[str, Any],
) -> int:
    response = client.management_request(
        "PUT", "/api/v1/controls", json={"name": name, "data": definition}
    )
    if response.status_code != 409:
        client._raise_for_status(response, f"Create control {name}")
        return int(response.json()["control_id"])

    existing = _find_control(client, name)
    if existing is None:
        raise AgentControlHttpError(f"Control {name!r} exists but could not be read back.")
    control_id = int(existing["id"])
    response = client.management_request(
        "PUT",
        f"/api/v1/controls/{control_id}/data",
        json={"data": definition},
    )
    client._raise_for_status(response, f"Update control {name}")
    return control_id


def _bind_control(client: AgentControlRestClient, control_id: int) -> None:
    # Remove a legacy direct-agent association so the target binding remains
    # the single authoritative enable/disable source.
    response = client.management_request(
        "DELETE",
        f"/api/v1/agents/{client.settings.agent_name}/controls/{control_id}",
    )
    client._raise_for_status(response, "Remove legacy direct control association")
    response = client.management_request(
        "PUT",
        "/api/v1/control-bindings/by-key",
        json={
            "target_type": client.settings.target_type,
            "target_id": client.settings.target_id,
            "control_id": control_id,
            "enabled": True,
        },
    )
    client._raise_for_status(response, "Create target control binding")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the three advanced server-only Agent Control controls."
    )
    parser.add_argument("--server-url", default=os.environ.get("AGENT_CONTROL_URL"))
    parser.add_argument("--agent-name", default=os.environ.get("AGENT_CONTROL_AGENT_NAME"))
    parser.add_argument("--target-type", default=os.environ.get("AGENT_CONTROL_TARGET_TYPE"))
    parser.add_argument("--target-id", default=os.environ.get("AGENT_CONTROL_TARGET_ID"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.server_url:
        os.environ["AGENT_CONTROL_URL"] = args.server_url
    if args.agent_name:
        os.environ["AGENT_CONTROL_AGENT_NAME"] = args.agent_name
    if args.target_type:
        os.environ["AGENT_CONTROL_TARGET_TYPE"] = args.target_type
    if args.target_id:
        os.environ["AGENT_CONTROL_TARGET_ID"] = args.target_id

    settings = DemoSettings.from_env()
    with AgentControlRestClient(settings) as client:
        client.health()
        client.register_agent(REGISTERED_STEPS)
        prepared: list[tuple[str, int]] = []
        for name, definition in control_specs():
            control_id = _ensure_control(client, name, definition)
            _bind_control(client, control_id)
            prepared.append((name, control_id))

        controls = client.list_effective_controls(refresh=True)
        expected_names = {name for name, _ in control_specs()}
        demo_controls = [item for item in controls if str(item.get("name")) in expected_names]
        observed_names = {str(item.get("name")) for item in demo_controls}
        missing = sorted(expected_names - observed_names)
        if missing:
            raise AgentControlHttpError(
                "Missing enabled advanced controls: " + ", ".join(missing)
            )
        non_server = [
            str(item.get("name"))
            for item in demo_controls
            if not isinstance(item.get("control"), dict)
            or item["control"].get("execution") != "server"
        ]
        if non_server:
            raise AgentControlHttpError(
                "These demo controls are not server-executed: " + ", ".join(non_server)
            )

    print(f"Registered agent: {settings.agent_name}")
    print(f"Target: {settings.target_type}:{settings.target_id}")
    for name, control_id in prepared:
        print(f"Prepared server control: {name} ({control_id})")
    print("DefenseClaw local rules: S3 deletion and filesystem deletion")
    print("Agent Control SDK used: no")


if __name__ == "__main__":
    main()
