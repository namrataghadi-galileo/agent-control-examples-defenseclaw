#!/usr/bin/env python3
"""Create and target-bind the ten DefenseClaw-managed controls."""

from __future__ import annotations

from agent_control_client import AgentControlManagementClient
from control_catalog import POLICIES, REGISTERED_STEPS
from demo_config import DemoSettings


def main() -> None:
    settings = DemoSettings.from_env()
    prepared: list[tuple[str, int, str]] = []
    with AgentControlManagementClient(settings) as client:
        client.health()
        client.register_agent(REGISTERED_STEPS)
        for policy in POLICIES:
            control_id = client.ensure_control(policy.name, policy.control_definition())
            client.bind_control(control_id, enabled=True)
            prepared.append((policy.name, control_id, policy.execution))

        effective = client.list_effective_controls()

    effective_names = {str(control.get("name")) for control in effective}
    missing = [name for name, _, _ in prepared if name not in effective_names]
    if missing:
        raise RuntimeError("Controls were created but are not effective: " + ", ".join(missing))

    print(f"Registered Agent Control agent: {settings.agent_name}")
    print(f"Target: {settings.target_type}:{settings.target_id}")
    for name, control_id, execution in prepared:
        print(f"  {name} id={control_id} execution={execution}")
    print("Prepared 8 DefenseClaw-local controls and 2 Cisco AI Defense remote controls.")
    print("Agent Control SDK used: no")


if __name__ == "__main__":
    main()

