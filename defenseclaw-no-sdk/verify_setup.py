#!/usr/bin/env python3
"""Verify both enforcement layers without executing a tool or policy evaluator."""

from __future__ import annotations

from agent_control_http import AgentControlRestClient
from control_definitions import control_specs
from defenseclaw_gateway import DefenseClawGatewayClient
from demo_config import CONTROL_PREFIX, DemoSettings


def main() -> None:
    settings = DemoSettings.from_env()
    defenseclaw = DefenseClawGatewayClient()
    health = defenseclaw.health()

    with AgentControlRestClient(settings) as client:
        client.health()
        controls = client.list_effective_controls(refresh=True)
        if settings.runtime_auth_mode == "jwt":
            client.exchange_runtime_token(force=True)

    expected = {name for name, _ in control_specs()}
    demo_controls = [control for control in controls if str(control.get("name")) in expected]
    observed = {str(control.get("name")) for control in demo_controls}
    missing = sorted(expected - observed)
    if missing:
        raise RuntimeError("Missing enabled server controls: " + ", ".join(missing))
    non_server = [
        str(control.get("name"))
        for control in demo_controls
        if not isinstance(control.get("control"), dict)
        or control["control"].get("execution") != "server"
    ]
    if non_server:
        raise RuntimeError("Controls are not server-executed: " + ", ".join(non_server))
    print(f"DefenseClaw gateway: healthy ({health.get('status', 'ok')})")
    print(f"Agent Control agent: {settings.agent_name}")
    print(f"Agent Control target: {settings.target_type}:{settings.target_id}")
    print(f"Effective advanced {CONTROL_PREFIX} controls: {len(demo_controls)}")
    for control in demo_controls:
        definition = control.get("control")
        execution = definition.get("execution") if isinstance(definition, dict) else "unknown"
        print(f"  {control.get('name')} execution={execution}")
    print("Agent Control SDK imported: no")


if __name__ == "__main__":
    main()
