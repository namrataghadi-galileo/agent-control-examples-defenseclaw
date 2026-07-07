#!/usr/bin/env python3
"""Small CRUD helper mirroring operations normally performed in Agent Control UI."""

from __future__ import annotations

import argparse

from agent_control_client import AgentControlManagementClient
from control_catalog import POLICIES, POLICY_BY_NAME
from demo_config import DemoSettings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect or change demo control bindings.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("list")
    for command in ("enable", "disable"):
        child = subcommands.add_parser(command)
        child.add_argument("name", choices=sorted(POLICY_BY_NAME))
    delete = subcommands.add_parser("delete")
    delete.add_argument("name", choices=sorted(POLICY_BY_NAME))
    delete.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = DemoSettings.from_env()
    with AgentControlManagementClient(settings) as client:
        if args.command == "list":
            effective = {str(item.get("name")) for item in client.list_effective_controls()}
            for policy in POLICIES:
                state = "enabled" if policy.name in effective else "disabled"
                print(f"{state:<8} {policy.execution:<6} {policy.name}")
            return

        control = client.find_control(args.name)
        if control is None:
            raise RuntimeError(f"Control {args.name!r} was not found; run setup_controls.py.")
        control_id = int(control["id"])
        if args.command == "delete":
            client.delete_control(control_id, force=args.force)
            print(f"Deleted {args.name}")
            return
        enabled = args.command == "enable"
        client.set_binding_enabled(control_id, enabled=enabled)
        print(f"Target binding {'enabled' if enabled else 'disabled'}: {args.name}")


if __name__ == "__main__":
    main()

