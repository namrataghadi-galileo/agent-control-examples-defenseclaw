#!/usr/bin/env python3
"""Synchronize Agent Control policy state into the DefenseClaw enforcement runtime."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

from agent_control_client import AgentControlManagementClient
from defenseclaw_runtime_config import apply_managed_configuration, restart_gateway
from demo_config import DemoSettings
from policy_translator import (
    TranslatedBundle,
    current_bundle_digest,
    publish_bundle,
    translate_effective_controls,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pull effective Agent Control policies and install them into DefenseClaw."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Synchronize once (default).")
    mode.add_argument("--watch", action="store_true", help="Poll continuously for UI changes.")
    parser.add_argument(
        "--apply-defenseclaw-config",
        action="store_true",
        help="Manage rule_pack_dir, scanner_mode, and Cisco AI Defense enabled_rules.",
    )
    parser.add_argument(
        "--restart-gateway",
        action="store_true",
        help="Restart DefenseClaw whenever the effective bundle changes.",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def _write_state(settings: DemoSettings, bundle: TranslatedBundle) -> None:
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "bundle_sha256": bundle.digest,
        "synced_at": datetime.now(UTC).isoformat(),
        "enabled_control_names": bundle.enabled_control_names,
        "local_rule_ids": bundle.local_rule_ids,
        "remote_rules": bundle.remote_rules,
    }
    temporary = settings.sync_state_path.with_suffix(
        f"{settings.sync_state_path.suffix}.{os.getpid()}.tmp"
    )
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    temporary.replace(settings.sync_state_path)


def _activated_digest(settings: DemoSettings) -> str | None:
    try:
        payload = json.loads(settings.sync_state_path.read_text())
    except (OSError, ValueError):
        return None
    digest = payload.get("bundle_sha256") if isinstance(payload, dict) else None
    return str(digest) if digest else None


def synchronize_once(
    settings: DemoSettings,
    *,
    apply_config: bool,
    restart: bool,
    dry_run: bool,
    report_unchanged: bool = True,
) -> bool:
    with AgentControlManagementClient(settings) as client:
        controls = client.list_effective_controls()
    bundle = translate_effective_controls(controls)
    pack_changed = current_bundle_digest(settings.rule_pack_dir) != bundle.digest
    activation_pending = _activated_digest(settings) != bundle.digest

    if dry_run:
        _print_bundle_summary(bundle)
        print("Dry run: no rule pack, DefenseClaw config, or gateway state changed.")
        return pack_changed or activation_pending

    messages: list[str] = []
    if pack_changed:
        publish_bundle(bundle, settings.rule_pack_dir)
        messages.append(f"Published DefenseClaw rule pack: {settings.rule_pack_dir}")

    config_changed = False
    if apply_config:
        config_changed = apply_managed_configuration(
            settings, remote_rules=bundle.remote_rules
        )
        if config_changed:
            messages.append(f"Updated DefenseClaw config: {settings.defenseclaw_config_path}")

    changed = pack_changed or config_changed or activation_pending
    if changed or report_unchanged:
        _print_bundle_summary(bundle)
        for message in messages:
            print(message)
    if restart and changed:
        restart_gateway(settings)
        print("Restarted DefenseClaw gateway; the new bundle is active.")
        _write_state(settings, bundle)
    elif activation_pending:
        print("Bundle is published but not marked active; restart DefenseClaw before use.")
    return changed


def _print_bundle_summary(bundle: TranslatedBundle) -> None:
    print(
        f"Resolved {len(bundle.enabled_control_names)} managed controls: "
        f"local={len(bundle.local_rule_ids)} remote={len(bundle.remote_rules)}"
    )
    print(f"Bundle: {bundle.digest[:16]}")
    print(f"Remote AI Defense rules: {list(bundle.remote_rules) or 'none'}")


def main() -> int:
    args = parse_args()
    settings = DemoSettings.from_env()
    first_poll = True
    try:
        while True:
            try:
                synchronize_once(
                    settings,
                    apply_config=args.apply_defenseclaw_config,
                    restart=args.restart_gateway,
                    dry_run=args.dry_run,
                    report_unchanged=not args.watch or first_poll,
                )
                first_poll = False
            except Exception as exc:
                print(
                    f"Policy synchronization failed; last-known-good pack retained: {exc}",
                    file=sys.stderr,
                )
                if not args.watch:
                    return 1
            if not args.watch:
                return 0
            time.sleep(settings.refresh_seconds)
    except KeyboardInterrupt:
        print("\nPolicy watcher stopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
