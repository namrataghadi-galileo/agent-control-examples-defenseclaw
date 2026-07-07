#!/usr/bin/env python3
"""Verify control-plane discovery, translation, rule-pack state, and gateway health."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import httpx
import yaml

from agent_control_client import AgentControlManagementClient
from demo_config import DemoSettings
from policy_translator import current_bundle_digest, translate_effective_controls


def _resolved_path(value: object) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return Path(value).expanduser().resolve()


def _verify_defenseclaw_config(
    settings: DemoSettings, *, remote_rules: tuple[str, ...]
) -> tuple[Path | None, Path | None]:
    payload = yaml.safe_load(settings.defenseclaw_config_path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError("DefenseClaw config is not a YAML object.")
    guardrail = payload.get("guardrail")
    if not isinstance(guardrail, dict):
        raise RuntimeError("DefenseClaw config has no guardrail object.")
    connectors = guardrail.get("connectors")
    claude = connectors.get("claudecode") if isinstance(connectors, dict) else None
    remote = payload.get("cisco_ai_defense")

    expected = settings.rule_pack_dir.resolve()
    global_pack = _resolved_path(guardrail.get("rule_pack_dir"))
    claude_pack = (
        _resolved_path(claude.get("rule_pack_dir")) if isinstance(claude, dict) else None
    )
    configured_remote = remote.get("enabled_rules", []) if isinstance(remote, dict) else []
    expected_scanner_mode = "both" if remote_rules else "local"

    errors: list[str] = []
    if global_pack != expected:
        errors.append(f"global rule pack is {global_pack}, expected {expected}")
    if claude_pack != expected:
        errors.append(f"Claude rule pack is {claude_pack}, expected {expected}")
    if guardrail.get("mode") != "action":
        errors.append("guardrail.mode is not action")
    if guardrail.get("scanner_mode") != expected_scanner_mode:
        errors.append(
            f"guardrail.scanner_mode is not {expected_scanner_mode}"
        )
    if not isinstance(configured_remote, list) or not all(
        isinstance(rule, str) for rule in configured_remote
    ):
        errors.append("Cisco AI Defense enabled_rules is not a string list")
    elif sorted(configured_remote) != sorted(remote_rules):
        errors.append("Cisco AI Defense enabled_rules do not match the effective controls")
    if errors:
        raise RuntimeError(
            "DefenseClaw configuration is stale: "
            + "; ".join(errors)
            + ". Run sync_controls.py --once --apply-defenseclaw-config --restart-gateway."
        )
    return global_pack, claude_pack


def main() -> None:
    settings = DemoSettings.from_env()
    if importlib.util.find_spec("agent_control") is not None:
        raise RuntimeError("agent-control-sdk is installed; this example must remain SDK-free.")

    with AgentControlManagementClient(settings) as client:
        client.health()
        controls = client.list_effective_controls()
    bundle = translate_effective_controls(controls)

    response = httpx.get(f"{settings.defenseclaw_url}/health", timeout=2.0)
    response.raise_for_status()
    health = response.json()

    manifest_path = settings.rule_pack_dir / "agent-control-manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else None
    installed = current_bundle_digest(settings.rule_pack_dir)
    global_pack, claude_pack = _verify_defenseclaw_config(
        settings, remote_rules=bundle.remote_rules
    )

    print(f"DefenseClaw gateway: {health.get('status', 'healthy')}")
    print(f"Agent Control agent: {settings.agent_name}")
    print(f"Agent Control target: {settings.target_type}:{settings.target_id}")
    print(f"Enabled managed controls: {len(bundle.enabled_control_names)}")
    print(f"DefenseClaw-local rules: {list(bundle.local_rule_ids)}")
    print(f"Cisco AI Defense remote rules: {list(bundle.remote_rules)}")
    print(f"Expected bundle: {bundle.digest}")
    print(f"Installed bundle: {installed or 'missing'}")
    print(f"Manifest valid: {isinstance(manifest, dict)}")
    print(f"Global rule pack: {global_pack}")
    print(f"Claude rule pack: {claude_pack}")
    print("Agent Control runtime evaluation calls: 0")
    print("Agent Control SDK imported: no")
    if installed != bundle.digest:
        raise RuntimeError("Installed rule pack is stale; run sync_controls.py.")


if __name__ == "__main__":
    main()
