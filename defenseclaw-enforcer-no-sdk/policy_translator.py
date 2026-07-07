"""Translate effective Agent Control definitions into a DefenseClaw rule pack."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from control_catalog import (
    CONTROL_PREFIX,
    DEFAULT_DEFENSECLAW_CATEGORIES,
    POLICIES,
    POLICY_BY_NAME,
    ManagedPolicy,
)

NEVER_MATCH_PATTERN = r"\b\B"


class TranslationError(RuntimeError):
    """Raised when an effective control cannot be safely compiled for DefenseClaw."""


@dataclass(frozen=True)
class TranslatedBundle:
    """One immutable policy snapshot ready to publish."""

    files: dict[str, str]
    digest: str
    enabled_control_names: tuple[str, ...]
    local_rule_ids: tuple[str, ...]
    remote_rules: tuple[str, ...]


def _definition(item: dict[str, Any]) -> dict[str, Any]:
    definition = item.get("control")
    if not isinstance(definition, dict):
        raise TranslationError(f"Control {item.get('name')!r} has no rendered definition.")
    return definition


def _regex_pattern(definition: dict[str, Any], name: str) -> str:
    condition = definition.get("condition")
    if not isinstance(condition, dict):
        raise TranslationError(f"Control {name!r} does not have a condition object.")
    evaluator = condition.get("evaluator")
    if not isinstance(evaluator, dict) or evaluator.get("name") != "regex":
        raise TranslationError(f"Control {name!r} must use a regex evaluator.")
    config = evaluator.get("config")
    if not isinstance(config, dict) or not isinstance(config.get("pattern"), str):
        raise TranslationError(f"Control {name!r} has no regex pattern.")

    flags = config.get("flags", [])
    if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
        raise TranslationError(f"Control {name!r} has invalid regex flags.")
    flag_map = {"IGNORECASE": "i", "MULTILINE": "m", "DOTALL": "s"}
    unknown = sorted(set(flags) - set(flag_map))
    if unknown:
        raise TranslationError(
            f"Control {name!r} uses flags DefenseClaw cannot translate: {unknown}"
        )
    prefix = "" if not flags else "(?" + "".join(flag_map[flag] for flag in flags) + ")"
    pattern = prefix + config["pattern"]
    if len(pattern) > 2048:
        raise TranslationError(f"Control {name!r} exceeds DefenseClaw's regex length limit.")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise TranslationError(f"Control {name!r} has an invalid regex: {exc}") from exc
    return pattern


def _validate_common(definition: dict[str, Any], policy: ManagedPolicy) -> None:
    if definition.get("execution") != policy.execution:
        raise TranslationError(
            f"Control {policy.name!r} must use execution={policy.execution!r}."
        )
    action = definition.get("action")
    if not isinstance(action, dict) or action.get("decision") != "deny":
        raise TranslationError(f"Control {policy.name!r} must use the deny action.")


def _sentinel(category: str) -> dict[str, Any]:
    return {
        "id": f"AC-DISABLED-{category.upper()}",
        "pattern": NEVER_MATCH_PATTERN,
        "title": "Agent Control disabled every managed rule in this category",
        "severity": "LOW",
        "confidence": 1.0,
        "tags": ["agent-control", "disabled-sentinel"],
    }


def _yaml(payload: object) -> str:
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def translate_effective_controls(controls: list[dict[str, Any]]) -> TranslatedBundle:
    """Compile a target-resolved control list into local and remote DefenseClaw inputs."""
    managed: dict[str, dict[str, Any]] = {}
    for item in controls:
        name = str(item.get("name", ""))
        if not name.startswith(CONTROL_PREFIX):
            continue
        if name not in POLICY_BY_NAME:
            raise TranslationError(f"Unknown managed control {name!r}; refusing partial policy.")
        if name in managed:
            raise TranslationError(f"Effective control response contains duplicate {name!r}.")
        definition = _definition(item)
        if definition.get("enabled", True):
            managed[name] = definition

    category_rules: dict[str, list[dict[str, Any]]] = {
        category: [] for category in DEFAULT_DEFENSECLAW_CATEGORIES
    }
    local_rule_ids: list[str] = []
    remote_rules: list[str] = []

    for policy in POLICIES:
        definition = managed.get(policy.name)
        if definition is None:
            continue
        _validate_common(definition, policy)
        if policy.kind == "remote":
            if not policy.remote_rule:
                raise TranslationError(f"Remote control {policy.name!r} has no scanner rule.")
            remote_rules.append(policy.remote_rule)
            continue

        if not policy.rule_id or not policy.category:
            raise TranslationError(f"Local control {policy.name!r} lacks rule metadata.")
        pattern = _regex_pattern(definition, policy.name)
        category_rules[policy.category].append(
            {
                "id": policy.rule_id,
                "pattern": pattern,
                "title": policy.title,
                "severity": policy.severity,
                "confidence": policy.confidence,
                "tags": ["agent-control-managed", *policy.tags],
            }
        )
        local_rule_ids.append(policy.rule_id)

    files: dict[str, str] = {}
    for category in DEFAULT_DEFENSECLAW_CATEGORIES:
        rules = category_rules[category] or [_sentinel(category)]
        files[f"rules/{category}.yaml"] = _yaml(
            {"version": 1, "category": category, "rules": rules}
        )

    # DefenseClaw otherwise retains compiled-in local pattern families. Explicitly
    # clear them so Agent Control is the source of truth for this managed pack.
    files["rules/local-patterns.yaml"] = _yaml(
        {
            "version": 1,
            "injection": [],
            "injection_regexes": [],
            "pii_requests": [],
            "pii_data_regexes": [],
            "secrets": [],
            "exfiltration": [],
        }
    )
    files["sensitive-tools.yaml"] = _yaml({"version": 1, "tools": []})
    files["suppressions.yaml"] = _yaml(
        {
            "version": 1,
            "pre_judge_strips": [],
            "finding_suppressions": [],
            "tool_suppressions": [],
        }
    )
    for judge in ("pii", "injection", "tool-injection", "exfil"):
        files[f"judge/{judge}.yaml"] = _yaml(
            {
                "version": 1,
                "name": judge,
                "enabled": False,
                "system_prompt": "",
                "categories": {},
            }
        )

    enabled_names = tuple(policy.name for policy in POLICIES if policy.name in managed)
    manifest = {
        "schema_version": 1,
        "enabled_control_names": enabled_names,
        "local_rule_ids": sorted(local_rule_ids),
        "remote_rules": sorted(remote_rules),
    }
    digest_input = json.dumps(
        {"manifest": manifest, "files": files}, sort_keys=True, separators=(",", ":")
    ).encode()
    digest = hashlib.sha256(digest_input).hexdigest()
    manifest["bundle_sha256"] = digest
    files["agent-control-manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    return TranslatedBundle(
        files=files,
        digest=digest,
        enabled_control_names=enabled_names,
        local_rule_ids=tuple(sorted(local_rule_ids)),
        remote_rules=tuple(sorted(remote_rules)),
    )


def current_bundle_digest(path: Path) -> str | None:
    try:
        payload = json.loads((path / "agent-control-manifest.json").read_text())
    except (OSError, ValueError):
        return None
    digest = payload.get("bundle_sha256") if isinstance(payload, dict) else None
    return str(digest) if digest else None


def publish_bundle(bundle: TranslatedBundle, destination: Path) -> None:
    """Publish all files before a gateway restart; retain the old pack on write failure."""
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.tmp"
    backup = destination.parent / f".{destination.name}.previous"
    shutil.rmtree(temporary, ignore_errors=True)
    temporary.mkdir(mode=0o700)
    try:
        for relative, content in bundle.files.items():
            path = temporary / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        shutil.rmtree(backup, ignore_errors=True)
        if destination.exists():
            destination.rename(backup)
        temporary.rename(destination)
    except Exception:
        if not destination.exists() and backup.exists():
            backup.rename(destination)
        raise
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    shutil.rmtree(backup, ignore_errors=True)

