"""Apply translated policy state to DefenseClaw without storing secrets."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import time

import httpx
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from demo_config import DemoSettings


class DefenseClawConfigurationError(RuntimeError):
    """Raised when the local gateway configuration cannot be safely updated."""


def _mapping(parent: CommentedMap, name: str) -> CommentedMap:
    value = parent.get(name)
    if value is None:
        value = CommentedMap()
        parent[name] = value
    if not isinstance(value, CommentedMap):
        raise DefenseClawConfigurationError(f"DefenseClaw config field {name!r} is not a map.")
    return value


def apply_managed_configuration(
    settings: DemoSettings,
    *,
    remote_rules: tuple[str, ...],
) -> bool:
    """Set the managed pack and AI Defense rules while preserving unrelated YAML."""
    path = settings.defenseclaw_config_path
    if not path.is_file():
        raise DefenseClawConfigurationError(
            f"DefenseClaw config not found at {path}. Run defenseclaw quickstart first."
        )

    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    try:
        document = yaml.load(path.read_text())
    except Exception as exc:
        raise DefenseClawConfigurationError(f"Could not parse {path}: {exc}") from exc
    if not isinstance(document, CommentedMap):
        raise DefenseClawConfigurationError("DefenseClaw config root must be a YAML map.")

    guardrail = _mapping(document, "guardrail")
    guardrail["enabled"] = True
    guardrail["mode"] = "action"
    guardrail["scanner_mode"] = "both" if remote_rules else "local"
    guardrail["rule_pack_dir"] = str(settings.rule_pack_dir.resolve())

    # A connector-specific rule-pack path takes precedence over the global
    # guardrail.rule_pack_dir. Quickstart can leave such an override behind
    # from an earlier demo, so manage the Claude Code profile explicitly too.
    connectors = _mapping(guardrail, "connectors")
    claude_code = _mapping(connectors, "claudecode")
    claude_code["mode"] = "action"
    claude_code["hook_fail_mode"] = "closed"
    claude_code["rule_pack_dir"] = str(settings.rule_pack_dir.resolve())

    remote = _mapping(document, "cisco_ai_defense")
    remote["endpoint"] = settings.cisco_endpoint
    remote["api_key_env"] = settings.cisco_api_key_env
    remote["enabled_rules"] = list(remote_rules)
    remote["scan_hook_surface"] = True

    output = io.StringIO()
    yaml.dump(document, output)
    rendered = output.getvalue()
    previous = path.read_text()
    if rendered == previous:
        return False

    temporary = path.with_suffix(f"{path.suffix}.{os.getpid()}.tmp")
    temporary.write_text(rendered)
    os.chmod(temporary, path.stat().st_mode & 0o777)
    temporary.replace(path)
    return True


def restart_gateway(settings: DemoSettings) -> None:
    executable = os.environ.get("DEFENSECLAW_GATEWAY_BIN") or shutil.which(
        "defenseclaw-gateway"
    )
    if not executable:
        raise DefenseClawConfigurationError("defenseclaw-gateway is not on PATH.")
    completed = subprocess.run(
        [executable, "restart"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise DefenseClawConfigurationError(f"Gateway restart failed: {detail}")

    last_error = "gateway did not become healthy"
    for _ in range(20):
        try:
            response = httpx.get(f"{settings.defenseclaw_url}/health", timeout=1.0)
            response.raise_for_status()
            return
        except httpx.HTTPError as exc:
            last_error = str(exc)
            time.sleep(0.25)
    raise DefenseClawConfigurationError(
        f"Gateway restart completed but health failed: {last_error}"
    )
