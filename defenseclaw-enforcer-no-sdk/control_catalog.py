"""Ten Agent Control-managed policies understood by DefenseClaw."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

CONTROL_PREFIX = "dc-managed-"
LOCAL_CONTROL_TAG = "defenseclaw-local-rule"
REMOTE_CONTROL_TAG = "defenseclaw-ai-defense-rule"

REGISTERED_STEPS: list[dict[str, Any]] = [
    {"type": "llm", "name": "agent.user_prompt", "input_schema": {"type": "object"}},
    *[
        {"type": "tool", "name": name, "input_schema": {"type": "object"}}
        for name in ("Bash", "shell", "exec_command", "Write", "Edit")
    ],
]


@dataclass(frozen=True)
class ManagedPolicy:
    """Translation metadata for one UI-managed control."""

    name: str
    kind: Literal["local", "remote"]
    title: str
    description: str
    rule_id: str | None = None
    category: str | None = None
    pattern: str | None = None
    severity: str = "CRITICAL"
    confidence: float = 0.95
    tags: tuple[str, ...] = ()
    remote_rule: str | None = None

    @property
    def execution(self) -> str:
        return "sdk" if self.kind == "local" else "server"

    def control_definition(self) -> dict[str, Any]:
        """Return a valid Agent Control definition used only as policy configuration."""
        pattern = self.pattern if self.kind == "local" else r"\b\B"
        runtime_tag = LOCAL_CONTROL_TAG if self.kind == "local" else REMOTE_CONTROL_TAG
        tags = ["defenseclaw", runtime_tag, *self.tags]
        if self.rule_id:
            tags.append(f"defenseclaw-rule-id:{self.rule_id}")
        if self.remote_rule:
            tags.append(f"ai-defense-rule:{self.remote_rule}")
        return {
            "description": self.description,
            "enabled": True,
            "execution": self.execution,
            "scope": {"step_types": ["llm", "tool"], "stages": ["pre"]},
            "condition": {
                "selector": {"path": "input.policy_text"},
                "evaluator": {
                    "name": "regex",
                    "config": {"pattern": pattern, "flags": []},
                },
            },
            "action": {"decision": "deny"},
            "tags": tags,
        }


POLICIES: tuple[ManagedPolicy, ...] = (
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}curl-pipe-shell",
        kind="local",
        rule_id="CMD-PIPE-CURL",
        category="command",
        pattern=r"(?i)\bcurl\b\s+[^|]*\|\s*(?:[/\w]+/)?(?:bash|zsh|sh)\b",
        title="curl piped to shell",
        description="Block curl output piped directly to a shell.",
        confidence=0.95,
        tags=("execution", "download-exec"),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}bash-reverse-shell",
        kind="local",
        rule_id="CMD-REVSHELL-BASH",
        category="command",
        pattern=r"(?i)bash\s+-i\s+>&\s*/dev/tcp/",
        title="Bash reverse shell",
        description="Block Bash interactive reverse-shell syntax.",
        confidence=0.98,
        tags=("execution", "reverse-shell"),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}recursive-root-delete",
        kind="local",
        rule_id="CMD-RM-RF",
        category="command",
        pattern=(
            r"(?i)\brm\s+(?:-[a-zA-Z]*\s+)*(?:-[a-zA-Z]*)?(?:r[a-zA-Z]*f|"
            r"f[a-zA-Z]*r)\b(?:\s+\S+)*\s+/(?:$|[\"'\s,}\]]|(?:etc|bin|sbin|usr|"
            r"var|home|root|opt|boot|lib(?:64)?|srv|mnt|dev|proc|sys)(?:$|/|[\"'\s,}\]]))"
        ),
        title="Recursive force delete from critical root path",
        description="Block recursive force deletion of critical root paths.",
        confidence=0.95,
        tags=("destructive",),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}aws-credentials-path",
        kind="local",
        rule_id="PATH-AWS-CREDS",
        category="sensitive-path",
        pattern=r"(?:~|\$\{?HOME\}?|/home/\w+|/root|/Users/\w+)/\.aws/credentials",
        title="AWS credentials file",
        description="Block access to the AWS shared credentials file.",
        confidence=0.98,
        tags=("credential", "file-sensitive"),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}ssh-private-key-path",
        kind="local",
        rule_id="PATH-SSH-KEY",
        category="sensitive-path",
        pattern=r"(?i)(?:^|[\\/])id_(?:rsa|ed25519|ecdsa|dsa)(?:$|[^A-Za-z0-9_.-])",
        title="SSH private key file path",
        description="Block access to common SSH private-key file names.",
        confidence=0.90,
        tags=("credential", "file-sensitive"),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}aws-metadata-endpoint",
        kind="local",
        rule_id="C2-METADATA-AWS",
        category="c2",
        pattern=r"169\.254\.169\.254",
        title="AWS metadata endpoint",
        description="Block requests targeting the cloud metadata endpoint.",
        confidence=0.95,
        tags=("ssrf", "credential"),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}ignore-previous-instructions",
        kind="local",
        rule_id="TRUST-IGNORE-PREVIOUS",
        category="trust-exploit",
        pattern=(
            r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+"
            r"(?:instructions|rules|guidelines|context)"
        ),
        title="Ignore previous instructions",
        description="Block direct attempts to discard earlier instructions.",
        confidence=0.90,
        tags=("prompt-injection",),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}safety-override",
        kind="local",
        rule_id="TRUST-SAFETY-OVERRIDE",
        category="trust-exploit",
        pattern=(
            r"(?i)(?:safety|guardrail|filter|restriction)\s+"
            r"(?:override|bypass|disable|turn\s+off|remove)"
        ),
        title="Safety override attempt",
        description="Block attempts to disable or bypass safety controls.",
        confidence=0.90,
        tags=("prompt-injection",),
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}aidefense-prompt-injection",
        kind="remote",
        title="Cisco AI Defense prompt-injection inspection",
        description=(
            "Enable the Prompt Injection rule in DefenseClaw's remote Cisco AI Defense scanner."
        ),
        tags=("remote", "prompt-injection"),
        remote_rule="Prompt Injection",
    ),
    ManagedPolicy(
        name=f"{CONTROL_PREFIX}aidefense-data-leakage",
        kind="remote",
        title="Cisco AI Defense data-leakage inspection",
        description=(
            "Enable the Data Leakage rule in DefenseClaw's remote Cisco AI Defense scanner."
        ),
        tags=("remote", "data-leakage"),
        remote_rule="Data Leakage",
    ),
)

POLICY_BY_NAME = {policy.name: policy for policy in POLICIES}
DEFAULT_DEFENSECLAW_CATEGORIES = (
    "secret",
    "command",
    "sensitive-path",
    "c2",
    "cognitive-file",
    "trust-exploit",
)

