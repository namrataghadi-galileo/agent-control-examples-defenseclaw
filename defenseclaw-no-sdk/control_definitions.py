"""Three advanced Agent Control definitions; every evaluator runs on the server."""

from __future__ import annotations

from typing import Any

from demo_config import CONTROL_PREFIX

REGISTERED_STEPS: list[dict[str, Any]] = [
    {"type": "llm", "name": "agent.user_prompt", "input_schema": {"type": "object"}},
    *[
        {"type": "tool", "name": name, "input_schema": {"type": "object"}}
        for name in (
            "Bash",
            "shell",
            "exec_command",
            "Write",
            "Edit",
            "aws.s3.request",
            "filesystem.delete",
        )
    ],
]


def _regex(path: str, pattern: str) -> dict[str, Any]:
    return {
        "selector": {"path": path},
        "evaluator": {
            "name": "regex",
            "config": {"pattern": pattern, "flags": ["IGNORECASE"]},
        },
    }


def control_specs() -> list[tuple[str, dict[str, Any]]]:
    terraform_plan = r"\bterraform\s+(?:-chdir=[^\s]+\s+)?plan\b"
    injection_language = (
        r"(?:ignore|disregard|override|bypass)[\s\S]{0,100}"
        r"(?:instruction|policy|prompt|rule)"
        r"|(?:earlier|previous|prior|hidden|initialization|system)[\s\S]{0,100}"
        r"(?:instruction|policy|prompt|rule)"
    )
    control_delete = (
        r"\bcurl\b[\s\S]{0,240}(?:-X|--request)\s*DELETE"
        r"[\s\S]{0,320}/api/v1/controls/[A-Za-z0-9_-]+"
    )

    return [
        (
            f"{CONTROL_PREFIX}steer-terraform-plan-review",
            {
                "description": "Require Terraform validation before producing a plan.",
                "enabled": True,
                "execution": "server",
                "scope": {
                    "step_types": ["tool"],
                    "step_names": ["Bash", "shell", "exec_command"],
                    "stages": ["pre"],
                },
                "condition": _regex("input.policy_text", terraform_plan),
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
                "tags": ["demo-no-sdk", "terraform", "behavioral", "steer", "server"],
            },
        ),
        (
            f"{CONTROL_PREFIX}deny-prompt-injection-luna",
            {
                "description": "Detect prompt injection with a regex prefilter and hosted Luna.",
                "enabled": True,
                "execution": "server",
                "scope": {
                    "step_types": ["llm"],
                    "step_names": ["agent.user_prompt"],
                    "stages": ["pre"],
                },
                "condition": {
                    "and": [
                        _regex("input.policy_text", injection_language),
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
                "tags": ["demo-no-sdk", "prompt-injection", "luna", "deny", "server"],
            },
        ),
        (
            f"{CONTROL_PREFIX}deny-control-tampering",
            {
                "description": "Deny remote API attempts to delete Agent Control controls.",
                "enabled": True,
                "execution": "server",
                "scope": {
                    "step_types": ["tool"],
                    "step_names": ["Bash", "shell", "exec_command"],
                    "stages": ["pre"],
                },
                "condition": _regex("input.policy_text", control_delete),
                "action": {"decision": "deny"},
                "tags": ["demo-no-sdk", "tamper-protection", "deny", "server"],
            },
        ),
    ]
