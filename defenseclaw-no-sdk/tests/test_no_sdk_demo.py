from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any

import httpx
from yaml import safe_load

from agent_control_http import AgentControlRestClient, parse_evaluation_response
from claude_hook import policy_check_from_hook
from control_definitions import control_specs
from defenseclaw_gateway import DefenseClawVerdict
from demo_config import CONTROL_PREFIX, DemoSettings
from policy_models import PolicyCheck
from policy_runtime import DefenseClawNoSdkPolicyClient


def settings() -> DemoSettings:
    return DemoSettings(
        server_url="https://agent-control.test",
        api_key="test-key",
        api_key_header="Galileo-API-Key",
        agent_name="defenseclaw-no-sdk-demo",
        target_type="log_stream",
        target_id="stream-id",
        console_url="https://console.test",
        project_id="project-id",
        timeout_seconds=5,
        runtime_auth_mode="api-key",
        control_cache_seconds=0,
        fail_open=False,
        ingest_observability_events=False,
    )


def response(
    *,
    safe: bool,
    action: str | None = None,
    name: str = f"{CONTROL_PREFIX}test",
    guidance: str | None = None,
) -> Any:
    matches = []
    if action:
        matches.append(
            {
                "control_execution_id": "11111111-1111-4111-8111-111111111111",
                "control_id": 42,
                "control_name": name,
                "action": action,
                "result": {
                    "matched": True,
                    "confidence": 1.0,
                    "message": "matched",
                    "metadata": {},
                    "error": None,
                },
                "steering_context": {"message": guidance} if guidance else None,
            }
        )
    return parse_evaluation_response(
        {
            "is_safe": safe,
            "confidence": 1.0,
            "reason": None,
            "matches": matches,
            "errors": [],
            "non_matches": [],
        }
    )


class FakeRest:
    def __init__(self, evaluation: Any) -> None:
        self.evaluation = evaluation
        self.list_calls = 0
        self.evaluate_calls = 0
        self.events = 0

    def list_effective_controls(self) -> list[dict[str, Any]]:
        self.list_calls += 1
        return [
            {
                "id": 42,
                "name": f"{CONTROL_PREFIX}test",
                "control": {"execution": "server", "enabled": True},
            }
        ]

    def evaluate(self, *_: Any, **__: Any) -> Any:
        self.evaluate_calls += 1
        return self.evaluation

    def ingest_control_events(self, *_: Any, **__: Any) -> int:
        self.events += 1
        return 1

    def close(self) -> None:
        return None


class FakeDefenseClaw:
    def __init__(self, verdict: DefenseClawVerdict) -> None:
        self.verdict = verdict

    def inspect(self, *_: Any, **__: Any) -> DefenseClawVerdict:
        return self.verdict


class NoSdkRuntimeTests(unittest.TestCase):
    def check(self) -> PolicyCheck:
        return PolicyCheck(
            step_name="Bash",
            step_type="tool",
            input={"command": "echo safe"},
            hook_event="PreToolUse",
            client_name="claude-code",
        )

    def test_defenseclaw_s3_block_skips_agent_control(self) -> None:
        rest = FakeRest(response(safe=True))
        runtime = DefenseClawNoSdkPolicyClient(
            settings(),
            rest=rest,
            defenseclaw=FakeDefenseClaw(
                DefenseClawVerdict(
                    action="block",
                    reason="S3 bucket deletion",
                    findings=("DEMO-S3-DELETE-BUCKET",),
                )
            ),
        )
        decision = runtime.evaluate(self.check())
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "defenseclaw")
        self.assertFalse(decision.agent_control_called)
        self.assertEqual(rest.list_calls, 0)
        self.assertEqual(rest.evaluate_calls, 0)

    def test_defenseclaw_filesystem_block_skips_agent_control(self) -> None:
        rest = FakeRest(response(safe=True))
        runtime = DefenseClawNoSdkPolicyClient(
            settings(),
            rest=rest,
            defenseclaw=FakeDefenseClaw(
                DefenseClawVerdict(
                    action="block",
                    reason="Local filesystem deletion",
                    findings=("DEMO-FILESYSTEM-DELETE",),
                )
            ),
        )
        decision = runtime.evaluate(self.check())
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "defenseclaw")
        self.assertFalse(decision.agent_control_called)
        self.assertEqual(rest.list_calls, 0)
        self.assertEqual(rest.evaluate_calls, 0)

    def test_server_deny_is_enforced(self) -> None:
        rest = FakeRest(response(safe=False, action="deny"))
        runtime = DefenseClawNoSdkPolicyClient(
            settings(),
            rest=rest,
            defenseclaw=FakeDefenseClaw(DefenseClawVerdict("allow", "safe")),
        )
        decision = runtime.evaluate(self.check())
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.source, "agent-control-server")
        self.assertTrue(decision.agent_control_called)
        self.assertEqual(rest.evaluate_calls, 1)

    def test_defenseclaw_alert_continues_to_agent_control(self) -> None:
        rest = FakeRest(response(safe=True))
        runtime = DefenseClawNoSdkPolicyClient(
            settings(),
            rest=rest,
            defenseclaw=FakeDefenseClaw(
                DefenseClawVerdict(
                    action="alert",
                    reason="high severity signal",
                    findings=("C2-WEBHOOK-SITE",),
                )
            ),
        )
        decision = runtime.evaluate(self.check())
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.agent_control_called)
        self.assertEqual(rest.evaluate_calls, 1)

    def test_server_steer_returns_guidance(self) -> None:
        rest = FakeRest(response(safe=False, action="steer", guidance="validate first"))
        runtime = DefenseClawNoSdkPolicyClient(
            settings(),
            rest=rest,
            defenseclaw=FakeDefenseClaw(DefenseClawVerdict("allow", "safe")),
        )
        decision = runtime.evaluate(self.check())
        self.assertEqual(decision.action, "steer")
        self.assertEqual(decision.steering_context, "validate first")

    def test_safe_server_response_allows(self) -> None:
        rest = FakeRest(response(safe=True))
        runtime = DefenseClawNoSdkPolicyClient(
            settings(),
            rest=rest,
            defenseclaw=FakeDefenseClaw(DefenseClawVerdict("allow", "safe")),
        )
        decision = runtime.evaluate(self.check())
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.source, "agent-control-server")

    def test_all_three_advanced_controls_are_server_only_and_prefixed(self) -> None:
        specs = control_specs()
        self.assertEqual(len(specs), 3)
        for name, definition in specs:
            self.assertTrue(name.startswith(CONTROL_PREFIX))
            self.assertEqual(definition["execution"], "server")

    def test_hook_normalizes_bash_command(self) -> None:
        check = policy_check_from_hook(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "aws s3api delete-bucket --bucket demo"},
            }
        )
        self.assertIsNotNone(check)
        assert check is not None
        self.assertEqual(check.step_name, "Bash")
        self.assertIn("delete-bucket", check.input["policy_text"])


class DefenseClawRulePackTests(unittest.TestCase):
    def test_destructive_rules_are_valid_and_owned_by_defenseclaw(self) -> None:
        path = (
            Path(__file__).resolve().parents[1]
            / "defenseclaw_rule_pack"
            / "rules"
            / "demo-destructive-operations.yaml"
        )
        source = path.read_text()
        payload = safe_load(source)

        self.assertEqual(payload["category"], "demo-destructive-operations")
        self.assertEqual(
            {rule["id"] for rule in payload["rules"]},
            {"DEMO-S3-DELETE-BUCKET", "DEMO-FILESYSTEM-DELETE"},
        )
        compiled = {rule["id"]: re.compile(rule["pattern"]) for rule in payload["rules"]}
        for rule in payload["rules"]:
            self.assertEqual(rule["severity"], "CRITICAL")
            self.assertIsNone(compiled[rule["id"]].search(source))

        self.assertRegex(
            json.dumps({"command": "aws s3api delete-bucket --bucket demo"}),
            compiled["DEMO-S3-DELETE-BUCKET"],
        )
        self.assertRegex(
            json.dumps({"operation": "s3:DeleteBucket"}),
            compiled["DEMO-S3-DELETE-BUCKET"],
        )
        self.assertRegex(
            json.dumps({"command": "rm -rf ./demo-workspace/retired-build-cache"}),
            compiled["DEMO-FILESYSTEM-DELETE"],
        )
        documentation = "Documentation: aws s3api delete-bucket and rm -rf ./old"
        self.assertIsNone(compiled["DEMO-S3-DELETE-BUCKET"].search(documentation))
        self.assertIsNone(compiled["DEMO-FILESYSTEM-DELETE"].search(documentation))


class RestContractTests(unittest.TestCase):
    def test_evaluation_posts_target_bearing_payload_with_api_key(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/api/v1/evaluation":
                return httpx.Response(
                    200,
                    json={
                        "is_safe": True,
                        "confidence": 1.0,
                        "reason": "safe",
                        "matches": [],
                        "errors": [],
                        "non_matches": [],
                    },
                )
            raise AssertionError(request.url)

        with tempfile.TemporaryDirectory() as directory:
            old_cache = __import__("os").environ.get("DEFENSECLAW_NO_SDK_CACHE_DIR")
            __import__("os").environ["DEFENSECLAW_NO_SDK_CACHE_DIR"] = directory
            try:
                http = httpx.Client(
                    base_url="https://agent-control.test", transport=httpx.MockTransport(handler)
                )
                client = AgentControlRestClient(settings(), http)
                result = client.evaluate(
                    PolicyCheck(
                        step_name="Bash",
                        step_type="tool",
                        input={"command": "echo safe"},
                        hook_event="PreToolUse",
                        client_name="claude-code",
                    ),
                    trace_id="a" * 32,
                    span_id="b" * 16,
                    session_id="session",
                    defenseclaw_action="allow",
                    defenseclaw_severity="NONE",
                )
            finally:
                if old_cache is None:
                    __import__("os").environ.pop("DEFENSECLAW_NO_SDK_CACHE_DIR", None)
                else:
                    __import__("os").environ["DEFENSECLAW_NO_SDK_CACHE_DIR"] = old_cache
        self.assertTrue(result.is_safe)
        self.assertEqual(len(requests), 1)
        body = __import__("json").loads(requests[0].content)
        self.assertEqual(body["target_type"], "log_stream")
        self.assertEqual(body["target_id"], "stream-id")
        self.assertEqual(body["step"]["input"]["command"], "echo safe")
        self.assertEqual(requests[0].headers["Galileo-API-Key"], "test-key")

    def test_cache_path_is_outside_repository_by_default(self) -> None:
        self.assertNotEqual(settings().cache_dir, Path.cwd() / ".demo-cache")


if __name__ == "__main__":
    unittest.main()
