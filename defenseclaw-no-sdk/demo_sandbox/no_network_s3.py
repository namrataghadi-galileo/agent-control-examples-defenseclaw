"""Real boto3 calls intercepted in memory before any HTTP request."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

import boto3
from botocore.client import BaseClient
from botocore.stub import Stubber

from policy_models import PolicyCheck

SIMULATED_BUCKET = "demo-protected-bucket"


def _deny_network_send(**_: Any) -> None:
    raise RuntimeError("No-network boto3 tripwire stopped an unstubbed request before HTTP.")


class PolicyEvaluator(Protocol):
    def evaluate(self, check: PolicyCheck, **kwargs: Any) -> Any: ...


class NoNetworkS3Client:
    def __init__(self, client: BaseClient, policy: PolicyEvaluator) -> None:
        self._client = client
        self._policy = policy

    def _evaluate(self, operation: str, bucket: str | None = None) -> None:
        decision = self._policy.evaluate(
            PolicyCheck(
                step_name="aws.s3.request",
                step_type="tool",
                input={
                    "operation": operation,
                    "bucket": bucket,
                    "source": "no-network-boto3-stubber",
                },
                hook_event="PreToolUse",
                client_name="no-network-boto3-stubber",
            )
        )
        if not decision.allowed:
            raise PermissionError(decision.reason)

    def list_buckets(self, **kwargs: Any) -> dict[str, Any]:
        self._evaluate("s3:ListBuckets")
        response = {
            "Buckets": [
                {
                    "Name": SIMULATED_BUCKET,
                    "CreationDate": datetime(2026, 1, 1, tzinfo=UTC),
                }
            ],
            "Owner": {"DisplayName": "simulation", "ID": "simulation-only"},
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }
        with Stubber(self._client) as stubber:
            stubber.add_response("list_buckets", response, expected_params=kwargs)
            return self._client.list_buckets(**kwargs)

    def delete_bucket(self, *, Bucket: str, **kwargs: Any) -> None:
        self._evaluate("s3:DeleteBucket", Bucket)
        expected = {"Bucket": Bucket, **kwargs}
        with Stubber(self._client) as stubber:
            stubber.add_client_error(
                "delete_bucket",
                service_error_code="SimulationSafetyNet",
                service_message="No S3 request was made.",
                http_status_code=403,
                expected_params=expected,
            )
            self._client.delete_bucket(**expected)


def guarded_s3_client(*, policy: PolicyEvaluator) -> NoNetworkS3Client:
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="simulation-not-a-real-key",
        aws_secret_access_key="simulation-not-a-real-secret",
        aws_session_token="simulation-not-a-real-session",
        endpoint_url="http://127.0.0.1:9",
    )
    client.meta.events.register("before-send.s3.*", _deny_network_send)
    return NoNetworkS3Client(client, policy)
