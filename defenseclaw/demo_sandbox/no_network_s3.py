"""Real boto3 S3 calls intercepted in memory before any HTTP request.

The returned wrapper uses a genuine botocore S3 client and ``Stubber``. Agent
Control evaluates every operation before the boto3 method is called. Even if a
policy unexpectedly allows DeleteBucket, Stubber raises a simulated service
error without credentials, DNS, sockets, or an AWS account.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import boto3
from botocore.client import BaseClient
from botocore.stub import Stubber

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defenseclaw_runtime import DefenseClawPolicyClient  # noqa: E402
from policy_models import PolicyCheck  # noqa: E402

SIMULATED_BUCKET = "demo-protected-bucket"


def _deny_network_send(**_: Any) -> None:
    raise RuntimeError("No-network boto3 tripwire stopped an unstubbed S3 operation before HTTP.")


class PolicyEvaluator(Protocol):
    def evaluate(self, check: PolicyCheck) -> Any: ...


class NoNetworkS3Client:
    """Small S3 surface backed by a real boto3 client and in-memory responses."""

    def __init__(self, client: BaseClient, policy_client: PolicyEvaluator | None = None) -> None:
        self._client = client
        self._policy_client = policy_client

    def _evaluate(self, operation: str, bucket: str | None = None) -> None:
        owns_client = self._policy_client is None
        policy_client = self._policy_client or DefenseClawPolicyClient()
        try:
            decision = policy_client.evaluate(
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
        finally:
            if owns_client:
                policy_client.close()
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

    def list_objects_v2(self, *, Bucket: str, **kwargs: Any) -> dict[str, Any]:
        self._evaluate("s3:ListObjectsV2", Bucket)
        expected = {"Bucket": Bucket, **kwargs}
        response = {
            "IsTruncated": False,
            "Name": Bucket,
            "MaxKeys": 1000,
            "KeyCount": 1,
            "Contents": [
                {
                    "Key": "example.txt",
                    "LastModified": datetime(2026, 1, 1, tzinfo=UTC),
                    "ETag": '"simulation"',
                    "Size": 0,
                    "StorageClass": "STANDARD",
                }
            ],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }
        with Stubber(self._client) as stubber:
            stubber.add_response("list_objects_v2", response, expected_params=expected)
            return self._client.list_objects_v2(**expected)

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


def guarded_s3_client(
    *,
    boto3_module: Any = boto3,
    policy_client: PolicyEvaluator | None = None,
) -> NoNetworkS3Client:
    """Create a real boto3 client that cannot send an AWS request."""
    client = boto3_module.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="simulation-not-a-real-key",
        aws_secret_access_key="simulation-not-a-real-secret",
        aws_session_token="simulation-not-a-real-session",
        endpoint_url="http://127.0.0.1:9",
    )
    client.meta.events.register("before-send.s3.*", _deny_network_send)
    return NoNetworkS3Client(client, policy_client)
