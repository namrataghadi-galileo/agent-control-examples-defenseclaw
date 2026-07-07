#!/usr/bin/env python3
"""Exercise real boto3 methods with policy checks and zero AWS network traffic."""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from defenseclaw_runtime import DefenseClawPolicyClient
from demo_sandbox.no_network_s3 import SIMULATED_BUCKET, guarded_s3_client


def main() -> None:
    print(f"boto3 version: {boto3.__version__}")
    print("AWS credentials: placeholder values only")
    print("AWS network: prohibited by Stubber + before-send tripwire")

    with DefenseClawPolicyClient() as policy_client:
        s3 = guarded_s3_client(boto3_module=boto3, policy_client=policy_client)

        response = s3.list_buckets()
        names = [bucket["Name"] for bucket in response.get("Buckets", [])]
        print(f"ALLOW s3:ListBuckets -> {names} (in-memory response)")

        try:
            s3.delete_bucket(Bucket=SIMULATED_BUCKET)
        except PermissionError as exc:
            print(f"DENY  s3:DeleteBucket -> DefenseClaw first-layer policy: {exc}")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            print(f"DENY  s3:DeleteBucket -> botocore Stubber: {code}")
        else:
            raise RuntimeError("DeleteBucket unexpectedly escaped both safety boundaries.")

    print("RESULT no AWS request was made")


if __name__ == "__main__":
    main()
