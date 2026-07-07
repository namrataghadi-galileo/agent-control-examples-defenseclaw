#!/usr/bin/env python3
"""Use genuine boto3 with DefenseClaw-first policy and guaranteed zero AWS traffic."""

from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from demo_sandbox.no_network_s3 import SIMULATED_BUCKET, guarded_s3_client
from policy_runtime import DefenseClawNoSdkPolicyClient


def main() -> None:
    print(f"boto3 version: {boto3.__version__}")
    print("Agent Control SDK: not installed or imported")
    print("AWS credentials: placeholder values only")
    print("AWS network: prohibited by Stubber + before-send tripwire")
    with DefenseClawNoSdkPolicyClient() as policy:
        s3 = guarded_s3_client(policy=policy)
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
