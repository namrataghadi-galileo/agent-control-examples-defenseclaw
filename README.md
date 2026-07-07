# Agent Control examples

This repository contains three standalone examples:

- [`agentcontrol-raw-demo`](agentcontrol-raw-demo/README.md): Streamlit command-blocking and transfer-steering demo.
- [`defenseclaw`](defenseclaw/README.md): DefenseClaw first, then the Agent Control SDK.
- [`defenseclaw-no-sdk`](defenseclaw-no-sdk/README.md): The same scenarios with direct Agent Control REST evaluation and no SDK.

Each directory has its own dependency file, lockfile, setup instructions, and safety boundaries.

The DefenseClaw pair is intentionally aligned: DefenseClaw locally blocks S3
and filesystem deletion, while Agent Control handles Terraform steering,
prompt injection, and control-tampering protection. The only policy-runtime
difference is SDK versus direct server evaluation.
