# Agent Control examples

This repository contains four standalone examples:

- [`agentcontrol-raw-demo`](agentcontrol-raw-demo/README.md): Streamlit command-blocking and transfer-steering demo.
- [`defenseclaw`](defenseclaw/README.md): DefenseClaw first, then the Agent Control SDK.
- [`defenseclaw-no-sdk`](defenseclaw-no-sdk/README.md): The same scenarios with direct Agent Control REST evaluation and no SDK.
- [`defenseclaw-enforcer-no-sdk`](defenseclaw-enforcer-no-sdk/README.md): Agent Control manages policy state while DefenseClaw locally enforces translated rules and optional Cisco AI Defense findings.

Each directory has its own dependency file, lockfile, setup instructions, and safety boundaries.

The `defenseclaw` and `defenseclaw-no-sdk` pair is intentionally aligned:
DefenseClaw locally blocks S3 and filesystem deletion, while Agent Control
handles Terraform steering, prompt injection, and control-tampering
protection. Their policy-runtime difference is SDK versus direct server
evaluation. The enforcer example is a separate architecture: Agent Control is
the management plane and DefenseClaw owns the final runtime decision.
