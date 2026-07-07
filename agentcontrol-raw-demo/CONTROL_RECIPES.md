# Manual control recipes

Create these controls manually after registering `openclaw-safety-demo`.

In the Agent Control UI:

1. Open **Agents** and select `openclaw-safety-demo`.
2. Open **Controls** and click **Add Control**.
3. Click **Create Control**, then **Write your own**.
4. Enter the control name shown below and replace the JSON definition with the matching block.
5. Save. The UI creates the control and associates it directly with this agent.

All controls use built-in evaluators. Luna is not required.

## 1. Deny recursive deletion with regex

Name: `deny-recursive-file-deletion`

When using the Regex evaluator form, paste this directly into **Pattern** (single backslashes):

```regex
(?:^|[;&|]\s*)(?:sudo\s+)?rm\s+-(?:rf|fr)\b
```

The full JSON equivalent below uses doubled backslashes only because JSON strings escape the
backslash character.

```json
{
  "description": "Block recursive force-deletion commands proposed by the agent",
  "enabled": true,
  "execution": "server",
  "scope": {
    "step_types": ["tool"],
    "step_names": ["execute_shell_command"],
    "stages": ["pre"]
  },
  "condition": {
    "selector": {"path": "input.command"},
    "evaluator": {
      "name": "regex",
      "config": {
        "pattern": "(?:^|[;&|]\\s*)(?:sudo\\s+)?rm\\s+-(?:rf|fr)\\b",
        "flags": ["IGNORECASE"]
      }
    }
  },
  "action": {"decision": "deny"},
  "tags": ["demo", "shell", "destructive-command"]
}
```

Demo inputs:

- Allow: `ls -la ./demo-workspace`
- Deny: `rm -rf ./demo-workspace/important-project`
- Deny: `sudo rm -fr /tmp/demo-data`

## 2. Deny dangerous system commands with list matching

Name: `deny-dangerous-system-commands`

```json
{
  "description": "Block dangerous system-management commands proposed by the agent",
  "enabled": true,
  "execution": "server",
  "scope": {
    "step_types": ["tool"],
    "step_names": ["execute_shell_command"],
    "stages": ["pre"]
  },
  "condition": {
    "selector": {"path": "input.command"},
    "evaluator": {
      "name": "list",
      "config": {
        "values": ["rmdir", "mkfs", "shutdown", "reboot", "halt", "poweroff"],
        "logic": "any",
        "match_on": "match",
        "match_mode": "contains",
        "case_sensitive": false
      }
    }
  },
  "action": {"decision": "deny"},
  "tags": ["demo", "shell", "system-command"]
}
```

Demo inputs:

- Allow: `du -sh ./demo-workspace`
- Deny: `shutdown -h now`
- Deny: `mkfs.ext4 /dev/example`

## 3. Steer transfers above $10,000

Name: `steer-large-transfer-to-safe-cap`

The JSON evaluator is a validator: it triggers the action when validation fails. Here, an amount
above `10000` fails the configured maximum and produces a `steer` decision.

When using the control form, paste this directly into **Steering context** (normal quotes, no
backslashes):

```json
{"reason":"Transfer exceeds the autonomous limit. Reduce it to $10,000 or less and retry.","suggested_amount":10000,"instruction":"Apply the safe cap and resubmit the transfer."}
```

The full control JSON below escapes those quotes because `message` is itself a JSON string.

```json
{
  "description": "Steer transfers over $10,000 to a safe demo amount",
  "enabled": true,
  "execution": "server",
  "scope": {
    "step_types": ["tool"],
    "step_names": ["transfer_funds"],
    "stages": ["pre"]
  },
  "condition": {
    "selector": {"path": "input"},
    "evaluator": {
      "name": "json",
      "config": {
        "field_constraints": {
          "amount": {"type": "number", "max": 10000}
        },
        "allow_extra_fields": true
      }
    }
  },
  "action": {
    "decision": "steer",
    "steering_context": {
      "message": "{\"reason\":\"Transfer exceeds the autonomous limit. Reduce it to $10,000 or less and retry.\",\"suggested_amount\":10000,\"instruction\":\"Apply the safe cap and resubmit the transfer.\"}"
    }
  },
  "tags": ["demo", "finance", "steer", "high-value-transfer"]
}
```

Demo inputs:

- Allow: `$500`
- Steer: `$25,000`
- Corrected retry: `$10,000`

After creating the controls, click **Refresh controls** in the Streamlit sidebar (or wait up to 15
seconds) before running the scenarios.
