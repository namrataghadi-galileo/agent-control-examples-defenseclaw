# Agent Control raw Streamlit safety demo

This standalone example demonstrates two safety patterns for an autonomous assistant:

- Block dangerous shell commands before a simulated command tool runs.
- Steer large transfers to a safer amount and retry the corrected action.

It uses only the built-in `regex`, `list`, and `json` evaluators. It does not require Luna. The
shell tool never executes host commands, and the transfer tool never moves real money.

## 1. Start Agent Control

This demo currently uses editable packages from a sibling `agent-control`
checkout. Clone both repositories under the same parent directory, then from
`../agent-control` run the server:

```bash
make server-run
```

From `../agent-control/ui`, run the dashboard in a second terminal:

```bash
make dev
```

The API should be available at <http://localhost:8000> and the UI at
<http://localhost:4000>.

## 2. Install this example and register the agent

From this `agentcontrol-raw-demo` directory:

```bash
uv sync
uv run python register_agent.py
```

This creates or updates `openclaw-safety-demo` and registers these tool steps:

- `execute_shell_command`
- `transfer_funds`

It intentionally creates no controls.

## 3. Create controls manually

Open <http://localhost:4000>, select `openclaw-safety-demo`, and follow
[CONTROL_RECIPES.md](CONTROL_RECIPES.md). The UI associates each new control with the agent.

## 4. Run the Streamlit demo

```bash
uv run streamlit run app.py
```

Open <http://localhost:8501>. If the app was already open while controls were created, click
**Refresh controls** in its sidebar.

Suggested flow:

1. Allow `ls -la ./demo-workspace`.
2. Deny `rm -rf ./demo-workspace/important-project` with the regex control.
3. Deny `shutdown -h now` with the list control.
4. Allow a `$500` transfer.
5. Submit `$25,000`, inspect the steer guidance, then click the corrected `$10,000` retry.

Set a different server URL when needed:

```bash
AGENT_CONTROL_URL=http://localhost:8000 uv run streamlit run app.py
```
