"""Streamlit UI for the Agent Control safety demo."""

from __future__ import annotations

import asyncio
from typing import Any

import streamlit as st
from agent_control import ControlSteerError, ControlViolationError

from demo_agent import (
    AGENT_NAME,
    SERVER_URL,
    TRANSFER_LIMIT,
    active_controls,
    execute_shell_command,
    initialize_agent,
    parse_steering_context,
    refresh_controls,
    suggested_amount,
    transfer_funds,
)

SHELL_EXAMPLES = {
    "Safe: inspect a folder": "ls -la ./demo-workspace",
    "Safe: check disk usage": "du -sh ./demo-workspace",
    "Dangerous (regex): recursive deletion": "rm -rf ./demo-workspace/important-project",
    "Dangerous (list): shut down host": "shutdown -h now",
}


@st.cache_resource(show_spinner=False)
def start_agent() -> bool:
    """Initialize Agent Control once for the Streamlit process."""
    initialize_agent()
    return True


def control_names(controls: list[dict[str, Any]]) -> list[str]:
    """Extract display names from effective-control responses."""
    return [str(item.get("name", "unnamed")) for item in controls]


def render_sidebar() -> None:
    """Render connection details and effective-control status."""
    with st.sidebar:
        st.header("Agent Control")
        st.code(AGENT_NAME)
        st.caption(f"Server: {SERVER_URL}")

        if st.button("Refresh controls", use_container_width=True):
            with st.spinner("Refreshing controls..."):
                refresh_controls()

        controls = active_controls()
        names = control_names(controls)
        if names:
            st.success(f"{len(names)} active control(s)")
            for name in names:
                st.markdown(f"- `{name}`")
        else:
            st.warning("No controls are attached. Create them in the Agent Control UI.")

        st.divider()
        st.caption("All commands and transfers in this app are simulations.")


def render_command_demo() -> None:
    """Render the dangerous-command blocking scenario."""
    st.subheader("Dangerous command blocking")
    st.write(
        "Simulate commands proposed by an autonomous agent. Regex and list controls "
        "inspect `input.command` before the tool runs."
    )

    label = st.selectbox("Scenario", list(SHELL_EXAMPLES))
    command = st.text_input("Proposed command", value=SHELL_EXAMPLES[label])

    if st.button("Ask agent to run command", type="primary", use_container_width=True):
        if not command.strip():
            st.error("Enter a command.")
            return

        try:
            result = asyncio.run(execute_shell_command(command=command.strip()))
        except ControlViolationError as exc:
            st.error("DENIED — the command never reached the simulated tool.")
            st.json(
                {
                    "decision": "deny",
                    "control": exc.control_name,
                    "reason": exc.message,
                    "proposed_command": command,
                }
            )
        except ControlSteerError as exc:
            st.warning("STEERED — revise the command before retrying.")
            st.json(
                {
                    "decision": "steer",
                    "control": exc.control_name,
                    "guidance": exc.steering_context,
                }
            )
        except Exception as exc:  # Streamlit should surface server/configuration failures clearly.
            st.exception(exc)
        else:
            st.success("ALLOWED — Agent Control found no matching deny control.")
            st.json(result)


def run_transfer(amount: float, recipient: str, purpose: str) -> None:
    """Evaluate one transfer and persist its result across Streamlit reruns."""
    try:
        result = asyncio.run(
            transfer_funds(amount=amount, recipient=recipient, purpose=purpose)
        )
    except ControlViolationError as exc:
        st.session_state.transfer_result = {
            "kind": "deny",
            "payload": {
                "decision": "deny",
                "control": exc.control_name,
                "reason": exc.message,
                "requested_amount": amount,
            },
        }
        st.session_state.pop("pending_transfer", None)
    except ControlSteerError as exc:
        steering = parse_steering_context(exc.steering_context)
        capped_amount = suggested_amount(exc.steering_context)
        st.session_state.transfer_result = {
            "kind": "steer",
            "payload": {
                "decision": "steer",
                "control": exc.control_name,
                "reason": steering.get("reason", exc.message),
                "requested_amount": amount,
                "suggested_amount": capped_amount,
                "guidance": exc.steering_context,
            },
        }
        st.session_state.pending_transfer = {
            "amount": capped_amount,
            "recipient": recipient,
            "purpose": purpose,
        }
    except Exception as exc:  # Streamlit should surface server/configuration failures clearly.
        st.session_state.transfer_result = {
            "kind": "error",
            "payload": {"error": str(exc)},
        }
    else:
        st.session_state.transfer_result = {"kind": "allow", "payload": result}
        st.session_state.pop("pending_transfer", None)


def render_transfer_result() -> None:
    """Render the latest transfer decision and optional corrective retry."""
    result = st.session_state.get("transfer_result")
    if not result:
        return

    kind = result["kind"]
    if kind == "allow":
        st.success("ALLOWED — the simulated transfer completed.")
    elif kind == "steer":
        st.warning("STEERED — the original transfer was not executed.")
    elif kind == "deny":
        st.error("DENIED — the transfer was not executed.")
    else:
        st.error("The transfer could not be evaluated.")
    st.json(result["payload"])

    pending = st.session_state.get("pending_transfer")
    if pending and st.button(
        f"Apply steering and retry ${pending['amount']:,.2f}",
        type="primary",
        use_container_width=True,
    ):
        run_transfer(**pending)
        st.rerun()


def render_transfer_demo() -> None:
    """Render the high-value transfer steering scenario."""
    st.subheader("High-value transfer steering")
    st.write(
        f"A JSON evaluator validates `input.amount`. Transfers over ${TRANSFER_LIMIT:,.0f} "
        "are steered to the configured safe cap and can then be retried."
    )

    with st.form("transfer-form"):
        amount = st.number_input(
            "Amount (USD)",
            min_value=1.0,
            value=25_000.0,
            step=500.0,
        )
        recipient = st.text_input("Recipient", value="Acme Infrastructure LLC")
        purpose = st.text_input("Purpose", value="Infrastructure services")
        submitted = st.form_submit_button(
            "Ask agent to transfer funds", type="primary", use_container_width=True
        )

    if submitted:
        if not recipient.strip() or not purpose.strip():
            st.error("Recipient and purpose are required.")
        else:
            run_transfer(float(amount), recipient.strip(), purpose.strip())

    render_transfer_result()


def main() -> None:
    """Run the Streamlit application."""
    st.set_page_config(
        page_title="Agent Control Safety Demo",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("Agent Control: autonomous-action safety")
    st.caption(
        "Built-in evaluators only: regex, list, and JSON. No Luna evaluator is required."
    )

    try:
        start_agent()
    except Exception as exc:
        st.error(f"Could not initialize `{AGENT_NAME}` against `{SERVER_URL}`.")
        st.exception(exc)
        st.stop()

    render_sidebar()
    command_tab, transfer_tab = st.tabs(["Command safety", "Transfer steering"])
    with command_tab:
        render_command_demo()
    with transfer_tab:
        render_transfer_demo()


if __name__ == "__main__":
    main()
