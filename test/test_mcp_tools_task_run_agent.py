"""``task_run`` can name the agent the task runner executes under.

The dashboard has always been able to start a run under a chosen agent
(``/api/taskrunner`` reads ``body["agent"]`` and hands it to
``TaskRunner.start_background``), but the MCP surface could not express it:
``agent`` was absent from both the descriptor and ``TASK_RUN_SCHEMA``, and
unknown tool fields are rejected outright — so a cron- or skill-dispatched
``task_run(spec=..., agent="team-x")`` failed with "unknown field" rather
than running under ``team-x``.

The field is pattern-bound (``_AGENT_NAME_RE``, as every other agent-valued
tool field is) because the value reaches a ``--agent`` subprocess argument.

Everything is mocked at mcp_core's ``_post`` seam: no gateway, no runner, no
network.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from kiro_crew import mcp_core
from kiro_crew.mcp_core import _call_tool_inner
from kiro_crew.mcp_tools import control
from kiro_crew.validation import ValidationError


def _task_run_descriptor() -> dict[str, Any]:
    for tool in control.schemas():
        if tool["name"] == "task_run":
            return tool
    raise AssertionError("task_run descriptor missing")


class TestTaskRunAgentForwarding:
    def test_agent_is_forwarded_to_the_taskrunner_endpoint(self) -> None:
        with patch.object(mcp_core, "_resolve_session_key", return_value="cron:nightly"):
            with patch.object(mcp_core, "_post", return_value={"ok": True}) as p:
                out = _call_tool_inner(
                    "task_run", {"spec": "do the thing", "name": "N", "agent": "team-x"}
                )
        assert out == "Task runner started: N"
        assert p.call_args.args[1]["agent"] == "team-x"

    def test_an_omitted_agent_is_sent_as_the_empty_default(self) -> None:
        """Backward compatibility: the endpoint reads ``body.get("agent", "")``,
        and an empty string is what makes it fall through to the configured
        default agent."""
        with patch.object(mcp_core, "_resolve_session_key", return_value="dashboard:c"):
            with patch.object(mcp_core, "_post", return_value={"ok": True}) as p:
                _call_tool_inner("task_run", {"spec": "do the thing"})
        assert p.call_args.args[1]["agent"] == ""

    def test_a_malformed_agent_name_is_refused_before_the_post(self) -> None:
        """The value becomes a ``--agent`` argument, so it is grammar-checked
        rather than passed through."""
        with patch.object(mcp_core, "_post", side_effect=AssertionError("must not POST")):
            with pytest.raises(ValidationError) as exc:
                _call_tool_inner("task_run", {"spec": "x", "agent": "../../etc/passwd"})
        # Refused on its grammar, not merely as an unrecognised field.
        assert exc.value.field == "agent"
        assert exc.value.message == "invalid format"


class TestTaskRunDescriptor:
    def test_agent_is_advertised_and_stays_optional(self) -> None:
        schema = _task_run_descriptor()["inputSchema"]
        assert "agent" in schema["properties"]
        assert schema["properties"]["agent"]["type"] == "string"
        assert schema["required"] == ["spec"]
