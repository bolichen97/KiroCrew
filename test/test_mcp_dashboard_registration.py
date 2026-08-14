"""Managed-MCP registration for ``kirocrew-dashboard``, and why it is its own server.

The dashboard-control tools are deliberately NOT in ``kirocrew-core``. Core is the
surface every session carries and kiro-cli reads ``tools/list`` once per session,
so a capability the user grants occasionally would otherwise spend context in
every request of every session. Three properties encode that decision and must
not regress:

* **The default agent's spec does not carry the server**, in ``mcpServers`` or as
  an ``@kirocrew-dashboard`` ref in ``tools``. kiro-cli loads a server only when
  something references it, so an unreferenced set costs a default session
  literally zero context — the only shape that does.
* **A refresh never re-grants it.** An existing spec that names the server keeps
  its command current; one that does not is left alone, so the grant cannot come
  back on a gateway restart behind the user's back.
* **The managed spec carries NO ``autoApprove`` key.** An autoApproved MCP tool is
  approved inside kiro-cli and never reaches ``hooks.on_tool_call``, so the deny
  floor and governance ceiling would be bypassed for tools that rewrite the
  user's session layout.

The registry assertions mirror ``test_computer_use_registration.py``: a managed
server has to be named in several places, and a half-registered server is the
failure mode that test was written to prevent.
"""

from __future__ import annotations

from typing import Any

from kiro_crew import agent, mcp_cleanup, mcp_discovery, onboarding_import

DASH_SERVER = "kirocrew-dashboard"
DASH_SUBCOMMAND = "mcp-dashboard"


class TestRegistryParity:
    def test_named_in_every_managed_registry(self) -> None:
        assert DASH_SERVER in agent._MANAGED_MCP_SERVERS
        assert DASH_SERVER in mcp_cleanup.KIROCREW_BIN_MCP_SERVERS
        assert mcp_discovery._MANAGED_SERVER_SUBCOMMANDS.get(DASH_SERVER) == DASH_SUBCOMMAND
        assert DASH_SERVER in mcp_discovery._MANAGED_SERVER_NAMES
        assert DASH_SERVER in onboarding_import._MANAGED_MCP_NAMES

    def test_tool_module_is_mapped_for_in_process_listing(self) -> None:
        """Discovery reads tool names in-process; an unmapped server lists zero."""
        assert (
            mcp_discovery._MANAGED_SERVER_TOOL_MODULES.get(DASH_SERVER)
            == "kiro_crew.mcp_dashboard"
        )

    def test_spec_carries_no_auto_approve(self) -> None:
        assert "autoApprove" not in agent._MANAGED_MCP_SERVERS[DASH_SERVER]

    def test_server_key_is_slash_free(self) -> None:
        """A slash in the key would be rewritten by the alias normalization pass."""
        assert "/" not in DASH_SERVER and "\\" not in DASH_SERVER

    def test_it_is_marked_as_an_assignable_set(self) -> None:
        """``opt_in`` is what makes the two spec writers skip it."""
        assert agent._MANAGED_MCP_SERVERS[DASH_SERVER].get("opt_in") is True

    def test_the_cleanup_split_tracks_the_opt_in_flags(self) -> None:
        """Two sources name the same fact, so pin them together.

        ``mcp_cleanup`` splits always-on from opt-in for doctor's benefit, while
        ``agent`` owns the ``opt_in`` flag the spec writers read. A server added
        to one and not the other would either be demanded in every spec or
        silently granted, so neither may drift.
        """
        flagged = {n for n, s in agent._MANAGED_MCP_SERVERS.items() if s.get("opt_in")}
        assert set(mcp_cleanup.OPT_IN_BIN_MCP_SERVERS) == flagged
        assert set(mcp_cleanup.ALWAYS_ON_BIN_MCP_SERVERS) == set(agent._MANAGED_MCP_SERVERS) - flagged
        assert set(mcp_cleanup.KIROCREW_BIN_MCP_SERVERS) == set(agent._MANAGED_MCP_SERVERS)


class TestDoctorTreatsItAsAssignedNotMissing:
    """`kirocrew doctor` must not undo the assignment, in either direction."""

    def test_it_is_never_blanket_auto_approved(self) -> None:
        """``allowedTools`` skips the PreToolUse gate, so doctor may not mint one.

        Doctor mints a blanket grant for every managed server outside this set.
        For tools that rewrite the user's session layout that would delete the
        deny floor and the governance ceiling in one step.
        """
        from kiro_crew import cli_doctor

        assert DASH_SERVER in cli_doctor._NO_BLANKET_ALLOW_MCPS

    def test_its_absence_is_not_a_doctor_issue(self, tmp_path: Any, capsys: Any) -> None:
        """A default install has no grant, and that is the healthy state."""
        import json

        from kiro_crew import cli_doctor

        spec = tmp_path / "kirocrew.json"
        spec.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        n: {"command": "/usr/local/bin/kirocrew", "args": [f"mcp-{n.split('-', 1)[1]}"]}
                        for n in mcp_cleanup.ALWAYS_ON_BIN_MCP_SERVERS
                    },
                    "tools": [f"@{n}" for n in mcp_cleanup.ALWAYS_ON_BIN_MCP_SERVERS],
                    "allowedTools": [],
                }
            ),
            encoding="utf-8",
        )
        issues: list[str] = []
        cli_doctor._doctor_mcp_governance(spec, issues)
        assert f"@{DASH_SERVER} config" not in issues
        out = capsys.readouterr().out
        assert "markers missing" not in out


class TestTheDefaultAgentIsNotGrantedTheSet:
    """A fresh install must not spend context on a set nobody assigned."""

    def test_a_fresh_spec_does_not_define_the_server(self) -> None:
        config = agent.build_agent_config()
        assert DASH_SERVER not in config.get("mcpServers", {})

    def test_a_fresh_spec_does_not_reference_the_server(self) -> None:
        """The ``@`` ref is the actual mount: without it kiro-cli never loads it."""
        config = agent.build_agent_config()
        assert f"@{DASH_SERVER}" not in config.get("tools", [])

    def test_the_always_on_servers_are_still_granted(self) -> None:
        """The skip is scoped to opt-in sets, not to managed servers at large."""
        config = agent.build_agent_config()
        mcp = config.get("mcpServers", {})
        assert "kirocrew-core" in mcp
        assert "kirocrew-cron" in mcp

    def test_a_refresh_does_not_introduce_the_server(self) -> None:
        config: dict[str, Any] = {"mcpServers": {}}
        agent._refresh_dynamic_fields(config)
        assert DASH_SERVER not in config["mcpServers"]

    def test_a_refresh_keeps_an_existing_grant_current(self) -> None:
        """An agent the user granted the set to must survive an upgrade."""
        config: dict[str, Any] = {"mcpServers": {DASH_SERVER: {"command": "stale"}}}
        agent._refresh_dynamic_fields(config)
        entry = config["mcpServers"][DASH_SERVER]
        assert entry["command"] != "stale"
        assert DASH_SUBCOMMAND in entry["args"]


class TestWhatThisSetGrants:
    """Assignment is per SERVER, so the set is the unit of authorization.

    A spec that references this server gets every tool in it — there is no
    per-tool granularity in the mount. That is sound for the current tools: they
    grant no read the agent lacks (``list_sessions`` in core already returns every
    session's title and key) and delete nothing. It stops being sound the moment a
    capability with real blast radius is added to this same set, because granting
    the folder tools would silently grant that too.

    This ratchet pins the set, so such a capability fails here until the author
    puts it in a server of its own with the gate it actually needs.
    """

    FOLDER_TOOLS = {
        "chat_folder_tree",
        "chat_folder_create",
        "chat_folder_move",
        "chat_folder_move_session",
    }

    def test_the_set_is_exactly_the_folder_tools(self) -> None:
        from kiro_crew import mcp_dashboard

        assert {t["name"] for t in mcp_dashboard._tool_definitions()} == self.FOLDER_TOOLS

    def test_the_advertised_list_is_the_set(self) -> None:
        """Reaching the process means the set was assigned; nothing is hidden."""
        from kiro_crew import mcp_dashboard

        assert {t["name"] for t in mcp_dashboard._list_tools()} == self.FOLDER_TOOLS

    def test_no_session_driving_tool_joins_this_set(self) -> None:
        """A tool that messages/stops another session needs its own server."""
        from kiro_crew import mcp_dashboard

        names = {t["name"] for t in mcp_dashboard._tool_definitions()}
        forbidden = {n for n in names if "message" in n or "stop" in n or "steer" in n}
        assert not forbidden, (
            f"{sorted(forbidden)} drive another session but would be granted by "
            "assigning the folder-organization set — give that class its own server"
        )
