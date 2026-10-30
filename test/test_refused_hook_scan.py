"""Tests for the refused-hook listing: the shared deny helper, the scan, the
``kirocrew doctor`` section and the once-per-process startup warning.

``run_script_hook`` refuses a hook whose command the shell deny-list matches,
without running it. These tests pin that the listing asks the SAME check
(``hooks.hook_command_deny_reason``), so a hook the listing names is one a firing
hook is refused for, and that the listing never prints the command itself.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from kiro_crew import cli_doctor, hooks, refused_hook_scan
from kiro_crew.config.loader import KiroCrewConfig
from kiro_crew.config.paths import config_dir
from kiro_crew.doctor_checks import agents
from kiro_crew.hooks import HOOK_EVENT_PRE_TOOL_USE, HOOK_EVENT_STOP, ScriptHook

#: Refused by the always-on git-publish floor, as in ``test_script_hooks``.
DENIED = "git push origin main"
BENIGN = "echo hello"


def _write_spec(directory: Path, name: str, hooks_field: object) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"
    path.write_text(json.dumps({"name": name, "hooks": hooks_field}), encoding="utf-8")
    return path


def _write_hooks_page(entries: list[dict]) -> None:
    path = config_dir() / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": entries}), encoding="utf-8")


class TestRefusedScriptHooks:
    def test_the_helper_answers_the_deny_list(self) -> None:
        assert hooks.hook_command_deny_reason(DENIED)
        assert hooks.hook_command_deny_reason(BENIGN) is None

    @pytest.mark.asyncio
    async def test_run_script_hook_refuses_through_the_helper(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A benign command is refused once the helper says so: the runner's deny
        # branch asks this helper, so the listing and the runner cannot disagree.
        monkeypatch.setattr(
            hooks, "hook_command_deny_reason", lambda command: "Blocked by security policy: x"
        )
        hook = ScriptHook(id="h", name="greeter", event=HOOK_EVENT_STOP, command=BENIGN)
        result = await hooks.run_script_hook(hook, "ctx")
        assert result.error == "Blocked by security policy: x"
        assert hook.last_status == "blocked"

    def test_a_refused_hook_is_listed_with_its_reason_and_a_benign_one_is_not(self) -> None:
        refused = hooks.refused_script_hooks(
            [
                ScriptHook(id="a", name="pusher", event=HOOK_EVENT_PRE_TOOL_USE, command=DENIED),
                ScriptHook(id="b", name="greeter", event=HOOK_EVENT_STOP, command=BENIGN),
                ScriptHook(id="c", name="skills-only", event=HOOK_EVENT_STOP, command=""),
            ]
        )
        assert [(name, event) for name, event, _ in refused] == [
            ("pusher", HOOK_EVENT_PRE_TOOL_USE)
        ]
        assert "Blocked by security policy" in refused[0][2]


class TestScan:
    def test_spec_and_hooks_page_findings(self, tmp_path: Path) -> None:
        specs = tmp_path / "agents"
        _write_spec(specs, "builder", {"preToolUse": [{"command": DENIED}]})
        _write_spec(specs, "quiet", {"stop": [{"command": BENIGN}]})
        _write_hooks_page(
            [
                {"id": "h1", "name": "page-push", "event": "Stop", "command": DENIED},
                {"id": "h2", "name": "off", "event": "Stop", "command": DENIED, "enabled": False},
            ]
        )
        scan = refused_hook_scan.scan_refused_hooks(spec_dirs=[specs])
        assert scan.error == ""
        assert scan.unreadable == []
        owners = [(hook.owner, hook.event) for hook in scan.refused]
        assert owners == [("builder", HOOK_EVENT_PRE_TOOL_USE), ("", "Stop")]
        assert all("Blocked by security policy" in hook.reason for hook in scan.refused)
        assert all(DENIED not in hook.name for hook in scan.refused)

    def test_a_malformed_spec_is_reported_and_does_not_stop_the_scan(self, tmp_path: Path) -> None:
        specs = tmp_path / "agents"
        specs.mkdir()
        (specs / "broken.json").write_text("{not json", encoding="utf-8")
        _write_spec(specs, "builder", {"preToolUse": [{"command": DENIED}]})
        scan = refused_hook_scan.scan_refused_hooks(spec_dirs=[specs])
        assert scan.unreadable == ["broken.json"]
        assert [hook.owner for hook in scan.refused] == ["builder"]


class TestDoctorSection:
    @pytest.fixture()
    def dirs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        specs = tmp_path / "agents"
        specs.mkdir()
        monkeypatch.setattr(cli_doctor, "_agents_dir", lambda: specs)
        monkeypatch.setattr("kiro_crew.config.paths.mate_agents_dir", lambda: tmp_path / "mates")
        return specs

    def test_lists_a_refused_hook_with_its_reason_and_no_command(
        self, dirs: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_spec(dirs, "builder", {"preToolUse": [{"command": DENIED}]})
        _write_spec(dirs, "quiet", {"stop": [{"command": BENIGN}]})
        issues: list[str] = []
        agents._doctor_refused_hooks(KiroCrewConfig(), issues)
        out = capsys.readouterr().out
        assert "Refused Hooks" in out
        assert "agent 'builder'" in out
        assert "will be refused by the security policy and will not run" in out
        assert "Blocked by security policy" in out
        assert "kiro-cli runs a spec's hooks itself" in out
        assert "'quiet'" not in out
        assert DENIED not in out
        assert issues == ["hooks the security policy will refuse"]

    def test_the_listing_depends_on_the_helper(
        self,
        dirs: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Mutation proof: with the helper reporting nothing refused, the section
        # has nothing to list -- so the test above passes only through it.
        _write_spec(dirs, "builder", {"preToolUse": [{"command": DENIED}]})
        monkeypatch.setattr(hooks, "refused_script_hooks", lambda hook_list: [])
        issues: list[str] = []
        agents._doctor_refused_hooks(KiroCrewConfig(), issues)
        assert capsys.readouterr().out == ""
        assert issues == []

    def test_silent_when_every_hook_is_benign(
        self, dirs: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_spec(dirs, "quiet", {"stop": [{"command": BENIGN}]})
        issues: list[str] = []
        agents._doctor_refused_hooks(KiroCrewConfig(), issues)
        assert capsys.readouterr().out == ""
        assert issues == []

    def test_a_malformed_spec_does_not_crash_doctor(
        self, dirs: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (dirs / "broken.json").write_text("{not json", encoding="utf-8")
        _write_spec(dirs, "builder", {"preToolUse": [{"command": DENIED}]})
        issues: list[str] = []
        agents._doctor_refused_hooks(KiroCrewConfig(), issues)
        out = capsys.readouterr().out
        assert "agent 'builder'" in out
        assert "1 agent spec(s) could not be read ('broken.json')" in out

    def test_a_failing_deny_check_is_reported_as_not_checked(
        self,
        dirs: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write_spec(dirs, "builder", {"preToolUse": [{"command": DENIED}]})

        def _boom(command: str) -> str | None:
            raise RuntimeError("no context")

        monkeypatch.setattr(hooks, "hook_command_deny_reason", _boom)
        issues: list[str] = []
        agents._doctor_refused_hooks(KiroCrewConfig(), issues)
        assert "not checked: the deny check could not run ('RuntimeError')" in (
            capsys.readouterr().out
        )
        assert issues == []


class TestStartupWarning:
    def test_warns_once_per_process(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        specs = tmp_path / "agents"
        _write_spec(specs, "builder", {"preToolUse": [{"command": DENIED}]})
        monkeypatch.setattr(refused_hook_scan, "_default_spec_dirs", lambda: [specs])
        monkeypatch.setattr(refused_hook_scan, "_warned", False)
        with caplog.at_level(logging.WARNING, logger="kiro_crew.refused_hook_scan"):
            refused_hook_scan.warn_refused_hooks_once()
            refused_hook_scan.warn_refused_hooks_once()
        warnings = [r for r in caplog.records if r.name == "kiro_crew.refused_hook_scan"]
        assert len(warnings) == 1
        message = warnings[0].getMessage()
        assert "will be refused by the security policy and will not run" in message
        assert "agent 'builder'" in message
        assert DENIED not in message
