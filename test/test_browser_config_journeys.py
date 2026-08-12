"""Journey test: an operator's Playwright config must survive real user actions.

Simulates the sequences an operator actually performs -- toggling extension mode,
turning Browser Mode off and back on in Settings, and a gateway restart -- and
asserts the fields KiroCrew does not own are still there afterwards. The field
that matters is ``env.KIROCREW_PLAYWRIGHT_CMD``: on a host whose launcher is not
otherwise discoverable it is the only reason browsing works at all, so losing it
to a toggle is indistinguishable from the feature breaking.
"""

import json
from pathlib import Path

import pytest

import kiro_crew.mcp_cleanup as cleanup_mod
from kiro_crew.browser import setup as setup_mod
from kiro_crew.browser.setup import (
    converge_playwright_servers,
    deregister_playwright_proxy,
    register_playwright_proxy,
)
from kiro_crew.mcp_utils import mcp_server_alias

_CANONICAL = mcp_server_alias("@playwright/mcp")
_PIN = "/opt/pw/cli.js"


def _mcp_json(home: Path) -> Path:
    return home / ".kiro" / "settings" / "mcp.json"


def _read_entry(home: Path) -> dict | None:
    path = _mcp_json(home)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return (data.get("mcpServers") or {}).get(_CANONICAL)


def _seed_pinned_entry(home: Path) -> None:
    """An operator's working config: KiroCrew's proxy plus their own launcher pin."""
    path = _mcp_json(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    _CANONICAL: {
                        "command": "kirocrew",
                        "args": ["mcp-playwright-proxy", "--extension"],
                        "env": {
                            "KIROCREW_PLAYWRIGHT_CMD": _PIN,
                            "PLAYWRIGHT_MCP_EXTENSION_TOKEN": "tok",
                        },
                        "timeout": 60,
                    },
                    "other-mcp": {"command": "unrelated"},
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )


class TestOperatorConfigSurvivesUserJourneys:
    @pytest.fixture()
    def home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(setup_mod, "_kirocrew_bin", lambda: "kirocrew")
        monkeypatch.setattr(setup_mod, "get_extension_token", lambda: "tok")
        _seed_pinned_entry(tmp_path)
        return tmp_path

    def _mode(self, monkeypatch: pytest.MonkeyPatch, *, browser: bool, extension: bool) -> None:
        monkeypatch.setattr(setup_mod, "browser_mode_enabled", lambda: browser)
        monkeypatch.setattr(setup_mod, "has_playwright_extension", lambda: extension)

    def test_extension_toggled_off_and_on(self, home: Path, monkeypatch: pytest.MonkeyPatch):
        # `kirocrew browse extension off` then `on` -- two mode switches.
        self._mode(monkeypatch, browser=True, extension=False)
        register_playwright_proxy()
        assert (_read_entry(home) or {}).get("env", {}).get("KIROCREW_PLAYWRIGHT_CMD") == _PIN

        self._mode(monkeypatch, browser=True, extension=True)
        register_playwright_proxy()
        entry = _read_entry(home) or {}
        assert entry.get("env", {}).get("KIROCREW_PLAYWRIGHT_CMD") == _PIN
        assert entry.get("timeout") == 60

    def test_browser_mode_off_then_on_in_settings(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ):
        # The Settings toggle: deregister removes the tools, re-enabling restores
        # them. The operator's pin must not be collateral damage of that round trip.
        self._mode(monkeypatch, browser=True, extension=True)
        deregister_playwright_proxy()

        self._mode(monkeypatch, browser=True, extension=True)
        register_playwright_proxy()

        entry = _read_entry(home) or {}
        assert entry.get("env", {}).get("KIROCREW_PLAYWRIGHT_CMD") == _PIN

    def test_gateway_restart_converge(self, home: Path, monkeypatch: pytest.MonkeyPatch):
        # Boot-path convergence runs on every gateway start.
        self._mode(monkeypatch, browser=True, extension=True)
        converge_playwright_servers({})
        entry = _read_entry(home) or {}
        assert entry.get("env", {}).get("KIROCREW_PLAYWRIGHT_CMD") == _PIN

    def test_unrelated_servers_untouched(self, home: Path, monkeypatch: pytest.MonkeyPatch):
        self._mode(monkeypatch, browser=True, extension=True)
        register_playwright_proxy()
        data = json.loads(_mcp_json(home).read_text(encoding="utf-8"))
        assert data["mcpServers"]["other-mcp"] == {"command": "unrelated"}


class TestEveryPlaywrightSettingSurvives:
    """Inventory sweep: every piece of Playwright state vs every write path.

    Each case names the file and the action, so a regression says which setting
    was lost to which command rather than "browsing broke".
    """

    @pytest.fixture()
    def home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(setup_mod, "config_dir", lambda: tmp_path / "crew")
        monkeypatch.setattr(setup_mod, "_kirocrew_bin", lambda: "kirocrew")
        (tmp_path / "crew").mkdir(parents=True, exist_ok=True)
        _seed_pinned_entry(tmp_path)
        return tmp_path

    def _cfg(self, home: Path) -> Path:
        return home / "crew" / "playwright-config.json"

    def test_extension_token_survives_a_mode_round_trip(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ):
        token_file = home / "crew" / "playwright-extension-token"
        token_file.write_text("operator-token")
        monkeypatch.setattr(setup_mod, "browser_mode_enabled", lambda: True)
        monkeypatch.setattr(setup_mod, "has_playwright_extension", lambda: False)
        register_playwright_proxy()
        monkeypatch.setattr(setup_mod, "has_playwright_extension", lambda: True)
        register_playwright_proxy()
        assert token_file.read_text() == "operator-token"

    def test_browser_engine_choice_survives_a_mode_round_trip(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ):
        setup_mod.set_browser_engine("firefox")
        monkeypatch.setattr(setup_mod, "browser_mode_enabled", lambda: True)
        monkeypatch.setattr(setup_mod, "has_playwright_extension", lambda: False)
        register_playwright_proxy()
        deregister_playwright_proxy()
        register_playwright_proxy()
        assert setup_mod.get_browser_engine() == "firefox"

    def test_engine_choice_is_honoured_by_config_regeneration(self, home: Path):
        setup_mod.set_browser_engine("webkit")
        setup_mod.generate_playwright_config()
        cfg = json.loads(self._cfg(home).read_text(encoding="utf-8"))
        assert cfg["browser"]["browserName"] == "webkit"
        # channel is chromium-only; firefox/webkit reject it.
        assert "channel" not in cfg["browser"]["launchOptions"]

    def test_storage_state_is_attached_only_when_present(self, home: Path):
        setup_mod.generate_playwright_config()
        cfg = json.loads(self._cfg(home).read_text(encoding="utf-8"))
        assert cfg["browser"]["contextOptions"] == {}

        (home / "crew" / "playwright-storage-state.json").write_text('{"cookies":[]}')
        setup_mod.generate_playwright_config()
        cfg = json.loads(self._cfg(home).read_text(encoding="utf-8"))
        assert cfg["browser"]["contextOptions"]["storageState"].endswith(
            "playwright-storage-state.json"
        )


class TestUpdateLifecycle:
    """`kirocrew setup` (which an update runs) purges stale entries, then registers.

    A user migrated from the predecessor has a canonical entry whose command is
    the dead binary. The purge is correct to remove it, but the operator's own
    fields on that entry are still valid.
    """

    @pytest.fixture()
    def home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(setup_mod, "config_dir", lambda: tmp_path / "crew")
        monkeypatch.setattr(setup_mod, "_kirocrew_bin", lambda: "kirocrew")
        monkeypatch.setattr(setup_mod, "get_extension_token", lambda: "tok")
        monkeypatch.setattr(setup_mod, "browser_mode_enabled", lambda: True)
        monkeypatch.setattr(setup_mod, "has_playwright_extension", lambda: True)
        # mcp_cleanup resolves its target at IMPORT time, so patching Path.home
        # is not enough: whenever another test imported the module first, the
        # purge would run against the real ~/.kiro/settings/mcp.json.
        monkeypatch.setattr(cleanup_mod, "_KIRO_MCP_JSON", _mcp_json(tmp_path))
        (tmp_path / "crew").mkdir(parents=True, exist_ok=True)
        return tmp_path

    def _seed_predecessor_entry(self, home: Path) -> None:
        path = _mcp_json(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        _CANONICAL: {
                            # Points at the dead predecessor runtime, so the purge
                            # is right to remove it -- the command is unusable.
                            "command": "/opt/MeshClaw/bin/meshclaw",
                            "args": ["mcp-playwright-proxy"],
                            "env": {"KIROCREW_PLAYWRIGHT_CMD": _PIN},
                            "timeout": 120000,
                        },
                        "other-mcp": {"command": "unrelated"},
                    }
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def test_purge_removes_the_dead_predecessor_entry(self, home: Path):
        self._seed_predecessor_entry(home)
        removed = cleanup_mod.clean_stale_managed_mcp()
        assert _CANONICAL in removed
        assert _read_entry(home) is None
        # A genuine user server is never collateral.
        data = json.loads(_mcp_json(home).read_text(encoding="utf-8"))
        assert data["mcpServers"]["other-mcp"] == {"command": "unrelated"}

    def test_operator_pin_survives_the_update_purge_then_register(self, home: Path):
        # The sequence cli_setup runs: clean_stale_managed_mcp() at :313, then
        # register_playwright_proxy() at :386.
        self._seed_predecessor_entry(home)
        cleanup_mod.clean_stale_managed_mcp()
        register_playwright_proxy()

        entry = _read_entry(home)
        assert entry is not None
        # The dead command is replaced -- that is the point of the purge.
        assert entry["command"] == "kirocrew"
        # The pin is the operator's, still valid, and the only reason a launcher
        # resolves on some hosts.
        assert entry.get("env", {}).get("KIROCREW_PLAYWRIGHT_CMD") == _PIN
        assert entry.get("timeout") == 120000

    def test_purge_does_not_stash_a_users_own_server(self, home: Path):
        # _invokes_meshclaw matches on command basename alone, so the purge can
        # remove a server Kiro Crew never authored. Its fields must not be
        # carried into the proxy sidecar and reappear on the proxy entry.
        path = _mcp_json(home)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "their-own-thing": {
                            "command": "/opt/MeshClaw/bin/meshclaw",
                            "args": ["something-else"],
                            "env": {"THEIR_SECRET": "x"},
                        }
                    }
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        assert "their-own-thing" in cleanup_mod.clean_stale_managed_mcp()
        assert not setup_mod._carryover_path().exists()

        register_playwright_proxy()
        assert "THEIR_SECRET" not in (_read_entry(home) or {}).get("env", {})


class TestCarryoverSemantics:
    """The stash exists only to survive one Browser-Mode round trip."""

    @pytest.fixture()
    def home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(setup_mod, "config_dir", lambda: tmp_path / "crew")
        monkeypatch.setattr(setup_mod, "_kirocrew_bin", lambda: "kirocrew")
        monkeypatch.setattr(setup_mod, "get_extension_token", lambda: "tok")
        monkeypatch.setattr(setup_mod, "browser_mode_enabled", lambda: True)
        monkeypatch.setattr(setup_mod, "has_playwright_extension", lambda: True)
        _seed_pinned_entry(tmp_path)
        return tmp_path

    def test_token_is_not_copied_into_the_stash(self, home: Path):
        deregister_playwright_proxy()
        stash = json.loads(setup_mod._carryover_path().read_text(encoding="utf-8"))
        assert stash["env"]["KIROCREW_PLAYWRIGHT_CMD"] == _PIN
        # The token is re-minted per mode; duplicating it to a second file would
        # spread a credential for no benefit.
        assert "PLAYWRIGHT_MCP_EXTENSION_TOKEN" not in stash.get("env", {})

    def test_stash_is_consumed_once(self, home: Path):
        deregister_playwright_proxy()
        assert setup_mod._carryover_path().exists()
        register_playwright_proxy()
        assert not setup_mod._carryover_path().exists()

        # A second OFF/ON with nothing operator-owned must not resurrect the pin.
        path = _mcp_json(home)
        data = json.loads(path.read_text(encoding="utf-8"))
        entry = data["mcpServers"][_CANONICAL]
        entry.pop("env", None)
        entry.pop("timeout", None)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        deregister_playwright_proxy()
        register_playwright_proxy()
        assert "KIROCREW_PLAYWRIGHT_CMD" not in (_read_entry(home) or {}).get("env", {})

    def test_user_owned_entry_is_never_stashed(self, home: Path):
        # deregister leaves a user's own non-proxy server alone, so there is
        # nothing of theirs to carry and nothing to copy out of their config.
        path = _mcp_json(home)
        path.write_text(
            json.dumps(
                {"mcpServers": {_CANONICAL: {"command": "their-own", "env": {"SECRET": "x"}}}},
                indent=2,
            ),
            encoding="utf-8",
        )
        deregister_playwright_proxy()
        assert not setup_mod._carryover_path().exists()
        assert (_read_entry(home) or {})["command"] == "their-own"
