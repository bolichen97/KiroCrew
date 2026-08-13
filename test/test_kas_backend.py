"""KAS (Kiro Agent Server) backend selection.

Two paths reach KAS and they must not be confused. The DEFAULT one selects
kiro-cli's v3 engine, so Kiro Crew still talks to the CLI and the handshake is
unchanged. The OPTIONAL one spawns a locally-built KAS directly, which is a bare
Node process speaking KAS's own numeric protocol version. Tests here pin which
path is chosen, and the flags a direct spawn cannot omit.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from kiro_crew import platform_compat
from kiro_crew.acp.client import (
    _KAS_ENTRY_ENVS,
    _KAS_NODE_ENV,
    _KAS_ROOT_ENV,
    KIRO_CLI_KAS_ENGINE_ARG,
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_CLAUDE,
    PROTOCOL_VERSION_KAS,
    AcpClient,
    _resolve_kas_acp_bin,
)
from kiro_crew.acp.types import (
    ACP_BACKEND_CLAUDE,
    ACP_BACKEND_KAS,
    ACP_BACKEND_KIRO_CLI,
)
from kiro_crew.config.loader import AgentConfig


def _make_build(root: Path, *, bundled_node: bool = False) -> Path:
    """Lay down the entry script a KAS build exposes, and optionally its Node.

    The interpreter is named for the HOST platform, because that is what a real
    extracted bundle carries and what the resolver looks for: Windows has no
    execute bit and accepts only known extensions, so a bare `node` there would
    be invisible to `is_executable_file`.
    """
    entry = root / "packages" / "kiro-agent" / "dist" / "server" / "acp-server.js"
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text("// fake KAS entry\n", encoding="utf-8")
    if bundled_node:
        node = _bundled_node_path(root)
        node.parent.mkdir(parents=True, exist_ok=True)
        node.write_text("#!/bin/sh\n", encoding="utf-8")
        if not platform_compat.IS_WINDOWS:
            node.chmod(node.stat().st_mode | stat.S_IXUSR)
    return entry


def _bundled_node_path(root: Path) -> Path:
    """Where a real extracted bundle puts its pinned interpreter on this host."""
    name = "node.exe" if platform_compat.IS_WINDOWS else "node"
    return root / ".node" / "bin" / name


@pytest.fixture(autouse=True)
def _clear_kas_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every override reads the ambient environment; never inherit the host's."""
    for name in (*_KAS_ENTRY_ENVS, _KAS_ROOT_ENV, _KAS_NODE_ENV):
        monkeypatch.delenv(name, raising=False)


def _client(backend: str = "", kas_path: str = "") -> AcpClient:
    return AcpClient(
        work_dir=Path("/tmp/kas-backend-test"), acp_backend=backend, kas_path=kas_path
    )


class TestPathSelection:
    """Which of the two KAS paths a session takes."""

    def test_kas_without_a_local_build_uses_the_cli_engine(self) -> None:
        c = _client(ACP_BACKEND_KAS)
        assert c._is_kas is True
        # No install required: kiro-cli ships KAS, so the default must NOT be the
        # direct spawn that needs an operator-supplied build.
        assert c._is_kas_direct is False

    def test_configured_path_switches_to_a_direct_spawn(self) -> None:
        c = _client(ACP_BACKEND_KAS, kas_path="/some/build")
        assert c._is_kas_direct is True

    def test_blank_configured_path_is_not_a_local_build(self) -> None:
        assert _client(ACP_BACKEND_KAS, kas_path="   ")._is_kas_direct is False

    @pytest.mark.parametrize("env_name", _KAS_ENTRY_ENVS)
    def test_entry_env_switches_to_a_direct_spawn(
        self, env_name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(env_name, "/some/acp-server.js")
        assert _client(ACP_BACKEND_KAS)._is_kas_direct is True

    def test_kas_path_is_inert_on_the_default_backend(self) -> None:
        c = _client("", kas_path="/some/build")
        assert c._is_kas is False
        assert c._is_kas_direct is False

    def test_the_cli_engine_path_is_still_the_cli(self) -> None:
        """The sandbox wrapper keys kiro-cli behaviour off this.

        Selecting the v3 engine does not change WHAT is spawned — it is still the
        CLI launcher — so treating it as a bare Node process would misconfigure
        the sandbox.
        """
        assert _client(ACP_BACKEND_KAS)._is_kiro_cli is True

    def test_a_direct_spawn_is_not_the_cli(self) -> None:
        assert _client(ACP_BACKEND_KAS, kas_path="/some/build")._is_kiro_cli is False

    def test_claude_is_unaffected(self) -> None:
        c = _client(ACP_BACKEND_CLAUDE)
        assert c._is_claude is True
        assert c._is_kas is False
        assert c._is_kas_direct is False
        assert c._is_kiro_cli is False


class TestProtocolVersion:
    def test_cli_engine_keeps_the_cli_handshake(self) -> None:
        """Kiro Crew talks to kiro-cli on this path, not to KAS.

        kiro-cli owns the inner KAS handshake, so sending KAS's numeric version
        outward would be wrong even though KAS is what ultimately runs.
        """
        assert isinstance(PROTOCOL_VERSION, str)

    def test_direct_spawn_uses_the_acp_sdk_numeric_version(self) -> None:
        # KAS echoes the client's value back without validating, so this is the
        # semantically correct value, not a negotiated one.
        assert PROTOCOL_VERSION_KAS == PROTOCOL_VERSION_CLAUDE == 1


class TestDirectSpawnResolution:
    def test_unresolvable_root_returns_none(self, tmp_path: Path) -> None:
        assert _resolve_kas_acp_bin(str(tmp_path / "nope")) is None

    def test_empty_root_returns_none(self) -> None:
        assert _resolve_kas_acp_bin("") is None

    def test_required_flags_are_present(self, tmp_path: Path) -> None:
        """The WASM flag is load-bearing, not a nicety.

        The policy engine's Cedar and tree-sitter grammars are WASM modules, so
        without it shell parsing fails at import rather than at spawn.
        """
        entry = _make_build(tmp_path)
        argv = _resolve_kas_acp_bin(str(tmp_path))
        assert argv is not None
        assert "--experimental-wasm-modules" in argv
        assert "--transport=stdio" in argv
        assert "--auth=acp-callback" in argv
        # Node flags precede the script; server args follow it.
        assert argv.index("--experimental-wasm-modules") < argv.index(str(entry))
        assert argv.index(str(entry)) < argv.index("--transport=stdio")

    def test_bundled_node_preferred_over_host(self, tmp_path: Path) -> None:
        """An extracted bundle's natives are built for ONE Node ABI.

        Running them under a mismatched host interpreter fails at module import,
        far from the cause, so the bundled interpreter must win.
        """
        _make_build(tmp_path, bundled_node=True)
        argv = _resolve_kas_acp_bin(str(tmp_path))
        assert argv is not None
        assert argv[0] == str(_bundled_node_path(tmp_path))

    def test_node_env_override_is_honoured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_build(tmp_path)
        monkeypatch.setenv(_KAS_NODE_ENV, "/custom/node")
        argv = _resolve_kas_acp_bin(str(tmp_path))
        assert argv is not None
        assert argv[0] == "/custom/node"

    def test_bundled_node_beats_the_env_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ABI constraint is not a preference the operator can lose to."""
        _make_build(tmp_path, bundled_node=True)
        monkeypatch.setenv(_KAS_NODE_ENV, "/custom/node")
        argv = _resolve_kas_acp_bin(str(tmp_path))
        assert argv is not None
        assert argv[0] == str(_bundled_node_path(tmp_path))

    @pytest.mark.parametrize("env_name", _KAS_ENTRY_ENVS)
    def test_entry_env_overrides_configured_root(
        self, env_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        configured = tmp_path / "configured"
        _make_build(configured)
        override = tmp_path / "elsewhere" / "acp-server.js"
        override.parent.mkdir(parents=True)
        override.write_text("// override\n", encoding="utf-8")
        monkeypatch.setenv(env_name, str(override))

        argv = _resolve_kas_acp_bin(str(configured))
        assert argv is not None
        assert str(override) in argv
        assert str(configured) not in " ".join(argv)

    def test_entry_env_pointing_at_nothing_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An explicit override that is wrong must not silently fall through.

        Falling back to the configured root would run a DIFFERENT build than the
        operator named, which is the one outcome worse than failing.
        """
        configured = tmp_path / "configured"
        _make_build(configured)
        monkeypatch.setenv(_KAS_ENTRY_ENVS[0], str(tmp_path / "missing.js"))
        assert _resolve_kas_acp_bin(str(configured)) is None

    def test_root_env_used_when_config_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entry = _make_build(tmp_path)
        monkeypatch.setenv(_KAS_ROOT_ENV, str(tmp_path))
        argv = _resolve_kas_acp_bin("")
        assert argv is not None
        assert str(entry) in argv

    def test_config_root_wins_over_root_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg_root = tmp_path / "from-config"
        env_root = tmp_path / "from-env"
        cfg_entry = _make_build(cfg_root)
        _make_build(env_root)
        monkeypatch.setenv(_KAS_ROOT_ENV, str(env_root))
        argv = _resolve_kas_acp_bin(str(cfg_root))
        assert argv is not None
        assert str(cfg_entry) in argv

    def test_user_home_is_expanded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_build(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        # Windows resolves ~ from USERPROFILE, so set both for parity.
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        argv = _resolve_kas_acp_bin("~")
        assert argv is not None
        assert any(str(tmp_path) in part for part in argv)

    def test_path_is_never_searched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """KAS ships no PATH-installed launcher, so a PATH hit is some other
        binary. Resolution stays operator-pointed."""
        fake = tmp_path / "bin" / "acp-server.js"
        fake.parent.mkdir(parents=True)
        fake.write_text("// not ours\n", encoding="utf-8")
        monkeypatch.setenv("PATH", str(fake.parent) + os.pathsep + os.environ.get("PATH", ""))
        assert _resolve_kas_acp_bin("") is None


class TestConfigPlumbing:
    def test_default_backend_is_kiro_cli(self) -> None:
        assert AgentConfig().acp_backend == ACP_BACKEND_KIRO_CLI
        assert AgentConfig().kas_path == ""

    def test_backend_enum_offers_both(self) -> None:
        fields = {f.name: f for f in AgentConfig.__dataclass_fields__.values()}
        assert fields["acp_backend"].metadata.get("enum") == [
            ACP_BACKEND_KIRO_CLI,
            ACP_BACKEND_KAS,
        ]

    def test_engine_arg_names_the_v3_engine(self) -> None:
        # kiro-cli spells its KAS engine "v3"; the arg is the whole contract
        # between the two tools, so pin it.
        assert KIRO_CLI_KAS_ENGINE_ARG == "--agent-engine=v3"
