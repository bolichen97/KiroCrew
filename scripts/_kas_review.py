"""Apply the five review findings on PR #3196.

1. BLOCKING — load() enumerates every AgentConfig field explicitly, so the two
   new ones were dropped on load and overwritten on save.
2. FINDING — the two keys were absent from _EDITABLE_CONFIG, so the dashboard
   controls got HTTP 400 and never saved.
3. FINDING — _is_kas_direct omitted _KAS_ROOT_ENV, which the resolver and the
   spec both document as a direct-path trigger.
4. FINDING — the acp.types import was function-local (top-level-imports rule).
"""

from __future__ import annotations

import pathlib

LOADER_EDITS = [
    # 1. Wire the load path.
    (
        '                provider=agent_data.get("provider", "acp"),\n'
        '                default_agent=agent_data.get("default_agent", ""),',
        '                provider=agent_data.get("provider", "acp"),\n'
        "                acp_backend=(\n"
        '                    ACP_BACKEND_KAS\n'
        '                    if agent_data.get("acp_backend") == ACP_BACKEND_KAS\n'
        "                    else ACP_BACKEND_KIRO_CLI\n"
        "                ),\n"
        '                kas_path=str(agent_data.get("kas_path", "") or ""),\n'
        '                default_agent=agent_data.get("default_agent", ""),',
    ),
    # 4. Hoist the import that was function-local.
    (
        "        from kiro_crew.acp.types import ACP_BACKEND_KAS\n"
        "        from kiro_crew.providers.acp import (\n"
        "            AcpProvider,  # circular: acp -> client -> session -> config.loader\n"
        "        )",
        "        from kiro_crew.providers.acp import (\n"
        "            AcpProvider,  # circular: acp -> client -> session -> config.loader\n"
        "        )",
    ),
]

CLIENT_EDITS = [
    # 3. KIROCREW_KAS_ROOT is a documented trigger; honour it in the predicate.
    (
        "        if self._kas_path.strip():\n"
        "            return True\n"
        '        return any(os.environ.get(name, "").strip() for name in _KAS_ENTRY_ENVS)',
        "        if self._kas_path.strip():\n"
        "            return True\n"
        "        # Every env var the resolver accepts must also SELECT this path, or an\n"
        "        # operator who exports only the root var silently gets the CLI's\n"
        "        # embedded KAS instead of the build they named.\n"
        '        return any(\n'
        '            os.environ.get(name, "").strip()\n'
        "            for name in (*_KAS_ENTRY_ENVS, _KAS_ROOT_ENV)\n"
        "        )",
    ),
]


def apply(rel: str, edits: list[tuple[str, str]]) -> None:
    p = pathlib.Path(rel)
    s = p.read_text(encoding="utf-8")
    for old, new in edits:
        found = s.count(old)
        if found != 1:
            raise SystemExit(f"{rel}: expected 1 match, got {found}: {old[:60]!r}")
        s = s.replace(old, new)
    p.write_text(s, encoding="utf-8")
    print(f"{rel}: {len(edits)} edits applied")


def add_top_level_import() -> None:
    """Put ACP_BACKEND_* on loader.py's module imports."""
    p = pathlib.Path("src/kiro_crew/config/loader.py")
    s = p.read_text(encoding="utf-8")
    anchor = "from kiro_crew.acp.types import "
    if anchor in s:
        raise SystemExit("loader.py already imports from acp.types at module level")
    # Anchor on an existing first-party import block member.
    needle = "from kiro_crew.atomic_write import atomic_write\n"
    if s.count(needle) != 1:
        raise SystemExit(f"anchor import not found exactly once: {needle!r}")
    s = s.replace(
        needle,
        "from kiro_crew.acp.types import ACP_BACKEND_KAS, ACP_BACKEND_KIRO_CLI\n" + needle,
    )
    p.write_text(s, encoding="utf-8")
    print("loader.py: top-level acp.types import added")


def main() -> None:
    add_top_level_import()
    apply("src/kiro_crew/config/loader.py", LOADER_EDITS)
    apply("src/kiro_crew/acp/client.py", CLIENT_EDITS)


if __name__ == "__main__":
    main()
