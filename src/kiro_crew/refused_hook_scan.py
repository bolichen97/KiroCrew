"""Which installed hooks the shell deny-list will refuse, before any of them fires.

``run_script_hook`` vets a hook's command against the shell deny-list and refuses
it without running (:func:`kiro_crew.hooks.hook_command_deny_reason`). A hook that
matches a rule therefore never runs, and nothing says so until its event fires.
This module asks the same question ahead of time for every hook a host has:

* each installed agent spec's own ``hooks``, converted the way the turn loop
  converts them (:func:`kiro_crew.agent_sdk.spec_hooks.spec_script_hooks`). Kiro Crew
  fires those only on the harnesses in ``ACP_BACKENDS_CREW_FIRES_SPEC_HOOKS``; on
  kiro-cli, kiro-cli runs a spec's hooks itself and this vet does not apply;
* each enabled hook on the Hooks page (``hooks.json``), which Kiro Crew fires on
  every harness.

``kirocrew doctor`` prints the findings, and the gateway logs them once per
process after it starts serving. Reporting only: nothing here changes whether a
hook runs.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

#: ``RefusedHook.owner`` for a hook stored on the Hooks page rather than in a spec.
HOOKS_PAGE_OWNER = ""

_warned_lock = threading.Lock()
_warned = False


@dataclass(frozen=True)
class RefusedHook:
    """One hook the deny-list refuses. ``owner`` is the agent name, or
    :data:`HOOKS_PAGE_OWNER` for a Hooks-page hook. ``owner``, ``name`` and
    ``reason`` are redacted, but they come from user-writable files, so a caller
    escapes them for display. No field carries the hook's command."""

    owner: str
    event: str
    name: str
    reason: str


@dataclass
class RefusedHookScan:
    """The scan's findings. ``unreadable`` names the spec files whose hooks could
    not be read, so a caller can say the check is incomplete; ``error`` is set
    when the deny check itself could not run, and then ``refused`` is empty."""

    refused: list[RefusedHook] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    error: str = ""


def crew_fired_spec_hook_backends() -> tuple[str, ...]:
    """The harness ids on which Kiro Crew fires a spec's own hooks, sorted."""
    from kiro_crew.agent_sdk.backends_routing import ACP_BACKENDS_CREW_FIRES_SPEC_HOOKS

    return tuple(sorted(ACP_BACKENDS_CREW_FIRES_SPEC_HOOKS))


def _default_spec_dirs() -> list[Path]:
    from kiro_crew.config.paths import kiro_agents_dir, mate_agents_dir

    return [kiro_agents_dir(), mate_agents_dir()]


def _spec_files(directory: Path) -> list[Path]:
    from kiro_crew.agent_spec_format import is_agent_spec_name

    try:
        return sorted(
            path
            for path in directory.iterdir()
            if is_agent_spec_name(path.name) and not path.name.startswith("._")
        )
    except (FileNotFoundError, NotADirectoryError):
        return []


def scan_refused_hooks(
    *,
    spec_dirs: list[Path] | None = None,
    hooks_config_dir: Path | None = None,
) -> RefusedHookScan:
    """Every installed hook the shell deny-list refuses.

    The spec reader's SEL label names this scan with source ``unknown``, since
    doctor and the gateway both run it. *spec_dirs*
    defaults to the user-level and crewmate agent folders; *hooks_config_dir* to
    the data home that holds ``hooks.json``. A spec that cannot be read or
    converted is listed in ``unreadable`` and the scan goes on. Blocking: it reads
    files and runs the deny check, so a caller on the event loop offloads it.
    """
    from kiro_crew.agent_discovery import _read_agent_spec
    from kiro_crew.agent_sdk.spec_hooks import spec_script_hooks
    from kiro_crew.hooks import ScriptHookStore, redact_via_context, refused_script_hooks

    scan = RefusedHookScan()
    seen: set[Path] = set()
    try:
        for directory in spec_dirs if spec_dirs is not None else _default_spec_dirs():
            for path in _spec_files(directory):
                if path in seen:
                    continue
                seen.add(path)
                try:
                    data = _read_agent_spec(path, operation="refused_hook_scan", source="unknown")
                    if data is None:
                        scan.unreadable.append(path.name)
                        continue
                    raw_name = data.get("name")
                    agent = raw_name if isinstance(raw_name, str) and raw_name else path.stem
                    hooks = spec_script_hooks(agent, data)
                except Exception:  # noqa: BLE001 -- one broken spec must not hide the rest
                    logger.debug("refused-hook scan: spec %s unreadable", path, exc_info=True)
                    scan.unreadable.append(path.name)
                    continue
                for name, event, reason in refused_script_hooks(hooks):
                    scan.refused.append(
                        RefusedHook(
                            redact_via_context(agent), event, redact_via_context(name), reason
                        )
                    )
        stored = ScriptHookStore(hooks_config_dir).list_all()
        for name, event, reason in refused_script_hooks([h for h in stored if h.enabled]):
            scan.refused.append(
                RefusedHook(HOOKS_PAGE_OWNER, event, redact_via_context(name), reason)
            )
    except Exception as exc:  # noqa: BLE001 -- the deny check itself could not run
        logger.debug("refused-hook scan failed", exc_info=True)
        return RefusedHookScan(unreadable=scan.unreadable, error=type(exc).__name__)
    return scan


def warn_refused_hooks_once() -> None:
    """Log the scan's findings as one warning, at most once per process.

    For the gateway's start: a host whose hooks matched a rule after an upgrade
    sees which ones in its log rather than at the first event. Blocking, like
    :func:`scan_refused_hooks`; silent when nothing is refused.
    """
    global _warned
    with _warned_lock:
        if _warned:
            return
        _warned = True
    scan = scan_refused_hooks()
    if not scan.refused:
        return
    lines = [
        f"{len(scan.refused)} hook(s) will be refused by the security policy and will not run "
        f"(spec hooks only where Kiro Crew runs them: {', '.join(crew_fired_spec_hook_backends())}; "
        "run `kirocrew doctor` for details):"
    ]
    for hook in scan.refused:
        owner = f"agent {hook.owner!r}" if hook.owner else "Hooks page"
        lines.append(f"  {owner}, {hook.event!r}, hook {hook.name!r}: {hook.reason[:500]!r}")
    logger.warning("\n".join(lines))
