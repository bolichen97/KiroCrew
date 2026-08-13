"""Persisted record of the ``toolAliases`` pairs the alias pass itself emitted.

WHY A RECORD EXISTS
===================
The alias pass must clean up its OWN stale emissions: a renamed or withdrawn
registry declaration leaves a superseded ``@slug/tool -> alias`` pair behind in
the spec, and a rename that outlives its collision recreates the shadowing the
feature exists to remove. So cleanup needs to answer "did I write this pair?".

Answering it from the pair's SHAPE was tried three ways and each failed, because
shape asks about the present while ownership is a fact about the PAST:

* ``alias.startswith(f"{slug}_")`` claims a user's hand-written
  ``@linear/list_issues -> linear_issues``, so a rebuild deletes a deliberate
  edit.
* ``alias == f"{slug}_{tool}"`` (re-derivation) claims a user's hand-written
  ``@notion/search -> notion_search`` even though ``notion`` declares no aliases
  at all and this pass has never emitted anything for it. The shape of a name the
  pass WOULD emit is no evidence that it DID.
* Narrowing re-derivation to slugs that currently declare aliases reintroduces
  the first failure from the other side: a withdrawn declaration takes its slug
  out of the test, so the pair that declaration stranded stops being recognised
  as ours and becomes permanently unclearable.

Shape cannot decide history. This module persists the history instead: exactly
the ``(slug, tool, alias)`` triples the LAST pass emitted.

INVARIANTS
==========
1. **The record is the only ownership oracle.** A pair is this pass's own iff the
   record holds it. Absence proves nothing except "not provably ours", which is
   the safe reading -- an unrecorded pair is treated as the user's and survives.
   No shape rule, prefix test or re-derivation participates in the decision.

2. **The record AUTHORIZES deletion, so it must UNDERSTATE -- never overstate.**
   Ordering is therefore load-bearing, not incidental:

       load OLD record -> strip what it claims -> emit -> spec reaches disk
       -> write NEW record (equal to the just-emitted set)

   The record is written LAST, after the spec is durable, via
   :func:`~kiro_crew.atomic_write.atomic_write`. A crash in the window between
   the spec write and the record write leaves an alias that is emitted but
   unrecorded: never claimable, so it lingers for one cycle and is cleaned once a
   later pass records it. That is the safe failure.

   The reverse order is unsafe in a way no test of the happy path would show: it
   records a pair that never reached the spec, and a user who later hand-writes
   that exact name has it silently deleted -- the very ownership bug the record
   exists to fix, resurrected through a crash boundary.

3. **Membership IS the byte-equality test.** The alias is part of the key, so a
   pair is claimed only when the spec's CURRENT value matches the recorded form
   byte for byte. A user who edits a generated alias produces a triple the record
   does not hold, so their edit is left alone; no separate comparison is needed
   and none may be added, or the two checks could disagree.

4. **A missing, unreadable or malformed record is EMPTY, and empty claims
   NOTHING.** Losing the record degrades to "every pair is the user's": stale
   aliases linger (shadowing, the pre-feature behaviour) rather than a user's
   entries being deleted on a bad parse. Individual entries that are not three
   strings are dropped for the same reason -- dropping understates.

5. **Writing the record must never fail a rebuild.** It is bookkeeping for the
   NEXT pass; an unwritable data home costs one cycle of cleanup, while raising
   here would break the path that installs and repairs the agent spec.

The record is process-wide rather than per-spec because
:func:`~kiro_crew.agent.rebuild_agent_config` writes one canonical spec, and that
pass is the only emitter.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Collection, Mapping
from pathlib import Path

from kiro_crew.atomic_write import atomic_write
from kiro_crew.config.paths import config_dir

logger = logging.getLogger(__name__)

# A single emitted pair: the provider slug, the declared source tool, and the
# alias that was written for it.
EmittedAlias = tuple[str, str, str]

# Sidecar under the KiroCrew data home. kiro-cli validates agent specs with
# ``deny_unknown_fields``, so an in-spec ownership marker is impossible -- the
# record lives out of band in a directory KiroCrew owns outright, mirroring the
# ``owned-mcp-keys.json`` manifest that answers the same question for MCP server
# keys (see :mod:`kiro_crew.browser.setup`).
_RECORD_FILENAME = "connections-tool-aliases.json"

# Bumped only if the on-disk shape changes incompatibly. An unrecognised version
# reads as empty (invariant 4), which is why no migration path is needed: the
# cost of a version the reader does not understand is one cycle of cleanup.
_RECORD_VERSION = 1


def record_path() -> Path:
    """Path of the emitted-alias record sidecar."""
    return config_dir() / _RECORD_FILENAME


def split_tool_ref(ref: object) -> tuple[str, str] | None:
    """Split ``"@slug/tool"`` into ``(slug, tool)``, or None if it is not one.

    Rejects a whole-server ref (``@linear``), a missing ``@`` and an empty half:
    none of those name a single tool, so none can be a recorded emission.
    """
    if not isinstance(ref, str) or not ref.startswith("@") or "/" not in ref:
        return None
    slug, _, tool = ref[1:].partition("/")
    return (slug, tool) if slug and tool else None


def emitted_from_alias_map(aliases: Mapping[str, str]) -> frozenset[EmittedAlias]:
    """Convert a written ``{"@slug/tool": alias}`` map into record triples."""
    triples: set[EmittedAlias] = set()
    for ref, alias in aliases.items():
        parts = split_tool_ref(ref)
        if parts is not None and isinstance(alias, str):
            triples.add((parts[0], parts[1], alias))
    return frozenset(triples)


def load_emitted_aliases() -> frozenset[EmittedAlias]:
    """Return the triples the last pass recorded emitting.

    Empty on every failure -- absent file, unreadable file, malformed JSON,
    unexpected shape, unknown version (invariant 4). Empty claims nothing, so a
    lost record costs a cycle of cleanup and never a user's alias.
    """
    try:
        raw = record_path().read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Ignoring malformed Connections alias record", exc_info=True)
        return frozenset()
    if not isinstance(data, dict) or data.get("version") != _RECORD_VERSION:
        return frozenset()
    entries = data.get("emitted")
    if not isinstance(entries, list):
        return frozenset()

    triples: set[EmittedAlias] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        slug, tool, alias = entry.get("slug"), entry.get("tool"), entry.get("alias")
        if isinstance(slug, str) and isinstance(tool, str) and isinstance(alias, str):
            triples.add((slug, tool, alias))
    return frozenset(triples)


def store_emitted_aliases(emitted: Collection[EmittedAlias]) -> None:
    """Record *emitted* as exactly what the pass just wrote.

    Call only AFTER the spec carrying those aliases is durable (invariant 2), and
    call it even when *emitted* is EMPTY: an emptied record is how the pass
    relinquishes pairs it no longer writes. Skipping the empty write would leave a
    superseded triple claimable forever, so a user who later hand-writes that name
    would have it deleted.

    Best-effort by invariant 5: any failure is logged and swallowed.
    """
    payload = {
        "version": _RECORD_VERSION,
        "emitted": [
            {"slug": slug, "tool": tool, "alias": alias}
            for slug, tool, alias in sorted(emitted)
        ],
    }
    try:
        path = record_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, json.dumps(payload, indent=2) + "\n", mode=0o600)
    except OSError:
        logger.warning("Could not persist the Connections alias record", exc_info=True)


def is_recorded_emission(
    record: Collection[EmittedAlias], ref: object, alias: object
) -> bool:
    """True when the record proves THIS pass wrote ``(ref, alias)``.

    The whole triple must be present, so the recorded alias doubles as the
    byte-equality test on the spec's current value (invariant 3).
    """
    parts = split_tool_ref(ref)
    if parts is None or not isinstance(alias, str):
        return False
    return (parts[0], parts[1], alias) in record
