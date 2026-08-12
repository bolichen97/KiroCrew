"""Neutralise credential material in a bundle that is about to leave the host.

An off-host copy crosses a trust boundary the local archive does not: it lands in object
storage, and every principal that can read the bucket can read it. This module rewrites a
STAGED COPY of a bundle so the bytes that leave carry no usable credentials, and it is the
only place in the backup path that does so.

**It is lossy on purpose, and the loss is the point.** A redacted bundle restores to a
working shape but not to a working credential: the token field is present and inert, so the
operator re-enters it rather than discovering an empty file. That tradeoff is a deliberate
product decision, and `backup.redact_uploads` exists to reverse it for an operator who
would rather have a bundle that restores complete.

Two properties make the difference between a redacted bundle and a broken one:

* **Structure survives.** The redactors substitute a tag for a match, so they CHANGE
  LENGTH. Running them over the bytes of a SQLite file does not produce a database with
  dead credentials, it produces a file SQLite cannot open — which the restore path then
  correctly refuses as corrupt. Databases are therefore redacted through SQL, value by
  value, so what is written back is still a database.
* **The bundle says so.** The manifest records that this copy was redacted and what was
  touched, so a restore can tell the operator their credentials are inert instead of
  letting them find out when something fails to authenticate.
"""

from __future__ import annotations

import json
import shutil
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from kiro_crew.security import redact_credentials, redact_exfiltration_urls

try:  # pragma: no cover - exercised by whichever binding is installed
    import pysqlite3 as sqlite3  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    import sqlite3  # type: ignore[no-redef]

# Suffixes read as text. Everything else is either a database (handled through SQL) or
# opaque bytes, and guessing at an unknown binary format is how a bundle gets corrupted.
# Whether a file is text is decided by DECODING it, not by its name. A workspace holds
# whatever the operator put there — source files, csv, html, notes with no extension — and
# a suffix allowlist silently classified all of those as opaque.

# Files whose whole purpose is to be secret. There is no redacted form of a key that is
# still the key, so they are DROPPED from an outbound copy rather than blanked: a present
# but inert HMAC key would be indistinguishable from a rotated one.
# Bundle-RELATIVE paths, not basenames. A workspace holds whatever the operator put
# there, so matching on a bare name would delete their own `telemetry_salt` or
# `memory_index.db` from the off-host copy and make a restore quietly incomplete. These
# are the product's own files, and the product puts them at the bundle root.
_DROP_ENTIRELY = frozenset({"telemetry_salt", "sel_hmac.key"})

# Derived indexes. An FTS index mirrors content that is itself being redacted, so redacting
# it row by row would leave the index disagreeing with the table it indexes. Restore already
# handles an absent index by telling the operator to rebuild it, so absence is the honest
# state and the existing path carries it.
_DERIVED_INDEXES = frozenset({"memory_index.db"})

# Databases the product itself ships, by bundle-relative path. Only these may be DROPPED
# when they cannot be proven redacted: their absence is a state restore already reports.
# Any other `.db` is the operator's, so an unprovable one refuses the upload instead.
# A settled database needs two passes (one to clean, one to prove nothing moved). The
# rest of the budget is for chained triggers; past it, the database is not settling.
_MAX_SETTLE_PASSES = 10

_PRODUCT_DATABASES = frozenset({"memory.db", "workspace/knowledge/knowledge.db"})


class _SchemaCarriesCredential(Exception):
    """A credential sits in the schema itself, where no value rewrite can reach it.

    Rows can be rewritten in place. DDL cannot: changing it means rebuilding the object
    or enabling `writable_schema`, which risks leaving a file SQLite will not open. So a
    database in this state is one the pass cannot clean, and it is handled as such.
    """


class _Unprovable(Exception):
    """A file that is not the product's own and cannot be proven free of credentials."""


class OpaqueFilesPresent(Exception):
    """Files that are not text, so the pass cannot show them free of credentials.

    Raised instead of deleting them: an operator's own file missing from a restore that
    reported success is worse than an upload that refuses and says which files to deal
    with. Public because the upload path reports it to the operator.
    """

    def __init__(self, paths: list[str]) -> None:
        self.paths = paths
        super().__init__(", ".join(paths))


class _FileUnreadable(OSError):
    """A file that cannot be read at all, so nothing about it can be established.

    An `OSError` so the upload path's IO handler reports it as a refusal instead of
    letting it escape as a traceback -- the pass cannot prove a file it never read.
    """


class _TableNotInspectable(Exception):
    """A table this pass cannot read row-by-row, so its database cannot be cleared."""


@dataclass
class RedactionReport:
    """What the pass changed, so the operator can judge it rather than trust it."""

    replacements: dict[str, int] = field(default_factory=dict)
    dropped: list[str] = field(default_factory=list)
    rebuilt_indexes: list[str] = field(default_factory=list)
    skipped_unreadable: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.replacements.values())

    def as_manifest_entry(self) -> dict[str, object]:
        return {
            "redacted": True,
            "replacements": dict(sorted(self.replacements.items())),
            "dropped": sorted(self.dropped),
            "indexes_needing_rebuild": sorted(self.rebuilt_indexes),
            "skipped_unreadable": sorted(self.skipped_unreadable),
        }


def _scrub(text: str) -> tuple[str, int]:
    """Both mandatory outbound redactors, in the order the rest of the repo applies them."""
    cleaned, cred_warnings = redact_credentials(text)
    cleaned, url_warnings = redact_exfiltration_urls(cleaned)
    return cleaned, len(cred_warnings) + len(url_warnings)


def _redact_text_file(path: Path, report: RedactionReport, rel: str) -> bool:
    """Redact *path* as UTF-8 text. Returns False when it is not text at all.

    A `UnicodeDecodeError` is the answer to "is this text", not a failure: the caller
    refuses the upload for those rather than removing the file.
    """
    try:
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    except OSError as e:
        raise _FileUnreadable(f"{rel}: {e}") from e
    cleaned, hits = _scrub(original)
    if hits:
        path.write_text(cleaned, encoding="utf-8")
        report.replacements[rel] = report.replacements.get(rel, 0) + hits
    return True


# The pure index internals. `_content` is deliberately NOT here: for a standard fts5 table
# it holds the indexed PLAINTEXT and has a rowid, so it must be scanned like any other
# table. These four hold only index structure and are regenerated by the rebuild.
_FTS_INDEX_SUFFIXES = ("data", "idx", "docsize", "config")


def _fts_layout(conn: "sqlite3.Connection") -> tuple[list[str], set[str]]:
    """The FTS virtual tables, and the tables the row scan must not touch.

    Shadow tables are FTS5's private storage. Two of them (`_config`, `_idx`) are
    `WITHOUT ROWID`, so a row scan cannot address them — and refusing the database on that
    basis would delete every knowledge library from the outbound copy, which is how a
    fail-closed rule turns into data loss.

    They are also DERIVED: `_data`, `_idx` and `_docsize` hold the inverted index, so a
    credential survives there as index structure even after the text it came from is
    cleaned. Skipping them is therefore not enough on its own — the index is REBUILT from
    the redacted content afterwards, which is what actually removes the term.

    Identified positively from each virtual table's own name, not by pattern-matching
    every table that happens to end in `_idx`.
    """
    fts: list[str] = []
    for name, sql in conn.execute(
        "SELECT name, sql FROM sqlite_schema WHERE type='table'"
    ).fetchall():
        if sql and "USING fts" in sql.replace("using fts", "USING fts"):
            fts.append(name)
    skip = {f"{v}_{suffix}" for v in fts for suffix in _FTS_INDEX_SUFFIXES}
    # The virtual tables themselves are skipped too. Writing through one is REFUSED for an
    # external-content table (`content=items`), which is the shape this product actually
    # uses, and redundant for a standard one whose text is in `_content`. Redacting the
    # table that owns the text and rebuilding from it works for both, with no dependence
    # on which table the scan reaches first.
    skip.update(fts)
    return fts, skip


def _refuse_credential_in_schema(conn: sqlite3.Connection, rel: str) -> None:
    """A row scan never sees the DDL, and a credential can be written into it.

    A column DEFAULT, a VIEW's select list and a TRIGGER body are all stored as schema
    text, so a key placed in any of them survives a pass that only rewrites values.
    """
    for (sql,) in conn.execute(
        "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL"
    ).fetchall():
        _, hits = _scrub(str(sql))
        if hits:
            raise _SchemaCarriesCredential(rel)


def _redact_database(
    path: Path, report: RedactionReport, rel: str, *, product: bool
) -> None:
    """Rewrite credential-bearing VALUES in place, leaving a valid database behind.

    Every column is read and the decision is made on the VALUE's type, not the column's
    declared one. SQLite affinity is advisory — a column declared `BLOB`, or declared with
    no type at all, holds a Python `str` perfectly well — so filtering on the declaration
    would skip exactly the places a credential is least expected and most likely to sit.
    A value is written back only when it changed, so an untouched database keeps its pages.
    """
    try:
        with closing(sqlite3.connect(str(path))) as conn:
            _refuse_credential_in_schema(conn, rel)
            fts_tables, skip_tables = _fts_layout(conn)
            tables = [
                r[0]
                for r in conn.execute(
                    # `sqlite_schema` is the current name for the schema table, and the
                    # one this codebase already queries elsewhere.
                    "SELECT name FROM sqlite_schema WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            ]
            hits = 0
            # Scanned to a FIXPOINT rather than once. An UPDATE fires this database's
            # triggers, and a trigger can copy the pre-update value somewhere the scan
            # has already been — so one pass can leave a credential behind in a table it
            # already cleaned. Each pass reports its own replacements; zero means nothing
            # moved and the database is settled. Refusing all triggers instead would
            # reject the product's own full-text schema, which is maintained by them.
            for _ in range(_MAX_SETTLE_PASSES):
                pass_hits = 0
                for table in tables:
                    if table in skip_tables:
                        # FTS5's private storage: derived from the content table, regenerated
                        # by the rebuild below. Two of these have no rowid, so scanning them
                        # is impossible as well as pointless.
                        continue
                    cols = [
                        r[1] for r in conn.execute(f'PRAGMA table_info("{table}")').fetchall()
                    ]
                    if not cols:
                        # No enumerable columns means no way to read the table's values, which
                        # is the same position as a missing rowid: uninspectable, so refused.
                        raise _TableNotInspectable(f"{table}: no readable columns")
                    quoted = ", ".join(f'"{c}"' for c in cols)
                    # rowid is the update handle. A `WITHOUT ROWID` table has none and raises
                    # here — and a table this pass cannot inspect cannot be shown free of
                    # credentials, so the DATABASE is dropped rather than the table skipped.
                    # Skipping would upload the very rows the pass exists to clean, which is
                    # the one outcome this module must never produce.
                    try:
                        rows = conn.execute(
                            f'SELECT rowid, {quoted} FROM "{table}"'
                        ).fetchall()
                    except sqlite3.DatabaseError as e:
                        raise _TableNotInspectable(f"{table}: {e}") from e
                    for row in rows:
                        rowid, values = row[0], row[1:]
                        changes: dict[str, str | bytes] = {}
                        for col, value in zip(cols, values):
                            if not value:
                                continue
                            cleaned: str | bytes
                            if isinstance(value, str):
                                cleaned, n = _scrub(value)
                            elif isinstance(value, (bytes, bytearray)):
                                # A column's declared type does not decide what it holds, so a
                                # credential can arrive as bytes. latin-1 maps every byte to a
                                # codepoint and back without loss, so the patterns (ASCII) match
                                # inside binary too and a value with no hit is never rewritten —
                                # which is what keeps embeddings and other real blobs intact.
                                text, n = _scrub(bytes(value).decode("latin-1"))
                                cleaned = text.encode("latin-1")
                            else:
                                continue  # numbers and NULL carry no credential text
                            if n:
                                changes[col] = cleaned
                                pass_hits += n
                        if changes:
                            assignments = ", ".join(f'"{c}" = ?' for c in changes)
                            conn.execute(
                                f'UPDATE "{table}" SET {assignments} WHERE rowid = ?',
                                (*changes.values(), rowid),
                            )
                hits += pass_hits
                if not pass_hits:
                    break
            else:
                # Still moving after the cap: a trigger is feeding the scan faster than
                # it cleans. Unprovable, so it is handled as such rather than shipped.
                raise _TableNotInspectable(
                    "redaction did not settle; a trigger keeps reintroducing values"
                )
            if hits:
                for virtual in fts_tables:
                    # Regenerates `_data` / `_idx` / `_docsize` from the cleaned rows. A
                    # redacted content table with a stale index still answers a search
                    # for the credential, so this is part of the redaction, not tidying.
                    conn.execute(
                        f'INSERT INTO "{virtual}"("{virtual}") VALUES(\'rebuild\')'
                    )
                conn.commit()
                report.replacements[rel] = report.replacements.get(rel, 0) + hits
                if fts_tables:
                    report.rebuilt_indexes.extend(f"{rel}:{v}" for v in fts_tables)
    except (sqlite3.DatabaseError, _TableNotInspectable, _SchemaCarriesCredential) as e:
        # Shipping it is never an option: a database this pass cannot read end to end
        # cannot be proven redacted, whether the cause is corruption or a table it cannot
        # address. What differs is who owns the file. The product's own databases are
        # dropped, a state restore reports. Anyone else's is kept and the upload refuses,
        # because deleting an operator's file to protect them from it is not a trade this
        # module gets to make.
        report.skipped_unreadable.append(f"{rel} ({e})")
        if not product:
            raise _Unprovable(rel) from e
        path.unlink(missing_ok=True)
        report.dropped.append(rel)


def redact_bundle_for_egress(stage: Path) -> RedactionReport:
    """Redact a staged bundle IN PLACE. *stage* must be a throwaway copy, never the original.

    Walks the staged tree rather than a declared file list: what leaves the host is exactly
    what is on disk here, so the walk and the payload cannot disagree.
    """
    report = RedactionReport()
    opaque: list[str] = []
    for path in sorted(p for p in stage.rglob("*") if p.is_file()):
        rel = path.relative_to(stage).as_posix()
        name = path.name
        if _scrub(rel)[1]:
            # The archive stores its member names, so a credential written into a PATH
            # leaves the host even when every byte of content is clean. Renaming is not
            # the answer — the restore would then produce a file the operator never had —
            # so the upload refuses and names it.
            opaque.append(rel)
            continue
        if name == "MANIFEST.json":
            continue  # rewritten by the caller once the report is known
        if rel in _DROP_ENTIRELY:
            path.unlink()
            report.dropped.append(rel)
            continue
        if rel in _DERIVED_INDEXES:
            path.unlink()
            report.dropped.append(rel)
            report.rebuilt_indexes.append(rel)
            continue
        if path.suffix == ".db":
            try:
                _redact_database(path, report, rel, product=rel in _PRODUCT_DATABASES)
            except _Unprovable:
                # Not a product database and not provably clean — commonly a `.db` that
                # is not SQLite at all. Refused rather than removed, for the same reason
                # an opaque file is.
                opaque.append(rel)
            continue
        if _redact_text_file(path, report, rel):
            continue
        # Genuinely not text: the redactors work on strings, so this file cannot be shown
        # free of credentials. It is neither redacted nor deleted — deleting an operator's
        # file would make a restore quietly incomplete, so the UPLOAD is refused and the
        # file is named, leaving the choice with the person whose data it is.
        opaque.append(rel)
    if opaque:
        # Reported together so the operator sees the whole list, not the first offender.
        raise OpaqueFilesPresent(opaque)
    _stamp_manifest(stage, report)
    # LAST, because the stamp itself writes paths and error text into the manifest. The
    # manifest is the one file guaranteed to leave the host, so leaving it unscanned put
    # the only certain payload outside the pass.
    _redact_manifest(stage, report)
    return report


def _redact_manifest(stage: Path, report: RedactionReport) -> None:
    """Scrub the manifest after it is stamped, and prove it is still readable.

    The replacement tag carries no quote or backslash, so a scrubbed JSON string stays
    valid — but that is a property of the tag, not a guarantee, so it is checked instead
    of assumed. A manifest that no longer parses would make the bundle unrestorable.
    """
    mf = stage / "MANIFEST.json"
    if not mf.is_file():
        return
    try:
        original = mf.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise _Unprovable(f"MANIFEST.json: {e}") from e
    cleaned, hits = _scrub(original)
    if not hits:
        return
    try:
        json.loads(cleaned)
    except ValueError as e:
        raise _Unprovable(f"MANIFEST.json would not survive redaction: {e}") from e
    mf.write_text(cleaned, encoding="utf-8")
    report.replacements["MANIFEST.json"] = (
        report.replacements.get("MANIFEST.json", 0) + hits
    )


def _stamp_manifest(stage: Path, report: RedactionReport) -> None:
    """Record the redaction in the manifest so a restore can say what it is holding."""
    mf = stage / "MANIFEST.json"
    if not mf.is_file():
        return
    try:
        data = json.loads(mf.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    data["redaction"] = report.as_manifest_entry()
    mf.write_text(json.dumps(data, indent=2), encoding="utf-8")


def stage_redacted_copy(source_stage: Path, dest: Path) -> RedactionReport:
    """Copy *source_stage* to *dest* and redact the copy, never the original."""
    shutil.copytree(source_stage, dest)
    return redact_bundle_for_egress(dest)
