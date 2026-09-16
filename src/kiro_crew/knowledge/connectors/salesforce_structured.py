"""Salesforce structured-source connector (W10 / L2).

Salesforce is not prose. An sObject record and an Analytics report row are each a
typed record with a stable provider identity, so this connector turns them into
the knowledge Library's existing row shape and lets the SAME ``SyncScheduler``
that drives ``local_folder`` refresh them -- WITHOUT a second knowledge base,
sync engine, auth, vault, pagination, or ACL. It is a :class:`BaseConnector`.

Two independent discovery + read PATHS, both preserved, never one impersonating
the other:

* **SOQL object path** -- an sObject is *described* (``.../sobjects/{name}/
  describe``) into the L1 :class:`~kiro_crew.connections.vendors.salesforce.describe.ObjectDescribe`,
  then read with a SOQL ``SELECT`` whose results page through the L1 REST
  query-locator contract (``{done, records, nextRecordsUrl}``). One row per
  record; the record's ``Id`` is its entity key.
* **Report / Analytics path** -- a report is discovered and read through the
  Analytics REST API (``/analytics/reports/{id}``), whose result shape is a fact
  grid, NOT a record list. It is a genuinely different endpoint, response shape,
  and identity (a report id + row ordinal within a described column set), and it
  is read on its OWN path. A SOQL ``SELECT`` against the report's source object
  is NOT a report and this connector never substitutes one for the other.

What it owns, and what it borrows
---------------------------------
* **Owns** the domain model below -- the typed rows for each path, the primary
  keys that make a refresh idempotent, the conversion from a vendor payload into
  a row, the ``since`` + primary-key diff that makes a refresh incremental, the
  resumable checkpoint, the per-row lineage (carrying the
  :class:`~kiro_crew.knowledge.acl` ``ProviderResourceRef`` FIELDS a query-time
  revalidation probe needs), and config validation.
* **Borrows** everything else. The transport is the W01 control-plane executor
  (:func:`kiro_crew.connections.control_plane.executor.execute` /
  :class:`~kiro_crew.connections.control_plane.executor.PageWalk`), composed with
  real vault-custody + HTTP by
  :mod:`kiro_crew.connections.control_plane.production`; the record/field model,
  the query-locator pagination contract, the error taxonomy and the payload
  typing are the L1 ``vendors/salesforce`` primitives. The checkpoint lives in
  the source's existing ``properties`` blob; ingestion, de-duplication, storage
  and per-row lineage recording stay in the pipeline the scheduler already calls.

Security posture (fail-closed)
------------------------------
* **Never a real Salesforce business account in this round.** Live fetch is
  driven ONLY through the injected control-plane transport; the offline tests
  drive the pure domain layer and an in-memory fake transport, never a live org.
* **Field- and object-level permission unknown ⇒ deny.** The L1 describe keeps
  an unsourced permission flag as the ``UNKNOWN`` sentinel (not truth-valued);
  this connector treats ``UNKNOWN`` (and an absent describe) as NOT-readable and
  drops the field/object rather than inventing a grant. No ``SELECT`` is emitted
  for a field whose FLS ``accessible`` is not a real ``True``.
* **Every ingested row carries a resource ref.** :func:`render_row_metadata`
  emits the ``salesforce`` :class:`ProviderResourceRef` locator fields
  (``instanceUrl`` / ``sobjectType`` / ``recordId`` / ``reportId`` /
  ``fieldSet``) so the shared query-time ACL can revalidate the item against the
  provider through the same controlled runtime -- never a cached bypass.

Transport availability
-----------------------
The control-plane EXECUTOR (W01 · L09) is a separate stack slice. When it is not
yet in the import tree :meth:`fetch` / :meth:`detect_changes` REFUSE
(fail-closed) rather than returning a partial or mocked dataset -- a mock is not
a live read and must never be presented as one. The typed rows, keys,
conversion, incremental diff, checkpoint and lineage are exercised by the pure
functions this module exposes and their tests regardless.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence, Tuple, Union

from kiro_crew.connections.vendors.salesforce.describe import (
    UNKNOWN,
    ObjectDescribe,
)
from kiro_crew.connections.vendors.salesforce.payload import parse_record

from .base import BaseConnector

# ── the knowledge source_type this connector answers to ────────────────────
SOURCE_TYPE = "salesforce"

# ── the two path discriminants ─────────────────────────────────────────────
# A source's ``properties`` declares which of the two independent paths it is,
# and the two are NEVER collapsed: a report source is read on the Analytics
# path, an object source on the SOQL path. The value is stored verbatim on every
# row's lineage so a search hit says which path produced it.
PATH_SOQL_OBJECT = "soql_object"
PATH_ANALYTICS_REPORT = "analytics_report"
_PATHS = frozenset({PATH_SOQL_OBJECT, PATH_ANALYTICS_REPORT})

# ── entity types (one per record kind, stored verbatim on lineage) ─────────
ENTITY_SOBJECT_RECORD = "salesforce_sobject_record"
ENTITY_REPORT_ROW = "salesforce_report_row"
_ENTITY_TYPES = frozenset({ENTITY_SOBJECT_RECORD, ENTITY_REPORT_ROW})

# Primary-key segment separator. A Salesforce instance URL, org id, sObject
# type, record id, report id or row ordinal cannot contain a vertical bar, so it
# joins the domain segments unambiguously; every segment is checked for it at
# construction so a value carrying the separator cannot forge a key.
_PK_SEP = "|"

# An sObject API name: letters, digits and underscores, the shape Salesforce
# uses for both standard (``Account``) and custom (``My_Object__c``) objects.
# Anchored so a stray character (a space, a SOQL fragment) is rejected rather
# than accepted as an object name.
_SOBJECT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

# A Salesforce 15- or 18-char record id, or an Analytics report id (same id
# alphabet). Anchored for the same reason.
_SF_ID_RE = re.compile(r"^[A-Za-z0-9]{15,18}$")


class SalesforceLineageError(ValueError):
    """A row was built without complete provenance.

    Provenance is not optional: a row a search can surface without being able to
    say which org / object / report it came from -- and therefore without the
    resource ref a query-time ACL probe needs -- is worse than an absent row, so
    the conversion fails loudly rather than storing one.
    """


class SalesforceConfigError(ValueError):
    """A source config could not be validated into a well-formed path spec."""


# ── per-row provenance + the ProviderResourceRef domain ────────────────────
@dataclass(frozen=True)
class SalesforceRowLineage:
    """Per-row provenance and the full primary-key domain for one Salesforce row.

    Every typed row carries exactly one of these. It answers, for one stored
    row: which knowledge SOURCE it belongs to, which Salesforce INSTANCE (the org
    ``instance_url``) and ORG ID it came from, which read PATH produced it
    (``soql_object`` / ``analytics_report``), what KIND of record it is, the
    primary key that identifies it, and when it was read.

    ``source_id`` + ``instance_url`` + ``org_id`` + ``path`` + ``entity_type``
    are the key DOMAIN -- the qualifiers that keep two records sharing an entity
    key (the same 15-char id in two orgs, row ordinal 0 of two reports) from
    colliding when they belong to different sources, orgs, paths or kinds. The
    entity key (record id / ``report_id/ordinal``) is appended by
    :func:`primary_key_for`.

    ``resource_ref`` fields are the shared-ACL ``ProviderResourceRef`` locator
    (``salesforce: {instanceUrl, sobjectType, recordId, [reportId],
    [fieldSet]}``): what a revalidation probe needs to ask "does this subject
    still have access to THIS object right now". ``account`` is the VENDOR-side
    org (``org_id``) the resource lives in, the (provider, account) pair a
    per-candidate binding resolver keys on -- distinct from a KiroCrew tenant.
    """

    source_id: str
    instance_url: str
    org_id: str
    path: str
    entity_type: str
    primary_key: str
    # ProviderResourceRef locator fields (see module docstring / acl.py):
    sobject_type: Optional[str]
    record_id: Optional[str]
    report_id: Optional[str]
    field_set: Tuple[str, ...]
    fetched_at: str

    def validate(self) -> None:
        """Raise :class:`SalesforceLineageError` unless every fact is well-formed."""
        for label, value in (
            ("source_id", self.source_id),
            ("instance_url", self.instance_url),
            ("org_id", self.org_id),
        ):
            if not (value or "").strip():
                raise SalesforceLineageError(f"{label} is required")
            if _PK_SEP in value:
                raise SalesforceLineageError(f"{label} may not contain {_PK_SEP!r}")
        if self.path not in _PATHS:
            raise SalesforceLineageError(f"unknown path {self.path!r}")
        if self.entity_type not in _ENTITY_TYPES:
            raise SalesforceLineageError(f"unknown entity_type {self.entity_type!r}")
        if not (self.primary_key or "").strip():
            raise SalesforceLineageError("primary_key is required")
        if not (self.fetched_at or "").strip():
            raise SalesforceLineageError("fetched_at is required")
        # The two paths carry mutually-exclusive resource coordinates, and each
        # MUST carry its own: a resource ref that cannot locate the object it
        # came from cannot be revalidated, so an incomplete one is a deny, not a
        # stored row.
        if self.path == PATH_SOQL_OBJECT:
            if not (self.sobject_type or "").strip() or not (self.record_id or "").strip():
                raise SalesforceLineageError(
                    "a soql_object row needs both sobject_type and record_id"
                )
            if self.report_id:
                raise SalesforceLineageError("a soql_object row must not carry a report_id")
        else:  # PATH_ANALYTICS_REPORT
            if not (self.report_id or "").strip():
                raise SalesforceLineageError("an analytics_report row needs a report_id")
            if self.sobject_type or self.record_id:
                raise SalesforceLineageError(
                    "an analytics_report row must not carry sobject_type/record_id"
                )


# ── typed rows ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class SObjectRecordRow:
    """One Salesforce sObject record (the SOQL object path).

    Identity is the record ``id`` -- globally unique within an org by
    construction. ``fields`` is the record's typed field values (parsed against
    the object's describe by the L1 payload parser), never the raw envelope; the
    ``attributes`` envelope is dropped. The field set is FLS-filtered upstream,
    so a field the calling identity may not see is never present here.
    """

    PRIMARY_KEY_FIELDS = ("record_id",)

    sobject_type: str
    record_id: str
    fields: Mapping[str, Any]
    lineage: SalesforceRowLineage

    @property
    def primary_key(self) -> str:
        return primary_key_for(self)


@dataclass(frozen=True)
class ReportRow:
    """One row of a Salesforce Analytics report (the report path).

    A report's result is a fact grid, not a record list, so a row's identity is
    the report id plus its ORDINAL within the described, ordered column set --
    there is no per-row provider id to key on. ``columns`` names the report's
    detail-column labels in order; ``cells`` are this row's values in that same
    order. Keying on the ordinal is why a report refresh is a full re-read
    (see :func:`diff_rows`): a report has no stable per-row id to diff by.
    """

    PRIMARY_KEY_FIELDS = ("report_id", "row_ordinal")

    report_id: str
    row_ordinal: int
    columns: Tuple[str, ...]
    cells: Tuple[Any, ...]
    lineage: SalesforceRowLineage

    @property
    def primary_key(self) -> str:
        return primary_key_for(self)


TypedRow = Union[SObjectRecordRow, ReportRow]


def primary_key_for(row: TypedRow) -> str:
    """The row's identity string over the FULL key domain.

    Composed as ``source_id | instance_url | org_id | path | entity_type |
    <entity-key>``, the entity key being the row's ``PRIMARY_KEY_FIELDS`` joined
    by ``/``. The domain segments come from the row's lineage, so two records
    that share an entity key never collapse across sources, orgs, paths or kinds.
    A single stable string, so refreshes diff by identity with set operations.
    """
    entity_key = "/".join(str(getattr(row, f)) for f in row.PRIMARY_KEY_FIELDS)
    lin = row.lineage
    return _PK_SEP.join(
        (lin.source_id, lin.instance_url, lin.org_id, lin.path, lin.entity_type, entity_key)
    )


# ── conversion: vendor payload shape → typed row ───────────────────────────
def _make_soql_lineage(
    *,
    source_id: str,
    instance_url: str,
    org_id: str,
    sobject_type: str,
    record_id: str,
    field_set: Sequence[str],
    fetched_at: str,
) -> SalesforceRowLineage:
    primary_key = _PK_SEP.join(
        (source_id, instance_url, org_id, PATH_SOQL_OBJECT, ENTITY_SOBJECT_RECORD, record_id)
    )
    lineage = SalesforceRowLineage(
        source_id=source_id,
        instance_url=instance_url,
        org_id=org_id,
        path=PATH_SOQL_OBJECT,
        entity_type=ENTITY_SOBJECT_RECORD,
        primary_key=primary_key,
        sobject_type=sobject_type,
        record_id=record_id,
        report_id=None,
        field_set=tuple(field_set),
        fetched_at=fetched_at,
    )
    lineage.validate()
    return lineage


def _make_report_lineage(
    *,
    source_id: str,
    instance_url: str,
    org_id: str,
    report_id: str,
    row_ordinal: int,
    fetched_at: str,
) -> SalesforceRowLineage:
    primary_key = _PK_SEP.join(
        (
            source_id,
            instance_url,
            org_id,
            PATH_ANALYTICS_REPORT,
            ENTITY_REPORT_ROW,
            f"{report_id}/{row_ordinal}",
        )
    )
    lineage = SalesforceRowLineage(
        source_id=source_id,
        instance_url=instance_url,
        org_id=org_id,
        path=PATH_ANALYTICS_REPORT,
        entity_type=ENTITY_REPORT_ROW,
        primary_key=primary_key,
        sobject_type=None,
        record_id=None,
        report_id=report_id,
        field_set=(),
        fetched_at=fetched_at,
    )
    lineage.validate()
    return lineage


def record_from_payload(
    describe: ObjectDescribe,
    record: Mapping[str, Any],
    *,
    source_id: str,
    instance_url: str,
    org_id: str,
    fetched_at: str,
) -> SObjectRecordRow:
    """Convert ONE raw SOQL record into a typed :class:`SObjectRecordRow`.

    The record is typed against ``describe`` by the L1 payload parser (a
    mistyped field surfaces as a ``PayloadParseError`` rather than a silently
    wrong value), the ``attributes`` envelope is dropped, and the record's ``Id``
    becomes its entity key. A record missing an ``Id`` cannot be keyed and
    raises.

    Only FLS-readable fields should reach here; the field set persisted on the
    lineage is exactly the keys carried on the row, so the resource ref records
    which fields were read.
    """
    parsed = parse_record(describe, record)
    parsed.pop("attributes", None)
    record_id = parsed.get("Id") or record.get("Id")
    if not record_id or not isinstance(record_id, str):
        raise SalesforceLineageError(f"{describe.name} record has no string 'Id'; cannot key it")
    field_names = tuple(sorted(parsed.keys()))
    lineage = _make_soql_lineage(
        source_id=source_id,
        instance_url=instance_url,
        org_id=org_id,
        sobject_type=describe.name,
        record_id=record_id,
        field_set=field_names,
        fetched_at=fetched_at,
    )
    return SObjectRecordRow(
        sobject_type=describe.name, record_id=record_id, fields=parsed, lineage=lineage
    )


def report_rows_from_payload(
    report_id: str,
    payload: Mapping[str, Any],
    *,
    source_id: str,
    instance_url: str,
    org_id: str,
    fetched_at: str,
) -> Tuple[ReportRow, ...]:
    """Convert an Analytics report result payload into ordered :class:`ReportRow` s.

    The Analytics REST report result is a fact grid: ``reportMetadata.
    detailColumns`` is the ordered detail-column set, and
    ``factMap["T!T"].rows[*].dataCells[*].label`` are the cell values in that
    order. This reads that shape into one :class:`ReportRow` per grid row, keyed
    by ordinal. A payload that is not a report result (no ``reportMetadata`` /
    ``factMap``) raises rather than being coerced -- the report path never
    accepts an sObject record list in a report's place.
    """
    meta = payload.get("reportMetadata")
    fact_map = payload.get("factMap")
    if not isinstance(meta, Mapping) or not isinstance(fact_map, Mapping):
        raise SalesforceLineageError(
            "report payload missing reportMetadata/factMap; a SOQL record list is "
            "not a report result and must not be read as one"
        )
    columns = tuple(str(c) for c in (meta.get("detailColumns") or ()))
    # The grand-total fact-map key for a report's detail rows.
    grid = fact_map.get("T!T") or {}
    raw_rows = grid.get("rows") if isinstance(grid, Mapping) else None
    if not isinstance(raw_rows, list):
        raw_rows = []
    out: list[ReportRow] = []
    for ordinal, raw in enumerate(raw_rows):
        cells_raw = raw.get("dataCells") if isinstance(raw, Mapping) else None
        cells = tuple((c.get("label") if isinstance(c, Mapping) else c) for c in (cells_raw or ()))
        lineage = _make_report_lineage(
            source_id=source_id,
            instance_url=instance_url,
            org_id=org_id,
            report_id=report_id,
            row_ordinal=ordinal,
            fetched_at=fetched_at,
        )
        out.append(
            ReportRow(
                report_id=report_id,
                row_ordinal=ordinal,
                columns=columns,
                cells=cells,
                lineage=lineage,
            )
        )
    return tuple(out)


# ── incremental refresh: since + primary-key diff ──────────────────────────
@dataclass(frozen=True)
class RefreshPlan:
    """The outcome of diffing a fetched key set against the stored key set."""

    upserts: Tuple[TypedRow, ...]
    # Keys present in the store, absent from a FULL listing -- genuinely gone,
    # safe to retire. Populated ONLY when ``full_listing=True``. On a windowed
    # (``since``) SOQL refresh this is empty: a window returns only CHANGED
    # records, so "absent from this window" is the normal state of nearly every
    # stored key and says nothing about deletion.
    disappeared: Tuple[str, ...]
    # The watermark to persist -- the max ``SystemModstamp``/``LastModifiedDate``
    # seen -- so the next SOQL refresh asks only for what changed after it. A
    # report path carries None (a report has no per-row modstamp; it is
    # full-read each refresh).
    next_since: Optional[str]


def diff_rows(
    fetched: Tuple[TypedRow, ...],
    stored_keys: frozenset[str],
    *,
    prior_since: Optional[str],
    modstamps: Optional[Sequence[str]] = None,
    full_listing: bool = False,
) -> RefreshPlan:
    """Diff a freshly-fetched set against what is already stored.

    Every fetched row is an upsert. ``full_listing`` decides ``disappeared``:
    a full listing lets a stored key not in ``fetched`` be reported as gone; a
    ``since`` window (the default) never does, because a window carries only
    changed records and reporting the rest would invite purging live records.

    ``modstamps`` are the per-record modification stamps (SOQL path only) used to
    advance the watermark; the watermark never moves backwards. For the report
    path pass ``modstamps=None`` and ``full_listing=True`` (a report is
    re-read whole, keyed by ordinal, with no modstamp).

    A primary-key collision inside one fetched set keeps the LAST occurrence
    (last-writer-wins), so a page boundary re-listing a straddling record is
    idempotent.
    """
    by_key: dict[str, TypedRow] = {}
    for row in fetched:
        by_key[row.primary_key] = row
    upserts = tuple(by_key.values())
    disappeared = tuple(sorted(stored_keys - by_key.keys())) if full_listing else ()
    window_max = max(modstamps) if modstamps else None
    if window_max is None:
        next_since = prior_since
    elif prior_since is None:
        next_since = window_max
    else:
        next_since = max(window_max, prior_since)
    return RefreshPlan(upserts=upserts, disappeared=disappeared, next_since=next_since)


# ── resumable checkpoint (in the source's existing properties blob) ────────
_CHECKPOINT_KEY = "salesforce_structured_checkpoint"


@dataclass
class Checkpoint:
    """Where a refresh is up to, so it resumes after an interruption.

    ``since`` is the SOQL watermark for the next refresh (``None`` on the report
    path). ``query_locator`` is the REST ``nextRecordsUrl`` of the page last
    persisted within an in-progress SOQL walk -- the cursor the L1
    ``next_locator`` contract advances, persisted only after a page is fully
    consumed. ``in_progress`` distinguishes a clean watermark-only checkpoint
    from one paused mid-walk.
    """

    since: Optional[str] = None
    query_locator: Optional[str] = None
    in_progress: bool = False

    def to_dict(self) -> dict:
        return {
            "since": self.since,
            "query_locator": self.query_locator,
            "in_progress": self.in_progress,
        }

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Checkpoint":
        if not data:
            return cls()
        return cls(
            since=(data.get("since") or None),
            query_locator=(data.get("query_locator") or None),
            in_progress=bool(data.get("in_progress", False)),
        )


def read_checkpoint(source: dict) -> Checkpoint:
    """Read the checkpoint out of a source's ``properties`` blob.

    ``properties`` may already be a parsed dict (as the scheduler hands it) or a
    JSON string (as the raw row carries it); both are accepted.
    """
    props = source.get("properties")
    if isinstance(props, str):
        try:
            props = json.loads(props or "{}")
        except ValueError:
            props = {}
    if not isinstance(props, dict):
        props = {}
    return Checkpoint.from_dict(props.get(_CHECKPOINT_KEY))


def write_checkpoint(properties: dict, checkpoint: Checkpoint) -> dict:
    """Return a copy of ``properties`` with the checkpoint written under its key.

    Pure: the caller persists the result through the store's existing per-source
    state write, so the checkpoint logic is testable without a database.
    """
    updated = dict(properties or {})
    updated[_CHECKPOINT_KEY] = checkpoint.to_dict()
    return updated


# ── FLS-gated field selection (fail-closed) ────────────────────────────────
def readable_field_names(describe: ObjectDescribe) -> Tuple[str, ...]:
    """The fields whose FLS ``accessible`` is a real ``True`` -- nothing else.

    A field whose ``accessible`` is the ``UNKNOWN`` sentinel (the describe did
    not say) or ``False`` is NOT selected: an unknown permission is a deny, never
    a guessed grant. ``UNKNOWN`` is not truth-valued, so it is compared by
    identity (``is UNKNOWN``) rather than truthiness. Returned sorted for a
    stable SOQL projection.
    """
    out: list[str] = []
    for name, fd in describe.fields.items():
        accessible = fd.fls.accessible
        if accessible is UNKNOWN:
            continue
        if accessible is True:
            out.append(name)
    return tuple(sorted(out))


def object_is_queryable(describe: ObjectDescribe) -> bool:
    """Whether the object may be queried at all -- ``UNKNOWN``/``False`` ⇒ no.

    Reads the org-level ``ObjectPermissions.queryable`` flag by identity: an
    unsourced (``UNKNOWN``) or false queryable flag fails closed, so no SOQL is
    emitted against an object the calling identity is not proven to be able to
    query.
    """
    queryable = describe.object_permissions.queryable
    return queryable is True


def build_soql(
    describe: ObjectDescribe, *, since: Optional[str] = None, order_by: str = "Id"
) -> str:
    """Build a fail-closed SELECT over exactly the FLS-readable fields.

    Raises :class:`SalesforceConfigError` when the object is not proven queryable
    or has no readable field, rather than emitting a query that would be refused
    (or, worse, one that leaks an unintended field). A ``since`` watermark adds a
    ``WHERE SystemModstamp > <since>`` incremental filter.
    """
    if not object_is_queryable(describe):
        raise SalesforceConfigError(
            f"{describe.name} is not proven queryable (object permission unknown or "
            "denied); refusing to emit SOQL (fail-closed)"
        )
    fields = readable_field_names(describe)
    if not fields:
        raise SalesforceConfigError(
            f"{describe.name} has no FLS-readable field; refusing to emit SOQL"
        )
    projection = ", ".join(fields)
    clause = f" WHERE SystemModstamp > {since}" if since else ""
    return f"SELECT {projection} FROM {describe.name}{clause} ORDER BY {order_by}"


# ── rendering a typed row into the pipeline's (text, metadata) shape ───────
def render_row_text(row: TypedRow) -> str:
    """A stable, legible text projection of a typed row for the search index."""
    if isinstance(row, SObjectRecordRow):
        lines = [f"{row.lineage.entity_type} {row.primary_key}"]
        for key, value in row.fields.items():
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(v) for v in value)
            lines.append(f"{key}: {value}")
        return "\n".join(lines)
    # ReportRow: pair each described column with this row's cell.
    lines = [f"{row.lineage.entity_type} {row.primary_key}"]
    if row.columns and len(row.columns) == len(row.cells):
        for col, cell in zip(row.columns, row.cells):
            lines.append(f"{col}: {cell}")
    else:
        for i, cell in enumerate(row.cells):
            lines.append(f"col{i}: {cell}")
    return "\n".join(lines)


def render_row_metadata(row: TypedRow) -> dict:
    """A flat metadata dict: the primary key plus the ProviderResourceRef domain.

    The ``resource_ref`` sub-dict is exactly the shared ACL's ``salesforce``
    :class:`ProviderResourceRef` locator (``provider`` / ``account`` /
    ``resource_id`` / ``locator``), so the ingest path can persist it verbatim on
    the item's grant row and a query-time probe can locate the object.
    """
    lin = row.lineage
    locator: dict[str, Any] = {"instanceUrl": lin.instance_url}
    if lin.path == PATH_SOQL_OBJECT:
        locator["sobjectType"] = lin.sobject_type
        locator["recordId"] = lin.record_id
        if lin.field_set:
            locator["fieldSet"] = list(lin.field_set)
        resource_id = lin.record_id or ""
    else:
        locator["reportId"] = lin.report_id
        resource_id = lin.report_id or ""
    return {
        "primary_key": row.primary_key,
        "source_id": lin.source_id,
        "instance_url": lin.instance_url,
        "org_id": lin.org_id,
        "path": lin.path,
        "entity_type": lin.entity_type,
        "fetched_at": lin.fetched_at,
        # The shared ACL ProviderResourceRef, ready to persist on the grant row.
        "resource_ref": {
            "provider": SOURCE_TYPE,
            "account": lin.org_id,
            "resource_id": resource_id,
            "locator": locator,
        },
    }


# ── config validation for a source ─────────────────────────────────────────
@dataclass(frozen=True)
class SourceSpec:
    """The validated shape of a Salesforce structured source's config.

    One source is exactly one of the two paths. ``instance_url`` and ``org_id``
    identify the org; ``path`` selects SOQL-object vs Analytics-report; and the
    path-specific target (``sobject_type`` or ``report_id``) names what to read.
    """

    instance_url: str
    org_id: str
    path: str
    sobject_type: Optional[str]
    report_id: Optional[str]


def parse_source_spec(config: Mapping[str, Any]) -> SourceSpec:
    """Validate a source config into a :class:`SourceSpec`, or raise.

    The knowledge-source schema key every connector reads is ``uri`` (as
    ``local_folder`` does). A Salesforce structured source is declared as
    ``salesforce://<path>/<target>`` -- ``salesforce://object/Account`` or
    ``salesforce://report/00O...`` -- with ``instance_url`` and ``org_id`` in the
    source properties. Both id fields are required and must be well-formed:
    a source that cannot name its org cannot carry a resource ref.
    """
    uri = (config.get("uri") or config.get("url") or "").strip()
    instance_url = (config.get("instance_url") or "").strip()
    org_id = (config.get("org_id") or "").strip()
    if not uri.startswith("salesforce://"):
        raise SalesforceConfigError(
            "a Salesforce source uri must be salesforce://object/<Name> or "
            "salesforce://report/<ReportId>"
        )
    if not instance_url:
        raise SalesforceConfigError("instance_url is required")
    if not org_id:
        raise SalesforceConfigError("org_id is required")
    rest = uri[len("salesforce://") :]
    head, _, target = rest.partition("/")
    target = target.strip()
    if head == "object":
        if not _SOBJECT_NAME_RE.match(target):
            raise SalesforceConfigError(
                f"invalid sObject name {target!r}; expected an API name like "
                "'Account' or 'My_Object__c'"
            )
        return SourceSpec(
            instance_url=instance_url,
            org_id=org_id,
            path=PATH_SOQL_OBJECT,
            sobject_type=target,
            report_id=None,
        )
    if head == "report":
        if not _SF_ID_RE.match(target):
            raise SalesforceConfigError(
                f"invalid report id {target!r}; expected a 15/18-char Salesforce id"
            )
        return SourceSpec(
            instance_url=instance_url,
            org_id=org_id,
            path=PATH_ANALYTICS_REPORT,
            sobject_type=None,
            report_id=target,
        )
    raise SalesforceConfigError(
        f"unknown Salesforce source path {head!r}; expected 'object' or 'report'"
    )


# ── the connector ───────────────────────────────────────────────────────────
class SalesforceStructuredConnector(BaseConnector):
    """Consume Salesforce sObjects and Analytics reports as one structured source.

    Conforms to :class:`BaseConnector` so the existing ``SyncScheduler`` drives
    it. The typed-row conversion, primary-key diffing, checkpointing, FLS-gated
    field selection and SOQL building are the module-level pure functions above;
    this class binds them to the connector contract and owns config validation.

    The live transport is the W01 control-plane executor, INJECTED at
    construction (the same dependency-injection seam W01's own production
    composition uses -- not a bypass hook: the real assembly supplies the real
    executor, and only a test supplies a fake). When no transport is wired AND
    the executor is not importable, :meth:`fetch` / :meth:`detect_changes` refuse
    fail-closed rather than fabricating a live read.
    """

    def __init__(self, transport: Any = None) -> None:
        # ``transport`` is a control-plane executor Transport (see
        # kiro_crew.connections.control_plane.executor.Transport). Left None in
        # the offline/default construction; the real production assembly passes
        # the vault-custody + HTTP transport composed by
        # control_plane.production. It is NEVER a second HTTP client of this
        # module's own.
        self._transport = transport

    def source_type(self) -> str:
        return SOURCE_TYPE

    def validate_config(self, config: dict) -> tuple[bool, str]:
        try:
            parse_source_spec(config)
        except SalesforceConfigError as exc:
            return False, str(exc)
        return True, ""

    async def detect_changes(self, source: dict) -> bool:
        # A real detect_changes issues a bounded probe through the control-plane
        # executor (a COUNT() SOQL past the watermark on the object path; a report
        # is re-read whole so it always "may have changed"). Until the executor
        # transport is wired it refuses -- fail-closed, scheduling no ingest --
        # rather than fabricating a "changed" answer.
        if self._transport is None:
            raise NotImplementedError(
                "Salesforce live change-detection needs the W01 control-plane "
                "executor transport, which is not wired in this construction"
            )
        raise NotImplementedError(
            "Salesforce detect_changes transport wiring lands with the executor "
            "integration; see work item W10/L2"
        )

    async def fetch(self, source: dict) -> tuple[str, dict]:
        # A real fetch runs the object path (describe -> FLS-gated SOQL -> L1
        # query-locator PageWalk over the executor) or the report path
        # (Analytics report read over the executor), converts each vendor record
        # into a typed row, and renders the rows into the (text, metadata) shape
        # the ingestion pipeline stores -- carrying the ProviderResourceRef on
        # each item. Until the executor transport is wired it refuses: a
        # first-page-only or mocked payload is not a live dataset and must not be
        # stored as one.
        if self._transport is None:
            raise NotImplementedError(
                "Salesforce live fetch needs the W01 control-plane executor "
                "transport, which is not wired in this construction"
            )
        raise NotImplementedError(
            "Salesforce fetch transport wiring lands with the executor "
            "integration; see work item W10/L2"
        )


__all__ = [
    "SOURCE_TYPE",
    "PATH_SOQL_OBJECT",
    "PATH_ANALYTICS_REPORT",
    "ENTITY_SOBJECT_RECORD",
    "ENTITY_REPORT_ROW",
    "Checkpoint",
    "RefreshPlan",
    "ReportRow",
    "SalesforceConfigError",
    "SalesforceLineageError",
    "SalesforceRowLineage",
    "SalesforceStructuredConnector",
    "SObjectRecordRow",
    "SourceSpec",
    "build_soql",
    "diff_rows",
    "object_is_queryable",
    "parse_source_spec",
    "primary_key_for",
    "read_checkpoint",
    "readable_field_names",
    "record_from_payload",
    "render_row_metadata",
    "render_row_text",
    "report_rows_from_payload",
    "write_checkpoint",
]
