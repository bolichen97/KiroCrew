# Salesforce structured-source connector (W10 / L2)

The **runtime-wiring** layer that turns Salesforce records and reports into the
knowledge Library's row shape and lets the existing `SyncScheduler` refresh them.
It lives in `src/kiro_crew/knowledge/connectors/salesforce_structured.py` and is a
`BaseConnector` — the SAME contract `local_folder` uses — so it adds **no** second
knowledge base, sync engine, auth, vault, pagination or ACL. This spec is the
owning spec for that module; when the code changes what this document states, the
two are updated in the same commit.

This is distinct from the [Salesforce vendor-offline core](connector-salesforce-core.md)
(W10 / L1): the L1 core is the pure describe/query/bulk/apex/error model and does
no dispatch. This L2 connector consumes L1's primitives and the W01 control-plane
executor to perform the real fetch.

## Two independent paths, never one impersonating the other

A source is exactly one of two paths, declared in its config `uri`:

- **SOQL object path** (`salesforce://object/<ApiName>`) — the sObject is
  *described* into the L1 `ObjectDescribe`, then read with a SOQL `SELECT` whose
  results page through the L1 REST query-locator contract
  (`{done, records, nextRecordsUrl}`). One `SObjectRecordRow` per record; the
  record's `Id` is its entity key.
- **Report / Analytics path** (`salesforce://report/<ReportId>`) — the report is
  read through the Analytics REST API, whose result is a fact grid
  (`reportMetadata.detailColumns` + `factMap["T!T"].rows[*].dataCells[*].label`),
  NOT a record list. One `ReportRow` per grid row, keyed by `report_id/ordinal`
  (a report has no per-row provider id).

The two are never collapsed: `report_rows_from_payload` **raises** on a payload
with no `reportMetadata`/`factMap` (a SOQL record list is not a report result),
and a report is never satisfied by a `SELECT` against its source object. Both are
carried, per the campaign scope ("原有 SOQL / reports / Bulk / Apex … 一律不缩").

## Identity, incremental refresh, checkpoint (borrowed shapes)

- **Primary key** is the full domain
  `source_id | instance_url | org_id | path | entity_type | <entity-key>`, so two
  records that share an entity key never collide across sources, orgs, paths or
  kinds. The key is the dedup identity — never a mutable field like a record Name.
- **Incremental refresh** (`diff_rows`) uses a `since` watermark
  (`SystemModstamp`) plus a primary-key diff on the SOQL path; a `since` window
  never reports `disappeared` (it carries only changed records). The report path
  is a full re-read keyed by ordinal (`full_listing=True`, no modstamp). The
  watermark never moves backwards.
- **Resumable checkpoint** lives in the source's existing `properties` blob under
  `salesforce_structured_checkpoint` (`since`, `query_locator`, `in_progress`) —
  no new table. The `query_locator` advances only after a page is *fully
  consumed*, via the L1 `next_locator` contract.

## Security posture (fail-closed)

- **FLS / object-permission unknown ⇒ deny.** `readable_field_names` selects only
  fields whose FLS `accessible` is a real `True` (the L1 `UNKNOWN` sentinel and
  `False` are excluded); `object_is_queryable` requires a real `True` queryable
  flag; `build_soql` **refuses** to emit a query for an unqueryable object or one
  with no readable field. No field a caller may not see is ever selected.
- **Every ingested row carries a resource ref.** `render_row_metadata` emits the
  shared-ACL `salesforce` `ProviderResourceRef` (`provider`/`account`(=org_id)/
  `resource_id`/`locator`) with locator fields `instanceUrl` / `sobjectType` /
  `recordId` (object path) or `reportId` (report path) and the read `fieldSet`,
  so the query-time ACL can revalidate the item against the provider through the
  same controlled runtime — never a cached bypass. Field-/object-permission
  unknowns fail closed; no grant is invented.
- **No real Salesforce business account this round.** Live fetch is driven ONLY
  through the injected control-plane executor transport; offline tests exercise
  the pure domain layer and an in-memory fake, never a live org.

## Transport = the W01 control-plane executor (no second transport)

The live transport is the W01 · L09 executor
(`connections.control_plane.executor.execute` / `PageWalk`), composed with real
vault custody + HTTP by `connections.control_plane.production`. The vendor-owned
request-shaping and result-decoding it injects live in
`connections/vendors/salesforce/transport.py` (owned): a `RequestLocator` that
turns each operation + its args into one `https` `HttpRequest` (credential-free
headers — the transport adds `Authorization`), and a `ResultDecode` per
operation — SOQL query/query-more (a `CollectionPayload` whose cursor is the real
`nextRecordsUrl`), Analytics report (a bounded snapshot, no cursor), sObject
describe (an `ObjectPayload`).

`fetch` is **real**, not a stub: it drives describe → FLS-gated SOQL → a real
`PageWalk` over the L1 query-locator (SOQL path), or runs the Analytics report
(report path), converts every vendor payload into a typed row, advances the
`SystemModstamp` watermark, and returns `(text, meta)` with each row's
`ProviderResourceRef` under `meta['rows']`. `detect_changes` issues a bounded
one-row probe past the watermark (SOQL) / reports changed (report full-snapshot).
The executor is reached through an **injected `SalesforceCallRunner`** the factory
composes (vault custody, handle issuance, binding resolution, per-operation
transport) — the connector holds no secret and composes no transport. When no
runner is wired, `fetch`/`detect_changes` refuse fail-closed (a mock is not a
live read).

## ACL persistence is a shared ingest-path dependency (not this slice's to own)

`render_row_metadata` produces the `salesforce` `ProviderResourceRef`
(`instanceUrl`/`sobjectType`/`recordId`/`reportId`/`fieldSet`) for every row, and
`fetch` carries it under `meta['rows']`. Persisting it via
`store.set_item_acl(resource_ref=..., managed=True)` requires an **ingest→ACL
bridge** that does not exist yet: the ingest pipeline (`ingest_text`) returns a
job id, not item ids, and calls `set_item_acl` nowhere. That bridge is the shared
store/ingest owner's (chat408), not this slice. Until it lands, a Salesforce
managed item's grant is unpersisted → the query-time gate denies it (fail-closed,
the correct posture); this slice invents no grant and, with field-/object-level
permission unknown, selects no field / emits no query.

## Report identity is a real record id or snapshot hash — never the grid ordinal

A Salesforce Analytics report result is a fact grid ordered by the report's
`sortBy`, capped at the first 2000 rows, and a re-run reflects current data (rows
added/removed/**re-sorted**) — so the grid ordinal is not a stable identity
(search-snippet corroborated; official pages 403). A `ReportRow`'s identity is the
real record Id from an id detail-column's `dataCells[*].value` when present, else
a content snapshot hash (`is_snapshot_identity`, a bounded full-snapshot
full-replaced each refresh). The 2000-row cap and `allData=false` truncation are
refused. `row_ordinal` is display-only, in no key or checkpoint.
