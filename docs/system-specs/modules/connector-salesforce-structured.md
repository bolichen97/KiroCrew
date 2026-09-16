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
vault custody + HTTP by `connections.control_plane.production`. It is **injected**
at connector construction — the framework's own dependency-injection seam, the
same one `production.py` fills — not a second HTTP client and not a permanent
bypass hook; the real production assembly supplies the real executor. When no
transport is wired, `fetch` / `detect_changes` **refuse** (fail-closed) rather
than returning a partial or mocked dataset.

The executor slice (`feat/connector-control-plane-executor`) is a separate stack
branch; final production factory registration and the executor-backed `fetch`
body land as that dependency stabilises and is threaded beneath this slice.
