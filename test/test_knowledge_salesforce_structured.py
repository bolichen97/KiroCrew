"""Typed rows, conversion, primary keys, lineage, FLS-gating, pagination
checkpoint, incremental diff and config validation for the Salesforce
structured connector (both the SOQL object path and the Analytics report path).

Pure-function tests: no database, no network, no event loop. They lock in the
shape of the deliverable that is testable today -- real typed fields, a primary
key that is the dedup identity, conversion from the vendor payload shapes,
per-row lineage that MUST be complete and MUST carry the ProviderResourceRef the
query-time ACL needs, FLS/object-permission fail-closed field selection, the
REST query-locator checkpoint contract, and both paths kept independent (a report
result is never read as a record list, and a record list never as a report).
"""

import asyncio
import unittest

from kiro_crew.connections.vendors.salesforce.describe import parse_object_describe
from kiro_crew.connections.vendors.salesforce.fixtures import (
    account_describe,
    query_page_first,
    query_page_terminal,
)
from kiro_crew.connections.vendors.salesforce.query_locator import (
    next_locator,
    parse_query_page,
)
from kiro_crew.knowledge.connectors.salesforce_structured import (
    ENTITY_REPORT_ROW,
    ENTITY_SOBJECT_RECORD,
    PATH_ANALYTICS_REPORT,
    PATH_SOQL_OBJECT,
    REPORT_MAX_ROWS,
    SOURCE_TYPE,
    Checkpoint,
    ReportRow,
    SalesforceConfigError,
    SalesforceLineageError,
    SalesforceStructuredConnector,
    SObjectRecordRow,
    build_soql,
    diff_rows,
    object_is_queryable,
    parse_source_spec,
    read_checkpoint,
    readable_field_names,
    record_from_payload,
    render_row_metadata,
    render_row_text,
    report_rows_from_payload,
    write_checkpoint,
)

SRC = "src-sf-1"
INSTANCE = "https://acme.my.salesforce.com"
ORG = "00Dxx0000001gP"
NOW = "2026-09-16T00:00:00Z"


def _describe():
    return parse_object_describe(account_describe())


def _record(**over):
    base = {
        "attributes": {"type": "Account", "url": "/x/1"},
        "Id": "001A00000000001",
        "Name": "Acme",
    }
    base.update(over)
    return base


def mk_record(rec=None):
    return record_from_payload(
        _describe(),
        rec or _record(),
        source_id=SRC,
        instance_url=INSTANCE,
        org_id=ORG,
        fetched_at=NOW,
    )


# ── SOQL object path: typed row, key, lineage ──────────────────────────────
class TestSObjectRecordRow(unittest.TestCase):
    def test_record_becomes_typed_row_keyed_by_id(self):
        row = mk_record()
        self.assertIsInstance(row, SObjectRecordRow)
        self.assertEqual(row.record_id, "001A00000000001")
        self.assertEqual(row.sobject_type, "Account")
        # attributes envelope dropped, fields typed
        self.assertNotIn("attributes", row.fields)
        self.assertEqual(row.fields["Name"], "Acme")

    def test_primary_key_is_full_domain_and_uses_id_not_name(self):
        row = mk_record()
        pk = row.primary_key
        self.assertIn(SRC, pk)
        self.assertIn(INSTANCE, pk)
        self.assertIn(ORG, pk)
        self.assertIn(PATH_SOQL_OBJECT, pk)
        self.assertIn(ENTITY_SOBJECT_RECORD, pk)
        self.assertIn("001A00000000001", pk)
        # renaming the record (Name) must NOT change identity
        renamed = mk_record(_record(Name="Acme Renamed"))
        self.assertEqual(row.primary_key, renamed.primary_key)

    def test_same_id_different_org_does_not_collide(self):
        row_a = mk_record()
        row_b = record_from_payload(
            _describe(),
            _record(),
            source_id=SRC,
            instance_url=INSTANCE,
            org_id="00Dyy0000002zZ",
            fetched_at=NOW,
        )
        self.assertNotEqual(row_a.primary_key, row_b.primary_key)

    def test_record_without_id_raises(self):
        rec = _record()
        del rec["Id"]
        with self.assertRaises(SalesforceLineageError):
            mk_record(rec)

    def test_lineage_carries_resource_ref_fields(self):
        row = mk_record()
        lin = row.lineage
        self.assertEqual(lin.sobject_type, "Account")
        self.assertEqual(lin.record_id, "001A00000000001")
        self.assertIsNone(lin.report_id)
        self.assertIn("Name", lin.field_set)


# ── FLS / object-permission fail-closed selection ──────────────────────────
class TestFlsGating(unittest.TestCase):
    def test_readable_fields_exclude_unknown_accessible(self):
        # The Account fixture marks every field accessible=True, so all appear.
        names = readable_field_names(_describe())
        self.assertIn("Name", names)
        self.assertIn("AnnualRevenue", names)

    def test_field_with_unknown_accessible_is_excluded(self):
        raw = account_describe()
        raw = dict(raw)
        # Add a field whose 'accessible' flag is OMITTED -> parses to UNKNOWN.
        fields = list(raw["fields"]) + [
            {
                "name": "Secret__c",
                "type": "string",
                "soapType": "xsd:string",
                "nillable": True,
                "createable": True,
                "updateable": True,
                # accessible deliberately omitted -> UNKNOWN -> must be excluded
            }
        ]
        raw["fields"] = fields
        describe = parse_object_describe(raw)
        names = readable_field_names(describe)
        self.assertNotIn("Secret__c", names)  # fail-closed: unknown => excluded

    def test_object_not_queryable_when_unknown(self):
        raw = dict(account_describe())
        del raw["queryable"]  # -> UNKNOWN
        describe = parse_object_describe(raw)
        self.assertFalse(object_is_queryable(describe))

    def test_build_soql_refuses_unqueryable_object(self):
        raw = dict(account_describe())
        raw["queryable"] = False
        describe = parse_object_describe(raw)
        with self.assertRaises(SalesforceConfigError):
            build_soql(describe)

    def test_build_soql_projects_only_readable_fields(self):
        soql = build_soql(_describe())
        self.assertTrue(soql.startswith("SELECT "))
        self.assertIn("FROM Account", soql)
        self.assertIn("ORDER BY Id", soql)
        # a since watermark adds an incremental filter
        inc = build_soql(_describe(), since="2026-01-01T00:00:00Z")
        self.assertIn("WHERE SystemModstamp >", inc)


# ── Analytics report path: grid → rows, independence from SOQL ─────────────
def _report_payload_with_id():
    # Detail columns include a record Id column; the id lives in dataCells[*].value.
    return {
        "allData": True,
        "reportMetadata": {"detailColumns": ["ACCOUNT.ID", "ACCOUNT.NAME", "AMOUNT"]},
        "factMap": {
            "T!T": {
                "rows": [
                    {
                        "dataCells": [
                            {"value": "001A00000000001", "label": "001A00000000001"},
                            {"label": "Acme"},
                            {"label": "$100"},
                        ]
                    },
                    {
                        "dataCells": [
                            {"value": "001B00000000002", "label": "001B00000000002"},
                            {"label": "Globex"},
                            {"label": "$200"},
                        ]
                    },
                ]
            }
        },
    }


def _report_payload_no_id():
    # A summary/aggregate report with no record-id column -> snapshot identity.
    return {
        "allData": True,
        "reportMetadata": {"detailColumns": ["ACCOUNT.NAME", "AMOUNT"]},
        "factMap": {
            "T!T": {
                "rows": [
                    {"dataCells": [{"label": "Acme"}, {"label": "$100"}]},
                    {"dataCells": [{"label": "Globex"}, {"label": "$200"}]},
                ]
            }
        },
    }


def _report_rows(payload, report_id="00O000000000001"):
    return report_rows_from_payload(
        report_id,
        payload,
        source_id=SRC,
        instance_url=INSTANCE,
        org_id=ORG,
        fetched_at=NOW,
    )


class TestReportRows(unittest.TestCase):
    def test_report_grid_becomes_rows(self):
        rows = _report_rows(_report_payload_with_id())
        self.assertEqual(len(rows), 2)
        self.assertIsInstance(rows[0], ReportRow)
        self.assertEqual(rows[0].columns, ("ACCOUNT.ID", "ACCOUNT.NAME", "AMOUNT"))
        self.assertEqual(rows[0].cells, ("001A00000000001", "Acme", "$100"))

    def test_identity_is_real_record_id_not_ordinal(self):
        rows = _report_rows(_report_payload_with_id())
        self.assertFalse(rows[0].is_snapshot_identity)
        self.assertEqual(rows[0].record_id, "001A00000000001")
        self.assertEqual(rows[0].report_row_key, "001A00000000001")
        pk = rows[0].primary_key
        self.assertIn(PATH_ANALYTICS_REPORT, pk)
        self.assertIn(ENTITY_REPORT_ROW, pk)
        self.assertIn("001A00000000001", pk)
        self.assertNotEqual(rows[0].primary_key, rows[1].primary_key)

    def test_resort_does_not_change_identity(self):
        # A re-sort between refreshes must not churn identities: record-id keys
        # are order-independent.
        p = _report_payload_with_id()
        keys_a = {r.primary_key for r in _report_rows(p)}
        p["factMap"]["T!T"]["rows"].reverse()
        keys_b = {r.primary_key for r in _report_rows(p)}
        self.assertEqual(keys_a, keys_b)

    def test_no_id_column_uses_snapshot_hash_not_ordinal(self):
        rows = _report_rows(_report_payload_no_id())
        self.assertTrue(rows[0].is_snapshot_identity)
        self.assertIsNone(rows[0].record_id)
        self.assertTrue(rows[0].report_row_key.startswith("snap-"))
        # identical content in two reads yields the same snapshot key (stable)
        rows2 = _report_rows(_report_payload_no_id())
        self.assertEqual(rows[0].report_row_key, rows2[0].report_row_key)

    def test_report_path_refuses_a_record_list(self):
        # A SOQL page (records list, no reportMetadata) must NOT parse as a report.
        with self.assertRaises(SalesforceLineageError):
            _report_rows(query_page_first())

    def test_truncated_report_is_refused(self):
        p = _report_payload_with_id()
        p["allData"] = False
        with self.assertRaises(SalesforceLineageError):
            _report_rows(p)

    def test_over_cap_is_refused(self):
        p = _report_payload_no_id()
        p["factMap"]["T!T"]["rows"] = [
            {"dataCells": [{"label": f"r{i}"}, {"label": "$1"}]} for i in range(REPORT_MAX_ROWS + 1)
        ]
        with self.assertRaises(SalesforceLineageError):
            _report_rows(p)

    def test_report_lineage_has_report_id_not_sobject(self):
        rows = _report_rows(_report_payload_with_id())
        lin = rows[0].lineage
        self.assertEqual(lin.report_id, "00O000000000001")
        self.assertIsNone(lin.sobject_type)
        self.assertIsNone(lin.record_id)
        self.assertEqual(lin.report_row_key, "001A00000000001")


# ── rendering + ProviderResourceRef metadata ───────────────────────────────
class TestRendering(unittest.TestCase):
    def test_soql_metadata_carries_resource_ref(self):
        meta = render_row_metadata(mk_record())
        rr = meta["resource_ref"]
        self.assertEqual(rr["provider"], SOURCE_TYPE)
        self.assertEqual(rr["account"], ORG)  # vendor-side org
        self.assertEqual(rr["resource_id"], "001A00000000001")
        self.assertEqual(rr["locator"]["instanceUrl"], INSTANCE)
        self.assertEqual(rr["locator"]["sobjectType"], "Account")
        self.assertEqual(rr["locator"]["recordId"], "001A00000000001")
        self.assertIn("Name", rr["locator"]["fieldSet"])

    def test_report_metadata_carries_report_resource_ref(self):
        # A snapshot (no-id) report row: resource_id is the report id.
        rows = _report_rows(_report_payload_no_id())
        rr = render_row_metadata(rows[0])["resource_ref"]
        self.assertEqual(rr["resource_id"], "00O000000000001")
        self.assertEqual(rr["locator"]["reportId"], "00O000000000001")
        self.assertNotIn("sobjectType", rr["locator"])
        self.assertTrue(rr["locator"]["reportRowKey"].startswith("snap-"))

    def test_report_metadata_with_record_id_carries_record_locator(self):
        # An id-bearing report row: the real record id rides the locator so the
        # item can be revalidated as that record, and is the resource_id.
        rows = _report_rows(_report_payload_with_id())
        rr = render_row_metadata(rows[0])["resource_ref"]
        self.assertEqual(rr["resource_id"], "001A00000000001")
        self.assertEqual(rr["locator"]["recordId"], "001A00000000001")
        self.assertEqual(rr["locator"]["reportId"], "00O000000000001")

    def test_text_projection_is_legible(self):
        text = render_row_text(mk_record())
        self.assertIn("Name: Acme", text)
        self.assertIn(ENTITY_SOBJECT_RECORD, text)


# ── incremental diff + watermark ───────────────────────────────────────────
class TestDiff(unittest.TestCase):
    def test_window_never_reports_disappeared(self):
        row = mk_record()
        plan = diff_rows(
            (row,),
            frozenset({"some-other-key"}),
            prior_since=None,
            modstamps=["2026-02-01T00:00:00Z"],
            full_listing=False,
        )
        self.assertEqual(plan.disappeared, ())
        self.assertEqual(plan.upserts, (row,))
        self.assertEqual(plan.next_since, "2026-02-01T00:00:00Z")

    def test_full_listing_reports_gone_keys(self):
        row = mk_record()
        plan = diff_rows(
            (row,),
            frozenset({row.primary_key, "gone-key"}),
            prior_since=None,
            modstamps=None,
            full_listing=True,
        )
        self.assertEqual(plan.disappeared, ("gone-key",))

    def test_watermark_never_moves_backwards(self):
        row = mk_record()
        plan = diff_rows(
            (row,),
            frozenset(),
            prior_since="2026-05-01T00:00:00Z",
            modstamps=["2026-02-01T00:00:00Z"],
            full_listing=False,
        )
        self.assertEqual(plan.next_since, "2026-05-01T00:00:00Z")

    def test_collision_keeps_last(self):
        r1 = mk_record(_record(Name="First"))
        r2 = mk_record(_record(Name="Second"))  # same Id => same key
        plan = diff_rows((r1, r2), frozenset(), prior_since=None, full_listing=True)
        self.assertEqual(len(plan.upserts), 1)
        self.assertEqual(plan.upserts[0].fields["Name"], "Second")


# ── checkpoint round-trip via the properties blob ──────────────────────────
class TestCheckpoint(unittest.TestCase):
    def test_round_trip(self):
        cp = Checkpoint(
            since="2026-03-01T00:00:00Z",
            query_locator="/services/data/v60.0/query/01g-200",
            in_progress=True,
        )
        props = write_checkpoint({"content_hash": "abc"}, cp)
        # untouched keys preserved
        self.assertEqual(props["content_hash"], "abc")
        back = read_checkpoint({"properties": props})
        self.assertEqual(back.since, cp.since)
        self.assertEqual(back.query_locator, cp.query_locator)
        self.assertTrue(back.in_progress)

    def test_read_from_json_string_properties(self):
        import json

        cp = Checkpoint(since="2026-03-01T00:00:00Z")
        props = write_checkpoint({}, cp)
        back = read_checkpoint({"properties": json.dumps(props)})
        self.assertEqual(back.since, "2026-03-01T00:00:00Z")

    def test_absent_checkpoint_is_empty(self):
        self.assertEqual(read_checkpoint({}).since, None)


# ── query-locator pagination checkpoint (reuse L1 contract) ────────────────
class TestPaginationContract(unittest.TestCase):
    def test_cursor_advances_only_after_full_consumption(self):
        first = parse_query_page(query_page_first())
        # not consumed => do not advance
        self.assertIsNone(next_locator(first, page_fully_consumed=False))
        # consumed => advance to the locator
        self.assertEqual(next_locator(first, page_fully_consumed=True), first.next_records_url)
        terminal = parse_query_page(query_page_terminal())
        self.assertTrue(terminal.is_terminal)
        self.assertIsNone(next_locator(terminal, page_fully_consumed=True))


# ── config validation ──────────────────────────────────────────────────────
class TestConfig(unittest.TestCase):
    def _cfg(self, **over):
        base = {"uri": "salesforce://object/Account", "instance_url": INSTANCE, "org_id": ORG}
        base.update(over)
        return base

    def test_valid_object_source(self):
        spec = parse_source_spec(self._cfg())
        self.assertEqual(spec.path, PATH_SOQL_OBJECT)
        self.assertEqual(spec.sobject_type, "Account")

    def test_valid_report_source(self):
        spec = parse_source_spec(self._cfg(uri="salesforce://report/00O000000000001"))
        self.assertEqual(spec.path, PATH_ANALYTICS_REPORT)
        self.assertEqual(spec.report_id, "00O000000000001")

    def test_missing_org_id_fails(self):
        with self.assertRaises(SalesforceConfigError):
            parse_source_spec(self._cfg(org_id=""))

    def test_bad_uri_fails(self):
        with self.assertRaises(SalesforceConfigError):
            parse_source_spec(self._cfg(uri="https://example.com"))

    def test_bad_sobject_name_fails(self):
        with self.assertRaises(SalesforceConfigError):
            parse_source_spec(self._cfg(uri="salesforce://object/DROP TABLE"))

    def test_connector_validate_config(self):
        conn = SalesforceStructuredConnector()
        ok, msg = conn.validate_config(self._cfg())
        self.assertTrue(ok)
        bad_ok, bad_msg = conn.validate_config(self._cfg(uri="nope"))
        self.assertFalse(bad_ok)
        self.assertTrue(bad_msg)


# ── connector fail-closed when no transport is wired ───────────────────────
class TestConnectorFailClosed(unittest.TestCase):
    def test_source_type(self):
        self.assertEqual(SalesforceStructuredConnector().source_type(), SOURCE_TYPE)

    def test_fetch_refuses_without_transport(self):
        conn = SalesforceStructuredConnector()
        with self.assertRaises(NotImplementedError):
            asyncio.run(conn.fetch({"uri": "salesforce://object/Account"}))

    def test_detect_changes_refuses_without_transport(self):
        conn = SalesforceStructuredConnector()
        with self.assertRaises(NotImplementedError):
            asyncio.run(conn.detect_changes({"uri": "salesforce://object/Account"}))


if __name__ == "__main__":
    unittest.main()
