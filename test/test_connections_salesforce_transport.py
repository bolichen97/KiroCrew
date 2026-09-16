"""RequestLocator + ResultDecode for the Salesforce control-plane transport.

Pure tests: no socket, no secret. They lock the vendor-owned request shaping
(method / absolute https URL / credential-free headers) and the 2xx decode into
the L01 payload envelope, including that the SOQL decode derives the paging
cursor from the vendor's own ``done``/``nextRecordsUrl`` (never a fabricated
one) and the report decode carries a bounded snapshot with no cursor.
"""

import unittest

from kiro_crew.connections.control_plane.production import HttpReply
from kiro_crew.connections.control_plane.result import CollectionPayload, ObjectPayload
from kiro_crew.connections.vendors.salesforce.transport import (
    DEFAULT_API_VERSION,
    describe_descriptor,
    report_run_descriptor,
    salesforce_describe_decode,
    salesforce_report_decode,
    salesforce_request_locator,
    salesforce_soql_decode,
    soql_query_descriptor,
    soql_query_more_descriptor,
)

INSTANCE = "https://acme.my.salesforce.com"


def _reply(obj):
    import json as _json

    return HttpReply(status=200, headers={}, body=_json.dumps(obj).encode("utf-8"))


class TestLocator(unittest.TestCase):
    def test_soql_query_url(self):
        req = salesforce_request_locator(
            descriptor=soql_query_descriptor(),
            request_args={"instance_url": INSTANCE, "soql": "SELECT Id FROM Account"},
        )
        self.assertEqual(req.method, "GET")
        self.assertIn(f"/services/data/{DEFAULT_API_VERSION}/query?q=", req.url)
        self.assertIn("SELECT%20Id%20FROM%20Account", req.url)
        # no credential in the locator's headers
        self.assertNotIn("Authorization", req.headers)

    def test_soql_query_more_uses_vendor_cursor(self):
        cursor = "/services/data/v60.0/query/01g000-2000"
        req = salesforce_request_locator(
            descriptor=soql_query_more_descriptor(),
            request_args={"instance_url": INSTANCE, "cursor": cursor},
        )
        self.assertEqual(req.url, INSTANCE + cursor)

    def test_batch_size_header(self):
        req = salesforce_request_locator(
            descriptor=soql_query_descriptor(),
            request_args={
                "instance_url": INSTANCE,
                "soql": "SELECT Id FROM Account",
                "batch_size": 500,
            },
        )
        self.assertEqual(req.headers.get("Sforce-Query-Options"), "batchSize=500")

    def test_report_url(self):
        req = salesforce_request_locator(
            descriptor=report_run_descriptor(),
            request_args={"instance_url": INSTANCE, "report_id": "00O000000000001"},
        )
        self.assertIn("/analytics/reports/00O000000000001?includeDetails=true", req.url)

    def test_describe_url(self):
        req = salesforce_request_locator(
            descriptor=describe_descriptor(),
            request_args={"instance_url": INSTANCE, "sobject_type": "Account"},
        )
        self.assertIn("/sobjects/Account/describe", req.url)

    def test_non_https_instance_refused(self):
        with self.assertRaises(ValueError):
            salesforce_request_locator(
                descriptor=soql_query_descriptor(),
                request_args={"instance_url": "http://acme.example", "soql": "SELECT Id FROM A"},
            )


class TestDecode(unittest.TestCase):
    def test_soql_decode_non_terminal_carries_cursor(self):
        result = salesforce_soql_decode(
            _reply(
                {
                    "totalSize": 350,
                    "done": False,
                    "nextRecordsUrl": "/services/data/v60.0/query/01g-200",
                    "records": [{"Id": "001A"}, {"Id": "001B"}],
                }
            )
        )
        payload = result["payload"]
        self.assertIsInstance(payload, CollectionPayload)
        self.assertEqual(len(payload.items), 2)
        # RESULT3: cursor lives on the envelope, NOT the collection.
        self.assertEqual(result["next_cursor"], "/services/data/v60.0/query/01g-200")
        self.assertFalse(hasattr(payload, "next_cursor"))

    def test_soql_decode_terminal_has_no_cursor(self):
        result = salesforce_soql_decode(
            _reply(
                {
                    "totalSize": 1,
                    "done": True,
                    "records": [{"Id": "001C"}],
                }
            )
        )
        self.assertIsNone(result["next_cursor"])
        self.assertEqual(len(result["payload"].items), 1)

    def test_report_decode_is_snapshot_no_cursor(self):
        body = {
            "reportMetadata": {"detailColumns": ["ACCOUNT.NAME"]},
            "factMap": {"T!T": {"rows": []}},
        }
        result = salesforce_report_decode(_reply(body))
        payload = result["payload"]
        self.assertIsInstance(payload, CollectionPayload)
        self.assertEqual(len(payload.items), 1)  # the whole report body as one object
        self.assertIsNone(result["next_cursor"])

    def test_describe_decode_is_object(self):
        result = salesforce_describe_decode(_reply({"name": "Account", "fields": []}))
        self.assertIsInstance(result["payload"], ObjectPayload)
        self.assertEqual(result["payload"].object["name"], "Account")


if __name__ == "__main__":
    unittest.main()
