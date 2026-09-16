"""Salesforce REST request-shaping and result-decoding for the control plane.

The W01 control-plane executor
(:mod:`kiro_crew.connections.control_plane.executor`) decides and dispatches; its
production transport
(:mod:`kiro_crew.connections.control_plane.production`) owns credential custody
and the wire, but leaves TWO vendor-owned holes it INJECTS:

* :data:`~kiro_crew.connections.control_plane.production.RequestLocator` -- turn an
  operation + its arguments into ONE concrete
  :class:`~kiro_crew.connections.control_plane.production.HttpRequest` (method,
  absolute ``https`` URL, headers WITHOUT the credential -- the transport adds
  ``Authorization`` itself).
* :data:`~kiro_crew.connections.control_plane.production.ResultDecode` -- map a
  2xx :class:`~kiro_crew.connections.control_plane.production.HttpReply` to the
  L01 success envelope, INCLUDING the ``payload`` (the items/object the caller
  reads), built with
  :func:`~kiro_crew.connections.control_plane.result.result_with_payload` so the
  envelope's ``next_cursor`` cannot disagree with the collection's.

This module fills BOTH holes for Salesforce, and NOTHING else: it opens no
socket, holds no secret, and builds no second transport/auth/vault. It shapes
the two structured read paths this connector serves:

* **SOQL object path** -- ``GET /services/data/vXX.X/query?q=<SOQL>`` for the
  first page and ``GET <nextRecordsUrl>`` (the opaque L1 query-locator) for each
  subsequent page. The decode reads the L1 REST query-page contract
  (``{done, records, nextRecordsUrl}``) and returns a
  :class:`~kiro_crew.connections.control_plane.result.CollectionPayload` whose
  cursor is the ``nextRecordsUrl`` (``None`` on the terminal page), so the
  executor's :class:`~kiro_crew.connections.control_plane.executor.PageWalk`
  advances on a REAL cursor.
* **Report / Analytics path** -- ``GET /services/data/vXX.X/analytics/reports/
  {id}?includeDetails=true``. Its result is a fact grid, NOT a record list, and
  it is capped at 2000 rows with no continuation cursor, so the decode returns a
  single-page :class:`CollectionPayload` with ``next_cursor=None`` (a report is a
  bounded snapshot, not a paged stream).

Facts search-snippet corroborated (``developer.salesforce.com`` rejects
automated fetches with HTTP 403).
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Mapping, Optional

from kiro_crew.connections.control_plane.operation import OperationDescriptor
from kiro_crew.connections.control_plane.production import HttpReply, HttpRequest
from kiro_crew.connections.control_plane.result import (
    CollectionPayload,
    ObjectPayload,
    OperationResult,
    result_with_payload,
)

#: The default Salesforce REST API version path segment. A caller may override
#: per source; this is the floor the offline core was corroborated against.
DEFAULT_API_VERSION = "v60.0"

# ── operation ids + descriptors (declared, never invented per-call) ────────
OP_SOQL_QUERY = "salesforce.soql_query"
OP_SOQL_QUERY_MORE = "salesforce.soql_query_more"
OP_REPORT_RUN = "salesforce.report_run"
OP_DESCRIBE = "salesforce.describe_sobject"

#: Every read here authenticates as the user's own OAuth grant, a scoped PAT, or
#: a service credential -- the manifest's three auth modes. The descriptor
#: DECLARES the set; the per-call context picks one (never outside this set).
_READ_MODES: tuple = ("oauth_user", "fine_grained_pat", "service_to_service")


def soql_query_descriptor() -> OperationDescriptor:
    """The list-read descriptor for a SOQL query (first page)."""
    return OperationDescriptor(
        operation_id=OP_SOQL_QUERY,
        service_id="salesforce",
        operation_kind="list",
        effect="read",
        credential_modes=_READ_MODES,
    )


def soql_query_more_descriptor() -> OperationDescriptor:
    """The list-read descriptor for a subsequent SOQL page (query-locator)."""
    return OperationDescriptor(
        operation_id=OP_SOQL_QUERY_MORE,
        service_id="salesforce",
        operation_kind="list",
        effect="read",
        credential_modes=_READ_MODES,
    )


def report_run_descriptor() -> OperationDescriptor:
    """The single-fetch descriptor for running an Analytics report."""
    return OperationDescriptor(
        operation_id=OP_REPORT_RUN,
        service_id="salesforce",
        operation_kind="single_fetch",
        effect="read",
        credential_modes=_READ_MODES,
    )


def describe_descriptor() -> OperationDescriptor:
    """The single-fetch descriptor for an sObject describe."""
    return OperationDescriptor(
        operation_id=OP_DESCRIBE,
        service_id="salesforce",
        operation_kind="single_fetch",
        effect="read",
        credential_modes=_READ_MODES,
    )


def _base(instance_url: str) -> str:
    return instance_url.rstrip("/")


# ── RequestLocator: operation + args → one concrete HttpRequest ────────────
def salesforce_request_locator(
    *,
    descriptor: OperationDescriptor,
    request_args: Mapping[str, Any],
    **_ignored: Any,
) -> HttpRequest:
    """Shape a Salesforce read operation into one ``https`` :class:`HttpRequest`.

    Reads ``instance_url`` and ``api_version`` from ``request_args`` (the source's
    org coordinates), plus the operation-specific selector:

    * ``salesforce.soql_query`` -- needs ``soql``; builds
      ``GET {instance}/services/data/{ver}/query?q=<url-encoded SOQL>``.
    * ``salesforce.soql_query_more`` -- needs ``cursor`` (the opaque
      ``nextRecordsUrl`` locator the prior page returned); builds
      ``GET {instance}<cursor>``. The cursor is an absolute PATH the vendor
      returned, so it is joined onto the instance origin and never re-encoded.
    * ``salesforce.report_run`` -- needs ``report_id``; builds
      ``GET {instance}/services/data/{ver}/analytics/reports/{id}?includeDetails=true``.

    No ``Authorization`` header is set -- the production transport adds the
    credential itself, so a locator never touches a secret. A ``batch_size`` hint
    (200..2000) becomes the ``Sforce-Query-Options`` header on the SOQL paths.
    """
    op = descriptor["operation_id"]
    instance_url = str(request_args.get("instance_url") or "").rstrip("/")
    if not instance_url.startswith("https://"):
        raise ValueError("Salesforce instance_url must be an absolute https URL")
    version = str(request_args.get("api_version") or DEFAULT_API_VERSION)
    headers: dict[str, str] = {"Accept": "application/json"}
    batch = request_args.get("batch_size")
    if isinstance(batch, int) and 200 <= batch <= 2000:
        headers["Sforce-Query-Options"] = f"batchSize={batch}"

    if op == OP_SOQL_QUERY:
        # PageWalk reuses ONE descriptor across pages and appends the cursor to
        # the base args, so a page carries both the original ``soql`` AND a
        # ``cursor``. Page 1 has cursor=None -> issue the query; page 2+ has the
        # vendor's nextRecordsUrl -> follow it (query-more), never re-issue the
        # query (which would re-fetch page 1 forever).
        cursor = request_args.get("cursor")
        if isinstance(cursor, str) and cursor:
            url = urllib.parse.urljoin(_base(instance_url) + "/", cursor.lstrip("/"))
            return HttpRequest(method="GET", url=url, headers=headers)
        soql = str(request_args.get("soql") or "")
        if not soql:
            raise ValueError("soql_query needs a 'soql' argument")
        url = f"{_base(instance_url)}/services/data/{version}/query?q=" + urllib.parse.quote(
            soql, safe=""
        )
        return HttpRequest(method="GET", url=url, headers=headers)

    if op == OP_SOQL_QUERY_MORE:
        cursor = request_args.get("cursor")
        if not cursor or not isinstance(cursor, str):
            raise ValueError("soql_query_more needs a string 'cursor' (nextRecordsUrl)")
        # The nextRecordsUrl is an absolute path on the same instance; join it
        # onto the origin. urljoin keeps a full path and rejects switching host.
        url = urllib.parse.urljoin(_base(instance_url) + "/", cursor.lstrip("/"))
        return HttpRequest(method="GET", url=url, headers=headers)

    if op == OP_REPORT_RUN:
        report_id = str(request_args.get("report_id") or "")
        if not report_id:
            raise ValueError("report_run needs a 'report_id' argument")
        url = (
            f"{_base(instance_url)}/services/data/{version}"
            f"/analytics/reports/{urllib.parse.quote(report_id, safe='')}?includeDetails=true"
        )
        return HttpRequest(method="GET", url=url, headers={"Accept": "application/json"})

    if op == OP_DESCRIBE:
        sobject = str(request_args.get("sobject_type") or "")
        if not sobject:
            raise ValueError("describe_sobject needs a 'sobject_type' argument")
        url = (
            f"{_base(instance_url)}/services/data/{version}"
            f"/sobjects/{urllib.parse.quote(sobject, safe='')}/describe"
        )
        return HttpRequest(method="GET", url=url, headers={"Accept": "application/json"})

    raise ValueError(f"unknown Salesforce operation_id {op!r}")


# ── ResultDecode: 2xx HttpReply → OperationResult (+payload) ───────────────
def _json_body(reply: HttpReply) -> Mapping[str, Any]:
    try:
        data = json.loads(reply.body.decode("utf-8")) if reply.body else {}
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"Salesforce reply body is not valid JSON: {exc}") from None
    if not isinstance(data, Mapping):
        raise ValueError("Salesforce reply body is not a JSON object")
    return data


def salesforce_soql_decode(reply: HttpReply, **_ignored: Any) -> OperationResult:
    """Decode a SOQL query/query-more 2xx into a paged :class:`CollectionPayload`.

    The body is the L1 REST query-page shape ``{totalSize, done, records,
    [nextRecordsUrl]}``. The records are carried as the collection's items and
    the ``nextRecordsUrl`` becomes the collection's ``next_cursor`` (``None`` on
    the terminal page), so the executor's ``PageWalk`` advances on the REAL
    vendor locator -- never a fabricated one. Contract violations (a
    ``done=false`` page with no locator, etc.) are the L1 parser's to raise; here
    the raw shape is carried and the cursor derived from ``done``.
    """
    body = _json_body(reply)
    records = body.get("records")
    items = tuple(r for r in records if isinstance(r, Mapping)) if isinstance(records, list) else ()
    done = body.get("done")
    next_cursor: Optional[str] = None
    if done is False:
        locator = body.get("nextRecordsUrl")
        next_cursor = locator if isinstance(locator, str) and locator else None
    payload = CollectionPayload(items=items, next_cursor=next_cursor)
    return result_with_payload(payload, status="ok")


def salesforce_report_decode(reply: HttpReply, **_ignored: Any) -> OperationResult:
    """Decode an Analytics report-run 2xx into a single-page collection.

    A report result is a bounded (<=2000-row) fact grid with NO continuation
    cursor, so the whole report body is carried as ONE object in a
    :class:`CollectionPayload` with ``next_cursor=None`` -- the connector's
    report converter reads the grid out of it. It is a collection of one so the
    connector's fetch loop treats both paths uniformly; the report is not a paged
    stream, hence no cursor.
    """
    body = _json_body(reply)
    # The full report result travels as a single object; the connector converts
    # its factMap into rows. No cursor: a report is a bounded snapshot.
    payload = CollectionPayload(items=(dict(body),), next_cursor=None)
    return result_with_payload(payload, status="ok")


def salesforce_describe_decode(reply: HttpReply, **_ignored: Any) -> OperationResult:
    """Decode an sObject-describe 2xx into a single :class:`ObjectPayload`.

    A describe is one object (the sObject's describe result), not a list, so it
    carries no cursor. The connector parses it into the L1 ``ObjectDescribe``.
    """
    body = _json_body(reply)
    return result_with_payload(ObjectPayload(object=dict(body)), status="ok")


__all__ = [
    "DEFAULT_API_VERSION",
    "OP_DESCRIBE",
    "OP_REPORT_RUN",
    "OP_SOQL_QUERY",
    "OP_SOQL_QUERY_MORE",
    "describe_descriptor",
    "report_run_descriptor",
    "salesforce_describe_decode",
    "salesforce_report_decode",
    "salesforce_request_locator",
    "salesforce_soql_decode",
    "soql_query_descriptor",
    "soql_query_more_descriptor",
]
