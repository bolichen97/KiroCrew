"""Zoom response decoder: a Zoom 2xx body -> the shared
:class:`~kiro_crew.connections.control_plane.result.OperationResult`, carrying
the returned records in the neutral ``payload`` channel and the SINGLE
authoritative ``next_cursor`` on the envelope.

WHAT THIS OWNS
==============
W01's production transport injects the 2xx -> ``OperationResult`` mapping as a
:data:`~kiro_crew.connections.control_plane.production.ResultDecode`, because
turning a vendor's body into the neutral shapes is the vendor's job. This module
is Zoom's decode. It takes the SHAPE of ``vendors/github/decoder.py``, not its
GitHub semantics:

* it puts the returned records into the ONE neutral data channel -- a
  :class:`~kiro_crew.connections.control_plane.result.CollectionPayload` for a
  ``list`` reply (Zoom wraps the page under ``meetings``), an
  :class:`~kiro_crew.connections.control_plane.result.ObjectPayload` for a
  single meeting object (``get`` / ``create`` / ``update``) -- via
  :func:`~kiro_crew.connections.control_plane.result.result_with_payload`, so a
  consumer reads the rows off ``ExecutionOutcome.payload`` and NOWHERE else;
* it sets the SINGLE authoritative ``next_cursor`` on the envelope so
  :class:`~kiro_crew.connections.control_plane.executor.PageWalk` advances on it
  alone.

WHERE ZOOM'S CURSOR COMES FROM (the established interface)
==========================================================
A Zoom cursor list carries its continuation IN THE BODY as ``next_page_token``
(absent/empty on the terminal page). This decoder reads it and folds it into the
one ``next_cursor`` through the W11-A paging unit's
:func:`~kiro_crew.connections.vendors.zoom.paging.to_next_cursor` -- the SAME
fold the pure helpers already use, not a second one. A cursor-less endpoint
(``get`` / a single meeting) NEVER has a cursor read for it: its decode is an
object payload with ``next_cursor=None``, so this module cannot invent a
continuation for an endpoint the paging unit declares cursor-less (the paging
unit's negative fault test 3, upheld on the decode side).

THE CURSOR IS SINGLE, AND LIVES ONLY ON THE ENVELOPE
====================================================
``CollectionPayload`` deliberately has no cursor of its own (W01 removed it at
``RESULT_SCHEMA_VERSION`` 3): a second copy is a second thing that can disagree.
:func:`result_with_payload` enforces that a cursor is passed ONLY with a
collection, so decoding a single object with a cursor is impossible by
construction.

WHAT THIS DELIBERATELY DOES NOT OWN
===================================
No error classification -- a non-2xx never reaches a ``ResultDecode`` (the
executor's :func:`~kiro_crew.connections.control_plane.executor.classify_error`
and Zoom's :func:`~kiro_crew.connections.vendors.zoom.errors.zoom_operation_error`
own that). No retry, no auth, no host verification (that is the dispatch layer's
readback, on the decoded object), no cache. A structurally impossible success
body is a :class:`ZoomDecodeError`, mirroring
``github/decoder.GithubDecodeError``.

See ``docs/system-specs/modules/connector-zoom.md``.
"""

from __future__ import annotations

import json
from typing import Any, List, Mapping, Optional

from kiro_crew.connections.control_plane.production import HttpReply
from kiro_crew.connections.control_plane.result import (
    CollectionPayload,
    ObjectPayload,
    OperationResult,
    result_with_payload,
)
from kiro_crew.connections.vendors.zoom.paging import to_next_cursor

#: The body key Zoom wraps a meetings list page under. A Zoom cursor list
#: returns ``{"page_size": .., "next_page_token": "..", "meetings": [ ... ]}``;
#: the records are under ``meetings``.
_LIST_COLLECTION_KEY = "meetings"

#: The body key carrying the continuation token on a Zoom cursor list.
_NEXT_PAGE_TOKEN_KEY = "next_page_token"


class ZoomDecodeError(ValueError):
    """A Zoom 2xx body was structurally malformed for its declared shape.

    A shaping fault only, mirroring ``github/decoder.GithubDecodeError``: a list
    reply whose ``meetings`` key is present but not a list, for instance. A Zoom
    HTTP failure is W01's typed boundary and never reaches a decode, so this is
    NOT a vendor-error class.
    """


def _parse_body(reply: HttpReply) -> Any:
    """Parse the reply body as JSON, or ``None`` when empty / non-JSON.

    An empty body (a 204-style acknowledgement, which Zoom's update returns) is
    ``None`` -- not an error -- so the caller decodes it as "no object", not a
    malformed body.
    """

    if not reply.body:
        return None
    try:
        return json.loads(reply.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _list_rows(parsed: Any) -> List[Mapping[str, Any]]:
    """The meeting row dicts of a Zoom list body.

    Zoom wraps the page under ``meetings``. A body missing the key, or with an
    empty page, yields ``[]``; a ``meetings`` value present but not a list is a
    :class:`ZoomDecodeError` rather than silently treated as empty (a malformed
    page must be loud, not a silent zero-row success).
    """

    if not isinstance(parsed, Mapping):
        return []
    inner = parsed.get(_LIST_COLLECTION_KEY)
    if inner is None:
        return []
    if not isinstance(inner, list):
        raise ZoomDecodeError(
            f"Zoom list body key {_LIST_COLLECTION_KEY!r} is present but not a list"
        )
    return [it for it in inner if isinstance(it, Mapping)]


def decode_list_page(reply: HttpReply) -> OperationResult:
    """Decode a Zoom cursor ``list`` reply into a collection payload.

    The rows go into a :class:`CollectionPayload`; the continuation is Zoom's
    body ``next_page_token``, folded into the SINGLE ``next_cursor`` through the
    paging unit's :func:`to_next_cursor` (present/non-empty -> the opaque cursor;
    absent/empty -> ``None``, the terminal page). Status is ``partial`` while a
    successor remains and ``ok`` on the terminal page -- the same convention the
    GitHub decoder uses, so a paging walk reads one shape across vendors.
    """

    parsed = _parse_body(reply)
    rows = _list_rows(parsed)
    payload = CollectionPayload(items=tuple(rows))
    token = parsed.get(_NEXT_PAGE_TOKEN_KEY) if isinstance(parsed, Mapping) else None
    next_cursor = to_next_cursor(token if isinstance(token, str) else None)
    if next_cursor is None:
        return result_with_payload(payload, status="ok", next_cursor=None)
    return result_with_payload(payload, status="partial", next_cursor=next_cursor)


def decode_single(reply: HttpReply) -> OperationResult:
    """Decode a single-meeting Zoom reply into an object payload (cursor-less).

    ``get`` / ``create`` / ``update`` return one meeting object. It goes into an
    :class:`ObjectPayload` with ``next_cursor=None`` -- there is no continuation,
    and a cursor is not even representable here (:func:`result_with_payload`
    refuses a cursor with a non-collection). A body that parses to a non-object
    (an empty update acknowledgement) yields a ``None`` payload rather than a
    forced object -- the operation returned no single object.
    """

    parsed = _parse_body(reply)
    if isinstance(parsed, Mapping):
        return result_with_payload(ObjectPayload(object=parsed), status="ok", next_cursor=None)
    return result_with_payload(None, status="ok", next_cursor=None)


def readback_host_id(reply: HttpReply) -> Optional[str]:
    """The ``host_id`` a create/update response reported, or ``None``.

    Exposed for the dispatch layer's host-readback gate: a create/update decodes
    to an :class:`ObjectPayload`, and the correctness check is that the object's
    ``host_id`` equals the requested target (an account-level S2S credential does
    not, by being account-level, prove the call hit the intended host). This only
    READS the value off the response body; the assertion itself is
    :func:`~kiro_crew.connections.vendors.zoom.meetings.verify_host_readback`. A
    body with no object, or no ``host_id``, yields ``None`` -- which the readback
    gate treats as ``unknown``, never as verified.
    """

    parsed = _parse_body(reply)
    if not isinstance(parsed, Mapping):
        return None
    host_id = parsed.get("host_id")
    return host_id if isinstance(host_id, str) and host_id else None


__all__ = [
    "ZoomDecodeError",
    "decode_list_page",
    "decode_single",
    "readback_host_id",
]
