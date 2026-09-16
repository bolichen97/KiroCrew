"""Zoom request locator: turn an ``operation_id`` + typed args into ONE concrete
:class:`~kiro_crew.connections.control_plane.production.HttpRequest`.

WHAT THIS OWNS
==============
W01's production transport (``control_plane/production.py``) is deliberately
vendor-blind: it composes credential custody + wire mechanics and INJECTS the
step that shapes an operation into a concrete method/URL/headers/body, because
that shape is the vendor owner's. This module is Zoom's implementation of that
injected :data:`~kiro_crew.connections.control_plane.production.RequestLocator`,
the same role ``vendors/github/locator.py`` plays for GitHub and
``vendors/microsoft/graph/locator.py`` for Graph. It takes the SHAPE of the
GitHub sibling, not its semantics.

It is pure logic and holds NO credential: the transport reveals the secret into
an ``Authorization: Bearer`` header itself (``build_production_transport`` step
4), so a locator that touched a token would be reaching across the boundary the
production module drew. Every request this builds carries vendor headers WITHOUT
a credential.

HOW IT STAYS HONEST (Zoom-specific, reused not re-derived)
==========================================================
The Zoom identity/paging semantics are NOT re-implemented here -- they come from
the W11-A vendor units and the W11-C request builders in
:mod:`kiro_crew.connections.vendors.zoom.meetings`:

* **Numeric ``meetingId`` and per-instance UUID stay separate address spaces.**
  A numeric id goes into the path verbatim; a UUID is routed through
  :func:`~kiro_crew.connections.vendors.zoom.identity.encode_uuid_path_segment`,
  which DOUBLE URL-encodes a UUID beginning with ``/`` or containing ``//``.
  This module never string-concatenates a raw id into a path.
* **Recurrence targeting is decided by ``occurrence_id``.** The update builder
  reads the target through
  :func:`~kiro_crew.connections.vendors.zoom.identity.occurrence_target`: a
  non-empty ``occurrence_id`` becomes a query parameter hitting that one
  occurrence, a missing one targets the parent series -- never a fabricated id.
* **Pagination is per-endpoint.** ``list`` renders ``page_size`` +
  ``next_page_token`` through the paging unit's cursor discipline; the
  cursor-less ``get`` / ``create`` / ``update`` never carry a ``next_page_token``.
  When the executor's :class:`~kiro_crew.connections.control_plane.executor.PageWalk`
  hands back the opaque continuation as ``request_args["cursor"]``, this locator
  feeds it to the ``list`` builder as ``next_page_token`` -- the one place a
  Zoom cursor re-enters a request.
* **Per-occurrence ``start_time`` + series ``timezone``; no local-time
  inference.** The create/update builders bind them via
  :func:`~kiro_crew.connections.vendors.zoom.identity.resolve_occurrence_time`.

WHAT THIS DELIBERATELY DOES NOT OWN
===================================
No auth, no custody, no retry, no error classification, no transport -- those
are W01's, consumed. A shaping fault is a :class:`ZoomLocatorError` (a
``ValueError``); a Zoom HTTP failure is W01's typed boundary via the executor /
:func:`~kiro_crew.connections.vendors.zoom.errors.zoom_operation_error`, never
here. Do not grow a vendor-error hierarchy in this module.

See ``docs/system-specs/modules/connector-zoom.md``.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Mapping, Optional

from kiro_crew.connections.control_plane.production import HttpRequest
from kiro_crew.connections.vendors.zoom.meetings import (
    OP_CREATE,
    OP_GET,
    OP_LIST,
    OP_UPDATE,
    ZoomRequest,
    build_create_request,
    build_get_request,
    build_list_request,
    build_update_request,
)

#: The absolute Zoom REST v2 base every request is built under. Kept a module
#: constant (not string-interpolated per call) so one place defines the host and
#: a test can point it at a loopback origin, exactly as the GitHub sibling's
#: ``GITHUB_API_BASE`` is monkeypatched for its real-TLS test.
ZOOM_API_BASE = "https://api.zoom.us/v2"

#: The request-arg key the executor / ``PageWalk`` carries a continuation cursor
#: under. ``PageWalk`` injects ``{"cursor": <value>}`` per page; this locator
#: reads it and feeds it to the ``list`` builder as Zoom's ``next_page_token``.
#: Its value is whatever the decoder put on ``OperationResult.next_cursor`` --
#: for Zoom that is the opaque ``next_page_token`` string.
CURSOR_ARG = "cursor"

#: The request-arg key naming the caller's desired page size for a cursor list.
#: Defaulted per the Zoom list contract when absent.
PAGE_SIZE_ARG = "page_size"

#: Zoom's documented default/again-safe list page size when a caller names none.
DEFAULT_PAGE_SIZE = 30


class ZoomLocatorError(ValueError):
    """A Zoom request could not be shaped from an operation + its params.

    A ``ValueError`` subclass mirroring ``github/locator.GithubLocatorError`` and
    ``graph/locator.GraphLocatorError``: a SHAPING fault (an unknown
    ``operation_id``, a missing required parameter, an invalid page size), NOT a
    vendor error. This slice defines no vendor-error taxonomy -- a Zoom HTTP
    failure is W01's typed boundary, classified by the executor /
    :func:`~kiro_crew.connections.vendors.zoom.errors.zoom_operation_error`. Do
    not grow an error hierarchy here.
    """


def _abs_url(path: str, query: Mapping[str, Any]) -> str:
    """Build an absolute ``https`` URL from a path + query mapping.

    The path is already assembled by the request builder (with any UUID
    double-encoding applied to the segments), so it is joined to
    :data:`ZOOM_API_BASE` verbatim and the query is percent-encoded with
    ``urlencode``. Query values are stringified; a ``None`` value is dropped
    rather than serialized as the literal ``"None"``.
    """

    filtered = {k: v for k, v in query.items() if v is not None}
    encoded = urllib.parse.urlencode({k: str(v) for k, v in filtered.items()})
    url = f"{ZOOM_API_BASE}{path}"
    if encoded:
        url = f"{url}?{encoded}"
    return url


def _body_bytes(body: Optional[Mapping[str, Any]]) -> Optional[bytes]:
    """Encode a JSON body to bytes, or ``None`` when there is no body.

    An empty mapping (a mutation whose caller supplied no fields) still encodes
    to ``{}`` so the request has a JSON body and a ``Content-Type`` the transport
    can set, rather than a bodyless POST/PATCH that some providers reject.
    """

    if body is None:
        return None
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _to_http_request(zoom_request: ZoomRequest) -> HttpRequest:
    """Convert a :class:`ZoomRequest` (pure data) into a W01 :class:`HttpRequest`.

    Headers carry NO credential -- the transport adds ``Authorization`` itself
    (:func:`~kiro_crew.connections.control_plane.production.build_production_transport`
    step 4). A body-bearing request declares ``Content-Type: application/json``;
    a bodyless GET declares none.
    """

    body = _body_bytes(zoom_request.body)
    headers: dict[str, str] = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return HttpRequest(
        method=zoom_request.method,
        url=_abs_url(zoom_request.path, zoom_request.query),
        headers=headers,
        body=body,
    )


def _require(request_args: Mapping[str, Any], key: str) -> Any:
    """Return a required request arg or raise a :class:`ZoomLocatorError`."""

    if key not in request_args or request_args[key] in (None, ""):
        raise ZoomLocatorError(f"request is missing required parameter {key!r}")
    return request_args[key]


def _page_size(request_args: Mapping[str, Any]) -> int:
    """Read the caller's page size for a list, defaulting per the Zoom contract.

    A supplied non-integer or non-positive size is a shaping fault (refused here)
    rather than passed to the builder, which would raise anyway -- refusing here
    gives the caller a locator-scoped message.
    """

    raw = request_args.get(PAGE_SIZE_ARG, DEFAULT_PAGE_SIZE)
    try:
        size = int(raw)
    except (TypeError, ValueError) as exc:
        raise ZoomLocatorError(f"{PAGE_SIZE_ARG!r} must be an integer, got {raw!r}") from exc
    if size <= 0:
        raise ZoomLocatorError(f"{PAGE_SIZE_ARG!r} must be a positive integer, got {size}")
    return size


# Keys the paging/size machinery consumes here; everything else on a create /
# update is a body field the caller asked to write.
_RESERVED_ARGS = frozenset({CURSOR_ARG, PAGE_SIZE_ARG})

# Keys the meetings builders take as explicit keyword arguments; a create/update
# passes the rest through ``extra`` as vendor body fields (settings, agenda,
# recurrence spec), so a caller can set a field this module does not name
# without the locator having to enumerate every Zoom meeting field.
_LIST_ARGS = frozenset({"user_id", CURSOR_ARG, PAGE_SIZE_ARG})
_GET_ARGS = frozenset({"meeting_id", "occurrence_id"})
_MUTATION_NAMED = frozenset({"topic", "start_time", "timezone", "duration"})


def _extra_body(request_args: Mapping[str, Any], *, structural: frozenset[str]) -> dict[str, Any]:
    """The caller's additional body fields -- everything not structural/reserved.

    ``structural`` names the keys the builder consumes as explicit arguments
    (``meeting_id`` / ``user_id`` / ``occurrence_id`` / the named body fields);
    the rest are vendor body fields passed through ``extra``. The builder's
    ``_meeting_body`` merges these with ``setdefault`` so they never override the
    identity/time fields it owns.
    """

    skip = structural | _RESERVED_ARGS
    return {k: v for k, v in request_args.items() if k not in skip}


def build_request(operation_id: str, request_args: Mapping[str, Any]) -> HttpRequest:
    """Shape one Zoom meetings operation + its args into an :class:`HttpRequest`.

    The core of the locator, split out from :func:`locate` so it is testable
    without the transport's keyword surface. It routes on the four
    ``operation_id`` values this stream owns and delegates the actual path/query/
    body construction to the W11-C builders in
    :mod:`kiro_crew.connections.vendors.zoom.meetings`, which apply the Zoom
    identity/recurrence/time invariants; this function only maps args in and the
    resulting :class:`ZoomRequest` out to a W01 :class:`HttpRequest`.

    Paging: for ``list`` the executor/``PageWalk`` carries the opaque
    continuation under ``request_args["cursor"]``; it is fed to the list builder
    as Zoom's ``next_page_token``. ``get`` / ``create`` / ``update`` are
    cursor-less and ignore it. An unknown ``operation_id`` is refused.
    """

    if operation_id == OP_LIST:
        user_id = _require(request_args, "user_id")
        cursor = request_args.get(CURSOR_ARG)
        next_page_token = cursor if isinstance(cursor, str) and cursor else None
        zoom_request = build_list_request(
            str(user_id),
            page_size=_page_size(request_args),
            next_page_token=next_page_token,
        )
        return _to_http_request(zoom_request)

    if operation_id == OP_GET:
        meeting_id = _require(request_args, "meeting_id")
        occurrence_id = request_args.get("occurrence_id")
        zoom_request = build_get_request(
            str(meeting_id),
            occurrence_id=occurrence_id if occurrence_id else None,
        )
        return _to_http_request(zoom_request)

    if operation_id == OP_CREATE:
        user_id = _require(request_args, "user_id")
        zoom_request = build_create_request(
            str(user_id),
            topic=request_args.get("topic"),
            start_time=request_args.get("start_time"),
            timezone=request_args.get("timezone"),
            duration=request_args.get("duration"),
            extra=_extra_body(request_args, structural=_MUTATION_NAMED | {"user_id"}),
        )
        return _to_http_request(zoom_request)

    if operation_id == OP_UPDATE:
        meeting_id = _require(request_args, "meeting_id")
        occurrence_id = request_args.get("occurrence_id")
        zoom_request = build_update_request(
            str(meeting_id),
            occurrence_id=occurrence_id if occurrence_id else None,
            topic=request_args.get("topic"),
            start_time=request_args.get("start_time"),
            timezone=request_args.get("timezone"),
            duration=request_args.get("duration"),
            extra=_extra_body(
                request_args, structural=_MUTATION_NAMED | {"meeting_id", "occurrence_id"}
            ),
        )
        return _to_http_request(zoom_request)

    raise ZoomLocatorError(f"operation {operation_id!r} is not a known Zoom meetings operation")


def locate(
    *,
    service_id: str,
    credential_mode: str,
    descriptor: Mapping[str, Any],
    request_args: Mapping[str, Any],
    request_idempotency_key: str = "",
    **_ignored: Any,
) -> HttpRequest:
    """The injected :data:`RequestLocator` Zoom hands to the transport.

    Matches the keyword surface W01's
    :func:`~kiro_crew.connections.control_plane.production.build_production_transport`
    calls a locator with (``service_id`` / ``credential_mode`` / ``descriptor`` /
    ``request_args`` / ``request_idempotency_key``). It reads the campaign
    ``operation_id`` off the control-plane descriptor and delegates to
    :func:`build_request`; the routing axes the transport passes are the trusted
    ones off the handle view, so this asserts the call is a Zoom call before
    shaping it.

    ``service_id`` is asserted to be ``zoom`` -- the transport routes on the
    trusted view's service, and a locator composed for Zoom receiving another
    service's call is a composition error, refused rather than shaped. A
    descriptor with no ``operation_id`` is a shaping fault. The credential mode is
    not read here (the transport attaches the credential itself); it is accepted
    to match the surface and otherwise ignored.
    """

    if service_id != "zoom":
        raise ZoomLocatorError(
            f"the Zoom locator was handed a call routed at service {service_id!r}; "
            "a locator composed for Zoom does not shape another service's request"
        )
    operation_id = descriptor.get("operation_id")
    if not isinstance(operation_id, str) or not operation_id:
        raise ZoomLocatorError("descriptor carries no operation_id to shape a request from")
    return build_request(operation_id, request_args)


__all__ = [
    "CURSOR_ARG",
    "DEFAULT_PAGE_SIZE",
    "PAGE_SIZE_ARG",
    "ZOOM_API_BASE",
    "ZoomLocatorError",
    "build_request",
    "locate",
]
