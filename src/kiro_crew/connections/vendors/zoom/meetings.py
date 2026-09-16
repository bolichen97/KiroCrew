"""Zoom meetings actions (W11-C): the four real operations, on the W01 seam.

The Zoom meetings connector exposes four real actions -- ``list`` / ``get`` /
``create`` / ``update`` -- and this module DECLARES and BUILDS them against the
already-landed W01 control plane. It carries three things and no more:

* a :class:`kiro_crew.connections.control_plane.OperationDescriptor` per action
  (what the operation is: its ``service_id`` ``"zoom"``, its ``operation_kind``,
  its ``effect``, and the ``credential_modes`` set it permits), consuming the
  shared descriptor shape rather than a Zoom-local one;
* request construction -- the HTTP method, the path (with the identity unit's
  UUID double-encoding and the recurrence ``occurrence_id`` query rule applied),
  the query parameters (the paging unit's cursor discipline), and the JSON body
  (per-occurrence ``start_time`` + series ``timezone``, no local-time
  inference); and
* response mapping -- a page's ``next_page_token`` folded into the shared
  :class:`kiro_crew.connections.control_plane.OperationResult`'s opaque
  ``next_cursor`` on success, and a Zoom failure folded through
  :func:`kiro_crew.connections.vendors.zoom.errors.zoom_operation_error` into
  the shared :class:`kiro_crew.connections.control_plane.OperationError` on
  failure.

What this module deliberately does NOT do
------------------------------------------
It builds no HTTP client, holds no credential, opens no socket, and dispatches
nothing. Auth, binding, dispatch, approval, and the ambiguous-write decision are
the shared control plane's (W01's) sole surface; this module never reimplements
them, never invents a second runtime, and never ghost-writes a W01 file. It also
does NOT resolve a credential value from a ``binding_ref`` -- an
:class:`~kiro_crew.connections.control_plane.context.OperationContext` carries
references only, and the resolution to a live token is a later leaf. The request
this module builds is a pure data description (method + path + params + body)
that such a leaf later sends; nothing here transmits it.

Invariants folded from the W11-A vendor units (never re-derived, never
collapsed)
-------------------------------------------------------------------------------
* **Numeric ``meetingId`` and per-instance UUID are separate address spaces.**
  A numeric id goes into a path segment verbatim; a UUID is encoded through
  :func:`~kiro_crew.connections.vendors.zoom.identity.encode_uuid_path_segment`,
  which DOUBLE URL-encodes a UUID that begins with ``/`` or contains ``//``.
  Passing a UUID where a numeric id belongs, or skipping the double-encode, is
  refused / handled by the identity unit -- this module only routes each id
  through the right door.
* **Recurrence update targeting is decided by ``occurrence_id``.** An update
  carrying a non-empty ``occurrence_id`` targets that ONE occurrence (the id is
  sent as a query parameter); the same update MISSING ``occurrence_id`` targets
  the parent series -- and therefore the whole recurring series. This module
  reads the target through
  :func:`~kiro_crew.connections.vendors.zoom.identity.occurrence_target` and
  never silently promotes a single-occurrence intent to a series edit.
* **Per-occurrence ``start_time`` + series ``timezone``; no local-time
  inference.** A create/update body carries the ``start_time`` verbatim and the
  series ``timezone`` beside it, bound through
  :func:`~kiro_crew.connections.vendors.zoom.identity.resolve_occurrence_time`.
  A ``start_time`` without a governing timezone is carried as-is; this module
  never guesses a wall-clock instant or substitutes a local zone.
* **Pagination is per-endpoint, and the opaque cursor is the control plane's.**
  ``list`` is a cursor endpoint (the paging unit classifies it); ``get`` /
  ``create`` / ``update`` are cursor-less and this module never attaches a
  cursor to them. A page's ``next_page_token`` folds to
  ``OperationResult.next_cursor`` through
  :func:`~kiro_crew.connections.vendors.zoom.paging.to_next_cursor`.
* **Error order is fixed: Zoom pre-redaction THEN the control plane compose.**
  A failure is mapped through
  :func:`~kiro_crew.connections.vendors.zoom.errors.zoom_operation_error`, which
  scrubs Zoom-shape credentials first and then hands the detail to the control
  plane's :func:`~kiro_crew.connections.control_plane.operation_error`. This
  module never builds an :class:`OperationError` by any other path, so no
  un-redacted error text or signed ``download_url`` / ``play_url`` / token can
  reach a ``detail`` -- and code ``3001``'s "real absence vs un-double-encoded
  UUID" ambiguity stays ``ambiguous``, never collapsed to ``not_found``.

Credential-identity vs target-host, kept distinct
-------------------------------------------------
Zoom authenticates with two of the three shared credential modes -- ``oauth_user``
and ``service_to_service`` (Server-to-Server account-credentials: account id +
client id + secret, NO refresh token) -- declared per operation from the W11-A
:data:`~kiro_crew.connections.vendors.zoom.identity.ZOOM_CREDENTIAL_MODES` set.
An account-level ``service_to_service`` credential does NOT, by being
account-level, prove it can or cannot target a specific human host: that depends
on the scopes the account admin authorized, a per-operation/per-account fact.
So an unverified ``(auth_mode, host)`` pair stays
:data:`~kiro_crew.connections.vendors.zoom.identity.HOST_REACHABILITY_UNKNOWN`
in either direction, and every create/update READS BACK ``host_id`` and asserts
it equals the requested target (:func:`verify_host_readback`) -- a create that
silently ran against a different host than intended is a correctness failure the
credential mode alone cannot rule out.

See ``docs/system-specs/modules/connector-zoom.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from kiro_crew.connections.control_plane import (
    CREDENTIAL_MODES,
    EFFECTS,
    OPERATION_KINDS,
    SERVICE_IDS,
    CollectionPayload,
    CredentialMode,
    ObjectPayload,
    OperationDescriptor,
    OperationError,
    OperationResult,
    ResultStatus,
    result_with_payload,
)
from kiro_crew.connections.vendors.zoom.errors import zoom_operation_error
from kiro_crew.connections.vendors.zoom.identity import (
    HOST_REACHABILITY_UNKNOWN,
    ZOOM_CREDENTIAL_MODES,
    OccurrenceTarget,
    OccurrenceTime,
    encode_uuid_path_segment,
    occurrence_target,
    resolve_occurrence_time,
)
from kiro_crew.connections.vendors.zoom.paging import (
    classify_pagination,
    next_cursor_request,
    to_next_cursor,
)

#: Bumped when this module's descriptor/request shapes change, mirroring the
#: module-level schema-version constant every sibling vendor/control-plane unit
#: carries.
MEETINGS_SCHEMA_VERSION = 1

# --- operation ids: the campaign's neutral Zoom operation identities --------
# These match the paging unit's own operation-id table (``paging.py``'s
# ``_PAGINATION_BY_OPERATION``) so the pagination discipline for ``list`` / ``get``
# is looked up, never restated. ``create`` / ``update`` are cursor-less
# mutations and are not in that table (a mutation has no page to follow); this
# module simply never asks the paging unit about them.
OP_LIST = "zoom.meetings.list"
OP_GET = "zoom.meetings.get"
OP_CREATE = "zoom.meetings.create"
OP_UPDATE = "zoom.meetings.update"

# --- Zoom REST base and endpoint templates ---------------------------------
# Path templates only; no host, no scheme baked into the descriptor. The path
# is what varies with identity/recurrence and is what this module constructs.
_USER_MEETINGS = "/users/{userId}/meetings"
_MEETING = "/meetings/{meetingId}"


# ---------------------------------------------------------------------------
# License / role scope, declared per operation and conditionally
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LicenseScope:
    """A per-operation license/role-scope declaration.

    ``oauth_scopes`` are the granular Zoom OAuth scopes the operation needs
    (e.g. ``meeting:read``); a Server-to-Server app is authorized for the same
    scope names at the account level. ``min_plan`` names the minimum
    subscription tier when the operation is plan-gated, or ``None`` when it is
    not. ``conditional`` records a scope that applies only under a stated
    condition (e.g. a create/update targeting another user's calendar needs a
    broader ``meeting:write:admin`` than a self-scheduled ``meeting:write``),
    so the declaration is honest about being conditional rather than asserting
    the broad scope unconditionally.
    """

    oauth_scopes: tuple[str, ...]
    min_plan: Optional[str] = None
    conditional: Mapping[str, str] = field(default_factory=dict)


# Scope declarations per operation. ``meeting:read`` / ``meeting:write`` are
# Zoom's own granular scope names for the Meetings API; the ``:admin`` variants
# are the account-scoped forms an S2S app or an admin acting on another user's
# calendar uses. license min-plan for basic meeting CRUD is None (Basic/free can
# schedule meetings); the AI-Companion summary tier gate lives in the processing
# unit's spec, not on these CRUD ops.
_LICENSE_BY_OPERATION: dict[str, LicenseScope] = {
    OP_LIST: LicenseScope(oauth_scopes=("meeting:read",)),
    OP_GET: LicenseScope(oauth_scopes=("meeting:read",)),
    OP_CREATE: LicenseScope(
        oauth_scopes=("meeting:write",),
        conditional={
            # Scheduling on ANOTHER user's calendar (userId != "me") requires
            # the account-scoped admin form, not the self scope.
            "other_user_target": "meeting:write:admin",
        },
    ),
    OP_UPDATE: LicenseScope(
        oauth_scopes=("meeting:write",),
        conditional={"other_user_target": "meeting:write:admin"},
    ),
}


def license_scope(operation_id: str) -> LicenseScope:
    """Return the license/role-scope declaration for a meetings operation.

    Raises ``KeyError`` for an operation this module does not own, rather than
    defaulting to an empty scope set (an empty set would falsely assert "needs
    nothing").
    """
    try:
        return _LICENSE_BY_OPERATION[operation_id]
    except KeyError as exc:
        raise KeyError(
            f"{operation_id!r} is not a Zoom meetings operation this module declares; "
            "declare its license scope explicitly rather than assuming none"
        ) from exc


# ---------------------------------------------------------------------------
# OperationDescriptors -- the shared W01 TypedDict, one per action
# ---------------------------------------------------------------------------
# service_id is "zoom" (a member of the shared SERVICE_IDS); credential_modes is
# the two-value Zoom subset (no fine_grained_pat); operation_kind/effect are the
# shared closed-set values. These are the CANONICAL control-plane descriptors,
# not a Zoom-local dataclass: a dispatch reads one shape across W02..W14.
_DESCRIPTORS: dict[str, OperationDescriptor] = {
    OP_LIST: {
        "operation_id": OP_LIST,
        "service_id": "zoom",
        "operation_kind": "list",
        "effect": "read",
        "credential_modes": ZOOM_CREDENTIAL_MODES,
    },
    OP_GET: {
        "operation_id": OP_GET,
        "service_id": "zoom",
        "operation_kind": "single_fetch",
        "effect": "read",
        "credential_modes": ZOOM_CREDENTIAL_MODES,
    },
    OP_CREATE: {
        "operation_id": OP_CREATE,
        "service_id": "zoom",
        "operation_kind": "mutation",
        "effect": "write",
        "credential_modes": ZOOM_CREDENTIAL_MODES,
    },
    OP_UPDATE: {
        "operation_id": OP_UPDATE,
        "service_id": "zoom",
        "operation_kind": "mutation",
        "effect": "write",
        "credential_modes": ZOOM_CREDENTIAL_MODES,
    },
}


def descriptor(operation_id: str) -> OperationDescriptor:
    """Return the shared :class:`OperationDescriptor` for a meetings operation.

    Raises ``KeyError`` for an unknown operation rather than fabricating a
    descriptor -- a caller must reference one of the four declared actions.
    """
    try:
        return _DESCRIPTORS[operation_id]
    except KeyError as exc:
        raise KeyError(
            f"{operation_id!r} is not one of the Zoom meetings operations "
            f"{tuple(_DESCRIPTORS)!r}"
        ) from exc


def descriptors() -> tuple[OperationDescriptor, ...]:
    """Return all four meetings descriptors, in list/get/create/update order."""
    return (
        _DESCRIPTORS[OP_LIST],
        _DESCRIPTORS[OP_GET],
        _DESCRIPTORS[OP_CREATE],
        _DESCRIPTORS[OP_UPDATE],
    )


# ---------------------------------------------------------------------------
# Request construction -- pure data description of one HTTP call
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ZoomRequest:
    """A pure, transport-agnostic description of one Zoom REST call.

    Carries the ``method`` and the already-constructed ``path`` (with any UUID
    double-encoding applied), the ``query`` parameters, and the JSON ``body``.
    It holds NO host, NO scheme, NO credential, and NO client: a later adapter
    leaf resolves the binding to a token and sends this. Immutable, so a
    constructed request cannot be mutated into targeting a different resource
    after the fact.
    """

    operation_id: str
    method: str
    path: str
    query: Mapping[str, Any] = field(default_factory=dict)
    body: Optional[Mapping[str, Any]] = None


def _require_numeric_meeting_id(meeting_id: str) -> str:
    """Reject an empty meeting id; a numeric id goes into the path verbatim.

    A numeric ``meetingId`` is NOT routed through the UUID encoder (that is the
    identity unit's separate address space). The one guard here is that the id
    is present -- an empty segment would silently address ``/meetings/``.
    """
    if meeting_id is None or meeting_id == "":
        raise ValueError("meetingId is required and must not be empty")
    return meeting_id


def build_list_request(
    user_id: str,
    *,
    page_size: int,
    next_page_token: Optional[str] = None,
) -> ZoomRequest:
    """Build the request for ``GET /users/{userId}/meetings`` (cursor-paged).

    The cursor discipline is looked up from the paging unit
    (:func:`~kiro_crew.connections.vendors.zoom.paging.next_cursor_request`),
    which refuses a non-positive page size and, because ``list`` is a plain
    cursor endpoint, refuses a date window. ``user_id`` may be ``"me"`` (the
    token's own user) or a specific userId; it is a path segment, not a UUID, so
    it is not double-encoded.
    """
    if user_id is None or user_id == "":
        raise ValueError("userId is required (use 'me' for the token's own user)")
    cursor = next_cursor_request(OP_LIST, page_size, next_page_token=next_page_token)
    query: dict[str, Any] = {"page_size": cursor.page_size}
    if cursor.next_page_token is not None:
        query["next_page_token"] = cursor.next_page_token
    return ZoomRequest(
        operation_id=OP_LIST,
        method="GET",
        path=_USER_MEETINGS.format(userId=user_id),
        query=query,
    )


def build_get_request(meeting_id: str, *, occurrence_id: Optional[str] = None) -> ZoomRequest:
    """Build the request for ``GET /meetings/{meetingId}`` (cursor-less).

    ``get`` is a single-resource read: the paging unit classifies it cursor-less
    and this module never attaches a ``next_page_token`` to it. A numeric
    ``meetingId`` is used verbatim. An ``occurrence_id`` (for reading one
    occurrence of a recurring series) is carried as a query parameter only when
    present; its absence reads the meeting/series object itself, which is the
    documented default and NOT a silent retarget (the retarget rule is
    load-bearing only for the mutating ``update`` path).
    """
    mid = _require_numeric_meeting_id(meeting_id)
    # Assert (defensively) that the endpoint really is cursor-less so a future
    # table edit that reclassified it would trip a test rather than silently
    # change behavior.
    assert not classify_pagination(OP_GET).is_cursor_paged
    query: dict[str, Any] = {}
    if occurrence_id is not None and occurrence_id != "":
        query["occurrence_id"] = occurrence_id
    return ZoomRequest(
        operation_id=OP_GET,
        method="GET",
        path=_MEETING.format(meetingId=mid),
        query=query,
    )


def _meeting_body(
    *,
    topic: Optional[str],
    start_time: Optional[str],
    timezone: Optional[str],
    duration: Optional[int],
    extra: Optional[Mapping[str, Any]],
) -> dict[str, Any]:
    """Assemble a create/update JSON body, binding start_time to its timezone.

    ``start_time`` is carried verbatim and ``timezone`` beside it via
    :func:`~kiro_crew.connections.vendors.zoom.identity.resolve_occurrence_time`
    -- NO local-time inference. A ``start_time`` with no governing timezone is
    sent as-is (Zoom then treats it as GMT per its own documented default); this
    module never fabricates a zone to fill the gap. Only fields the caller
    actually supplied are included, so an update is a partial PATCH body rather
    than one that nulls unspecified fields.
    """
    body: dict[str, Any] = {}
    if topic is not None:
        body["topic"] = topic
    if duration is not None:
        body["duration"] = duration
    if start_time is not None:
        occ: OccurrenceTime = resolve_occurrence_time(start_time, timezone)
        body["start_time"] = occ.start_time
        # Carry the series timezone ONLY when one was actually given. A missing
        # timezone is left absent, never guessed.
        if occ.timezone_known:
            body["timezone"] = occ.timezone
    elif timezone is not None and timezone != "":
        # A timezone with no start_time still describes the series' zone.
        body["timezone"] = timezone
    if extra:
        # Caller-supplied additional fields (settings, agenda, recurrence spec).
        # Merged last but never allowed to override the identity/time fields
        # this function is responsible for.
        for key, value in extra.items():
            body.setdefault(key, value)
    return body


def build_create_request(
    user_id: str,
    *,
    topic: Optional[str] = None,
    start_time: Optional[str] = None,
    timezone: Optional[str] = None,
    duration: Optional[int] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> ZoomRequest:
    """Build the request for ``POST /users/{userId}/meetings`` (create).

    A mutation, so it is cursor-less and carries a JSON body. ``start_time`` is
    bound to ``timezone`` with no local-time inference (:func:`_meeting_body`).
    The returned request is a pure data description; it does NOT authorize the
    call, resolve a credential, or verify the target host -- host verification is
    a readback step the adapter performs on the RESPONSE via
    :func:`verify_host_readback`, because the credential's mode alone cannot
    settle host reachability.
    """
    if user_id is None or user_id == "":
        raise ValueError("userId is required (use 'me' for the token's own user)")
    body = _meeting_body(
        topic=topic,
        start_time=start_time,
        timezone=timezone,
        duration=duration,
        extra=extra,
    )
    return ZoomRequest(
        operation_id=OP_CREATE,
        method="POST",
        path=_USER_MEETINGS.format(userId=user_id),
        body=body,
    )


def build_update_request(
    meeting_id: str,
    *,
    occurrence_id: Optional[str] = None,
    topic: Optional[str] = None,
    start_time: Optional[str] = None,
    timezone: Optional[str] = None,
    duration: Optional[int] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> ZoomRequest:
    """Build the request for ``PATCH /meetings/{meetingId}`` (update).

    The recurrence-targeting invariant is load-bearing here: the target is read
    through :func:`~kiro_crew.connections.vendors.zoom.identity.occurrence_target`,
    and a non-empty ``occurrence_id`` is sent as a query parameter to hit that
    ONE occurrence. A MISSING ``occurrence_id`` targets the parent series -- this
    function does not fabricate one, so a caller that meant a single occurrence
    but omitted the id gets a parent-series update, exactly as
    :data:`~kiro_crew.connections.vendors.zoom.identity.OccurrenceTarget.PARENT_SERIES`
    reports (negative fault test 2). ``start_time`` + ``timezone`` follow the
    no-inference rule via :func:`_meeting_body`.
    """
    mid = _require_numeric_meeting_id(meeting_id)
    target = occurrence_target(occurrence_id)
    query: dict[str, Any] = {}
    if target is OccurrenceTarget.SINGLE_OCCURRENCE:
        # occurrence_id is non-empty here (occurrence_target said so).
        query["occurrence_id"] = occurrence_id
    body = _meeting_body(
        topic=topic,
        start_time=start_time,
        timezone=timezone,
        duration=duration,
        extra=extra,
    )
    return ZoomRequest(
        operation_id=OP_UPDATE,
        method="PATCH",
        path=_MEETING.format(meetingId=mid),
        query=query,
        body=body,
    )


def update_request_target(occurrence_id: Optional[str]) -> OccurrenceTarget:
    """Expose what an update's ``occurrence_id`` targets, for a caller's check.

    A thin, honest pass-through to
    :func:`~kiro_crew.connections.vendors.zoom.identity.occurrence_target` so a
    caller can confirm -- BEFORE issuing a mutation -- whether an update will hit
    one occurrence or the whole parent series, and refuse a series-wide edit it
    did not intend. It does not decide the write (that is W01's ambiguous-write
    surface); it only reports the target the built request will hit.
    """
    return occurrence_target(occurrence_id)


# ---------------------------------------------------------------------------
# UUID-path variants (per-instance reads that address by UUID, not numeric id)
# ---------------------------------------------------------------------------
def encode_meeting_uuid_segment(raw_uuid: str) -> str:
    """Double-encode a per-instance meeting UUID for a UUID-path endpoint.

    A pass-through to
    :func:`~kiro_crew.connections.vendors.zoom.identity.encode_uuid_path_segment`
    so the meetings module routes a UUID (not a numeric id) through the one
    encoder that applies Zoom's double-encoding rule for a UUID beginning with
    ``/`` or containing ``//``. Exposed here so a caller building a
    ``past_meetings/{uuid}`` style path uses the vendor rule rather than
    hand-encoding -- keeping the numeric-vs-UUID address spaces from collapsing.
    """
    return encode_uuid_path_segment(raw_uuid)


# ---------------------------------------------------------------------------
# Response mapping -- success -> OperationResult, failure -> OperationError
# ---------------------------------------------------------------------------
def map_list_result(
    next_page_token: Optional[str],
    *,
    payload: Optional[CollectionPayload] = None,
) -> OperationResult:
    """Fold a ``list`` page's ``next_page_token`` into an ``OperationResult``.

    A present, non-empty token becomes the opaque
    :attr:`OperationResult.next_cursor`; an absent/empty token (Zoom's
    terminal-page signal) becomes ``None``, and the status downgrades to
    ``partial`` while a successor remains. The envelope carries a
    :class:`~kiro_crew.connections.control_plane.result.CollectionPayload` on the
    neutral data channel (``RESULT_SCHEMA_VERSION`` 3): an empty one by default
    when this convenience builder is used without rows, or the caller's page when
    given. The dispatch path builds the real payload in the decoder; this helper
    exists for a caller that only needs the cursor-folded envelope.
    """
    cursor = to_next_cursor(next_page_token)
    collection = payload if payload is not None else CollectionPayload(items=())
    status: ResultStatus = "partial" if cursor is not None else "ok"
    return result_with_payload(collection, status=status, next_cursor=cursor)


def map_single_result(
    payload: Optional[ObjectPayload] = None,
) -> OperationResult:
    """Return the ``OperationResult`` for a cursor-less single-resource outcome.

    ``get`` / ``create`` / ``update`` return one object and carry no cursor, so
    the envelope is ``ok`` with ``next_cursor=None`` and the object on the
    neutral :data:`~kiro_crew.connections.control_plane.result.OperationPayload`
    channel (or ``None`` when the caller has no object to carry). Kept a function
    (rather than a module constant) so each call gets its own dict and a caller
    cannot mutate a shared instance.
    """
    return result_with_payload(payload, status="ok", next_cursor=None)


def map_error(
    error_code: Optional[int],
    detail: str,
    *,
    http_status: Optional[int] = None,
) -> OperationError:
    """Map a Zoom failure to a control-plane :class:`OperationError`.

    The single error path for this module: it delegates to
    :func:`~kiro_crew.connections.vendors.zoom.errors.zoom_operation_error`,
    which (1) classifies the Zoom code/status into the RUN-01 taxonomy -- keeping
    ``3001`` ``ambiguous`` -- and (2) redacts the detail in the fixed order (Zoom
    vendor pre-scrub, THEN the control plane's site-wide redact-then-truncate).
    This module opens no second error-text channel and never constructs an
    :class:`OperationError` dict directly.
    """
    return zoom_operation_error(error_code, detail, http_status=http_status)


# ---------------------------------------------------------------------------
# Host readback verification -- credential mode never settles host reachability
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class HostVerification:
    """The outcome of verifying a create/update ran against the intended host.

    ``verified`` is True ONLY when a concrete ``host_id`` was read back from the
    response and equals the requested target. When either side is unknown (no
    target given, or no ``host_id`` in the response), ``verified`` is False and
    ``reachability`` is
    :data:`~kiro_crew.connections.vendors.zoom.identity.HOST_REACHABILITY_UNKNOWN`
    -- never asserted reachable or unreachable from the credential's mode alone.
    """

    verified: bool
    reachability: str
    target_host: Optional[str]
    readback_host: Optional[str]


def verify_host_readback(
    target_host_id: Optional[str],
    readback_host_id: Optional[str],
) -> HostVerification:
    """Assert a mutation's readback ``host_id`` equals the requested target.

    This is the create/update correctness gate the spec requires: an
    account-level Server-to-Server credential does not, by being account-level,
    prove the call hit the intended human host, so the ONLY sound check is to
    read ``host_id`` back from the response and compare it to the target.

    * Both present and equal -> ``verified=True``, reachability ``"verified"``.
    * Both present and different -> ``verified=False``, reachability
      ``"mismatch"`` (a silent wrong-host write, the failure this gate exists to
      catch).
    * Either side absent -> ``verified=False``, reachability
      :data:`HOST_REACHABILITY_UNKNOWN` -- the honest "cannot tell" state, never
      inferred from the credential mode.
    """
    if not target_host_id or not readback_host_id:
        return HostVerification(
            verified=False,
            reachability=HOST_REACHABILITY_UNKNOWN,
            target_host=target_host_id or None,
            readback_host=readback_host_id or None,
        )
    if target_host_id == readback_host_id:
        return HostVerification(
            verified=True,
            reachability="verified",
            target_host=target_host_id,
            readback_host=readback_host_id,
        )
    return HostVerification(
        verified=False,
        reachability="mismatch",
        target_host=target_host_id,
        readback_host=readback_host_id,
    )


def auth_mode_host_reachability(
    credential_mode: CredentialMode,
    verified: bool,
) -> str:
    """Report the ``(auth_mode, host)`` reachability, unknown until verified.

    An unverified pair is :data:`HOST_REACHABILITY_UNKNOWN` for BOTH credential
    modes -- being ``service_to_service`` (account-level) does not make it
    reachable, and being ``oauth_user`` does not make it unreachable. Only a
    completed readback (:func:`verify_host_readback` -> ``verified=True``) turns
    it into ``"verified"``. The ``credential_mode`` argument is validated as a
    real Zoom mode so a caller cannot ask about a mode Zoom does not support.
    """
    if credential_mode not in ZOOM_CREDENTIAL_MODES:
        raise ValueError(
            f"{credential_mode!r} is not a Zoom credential mode " f"{ZOOM_CREDENTIAL_MODES!r}"
        )
    return "verified" if verified else HOST_REACHABILITY_UNKNOWN


# ---------------------------------------------------------------------------
# Import-time validation against the shared closed sets (fail-closed)
# ---------------------------------------------------------------------------
def _validate() -> None:
    """Fail-closed checks that the four descriptors fold into W01's vocabulary.

    Mirrors the GitHub stream's import-time ``_validate``: every descriptor's
    ``service_id`` / ``operation_kind`` / ``effect`` is a member of the shared
    control-plane closed set, every ``credential_modes`` value is a member of
    the shared ``CREDENTIAL_MODES`` set (and a subset of Zoom's two supported
    modes), and the operation_id keys agree with each descriptor's own
    ``operation_id``. A drift here is a typo inventing a value a manifest
    validator would never see, so it fails at import.
    """
    credential_modes = set(CREDENTIAL_MODES)
    for operation_id, desc in _DESCRIPTORS.items():
        if desc["operation_id"] != operation_id:
            raise ValueError(
                f"descriptor key {operation_id!r} disagrees with its operation_id "
                f"{desc['operation_id']!r}"
            )
        if desc["service_id"] not in SERVICE_IDS:
            raise ValueError(f"{operation_id}.service_id={desc['service_id']!r} not in SERVICE_IDS")
        if desc["service_id"] != "zoom":
            raise ValueError(
                f"{operation_id}.service_id must be 'zoom', got {desc['service_id']!r}"
            )
        if desc["operation_kind"] not in OPERATION_KINDS:
            raise ValueError(
                f"{operation_id}.operation_kind={desc['operation_kind']!r} not in OPERATION_KINDS"
            )
        if desc["effect"] not in EFFECTS:
            raise ValueError(f"{operation_id}.effect={desc['effect']!r} not in EFFECTS")
        for mode in desc["credential_modes"]:
            if mode not in credential_modes:
                raise ValueError(
                    f"{operation_id}.credential_modes contains {mode!r}, not in CREDENTIAL_MODES"
                )
            if mode not in ZOOM_CREDENTIAL_MODES:
                raise ValueError(
                    f"{operation_id}.credential_modes contains {mode!r}, not a Zoom-supported mode "
                    f"{ZOOM_CREDENTIAL_MODES!r}"
                )
    # Every operation that declares a license scope must be one of the four,
    # and vice-versa -- the two tables cover the same operation set.
    if set(_LICENSE_BY_OPERATION) != set(_DESCRIPTORS):
        raise ValueError(
            "license-scope table and descriptor table cover different operations: "
            f"{set(_LICENSE_BY_OPERATION) ^ set(_DESCRIPTORS)!r}"
        )


_validate()
