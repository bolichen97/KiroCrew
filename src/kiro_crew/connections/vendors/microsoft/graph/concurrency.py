"""Microsoft Graph optimistic-concurrency version-safe write protocol.

WHAT THIS OWNS
==============
W01's executor (``connections/control_plane/executor.py`` + ``production.py``)
owns the decision chain, credential custody, the pre-send gates, and the real
HTTP sender. It leaves two seats VENDOR-OWNED and injected:

* :data:`~kiro_crew.connections.control_plane.production.RequestLocator`
  ``= Callable[..., HttpRequest]`` -- shape the concrete Graph request. It is
  called by the transport with ``service_id`` / ``credential_mode`` /
  ``descriptor`` / ``request_args`` / ``request_idempotency_key``; the vendor
  reads ``request_args`` for the operation's method / path / If-Match / body.
* :data:`~kiro_crew.connections.control_plane.production.ResultDecode`
  ``= Callable[..., OperationResult]`` -- map a 2xx reply to the L01 envelope,
  cursor-shaped via A's paging.

This module fills both seats AND owns the version-safe WRITE ORCHESTRATION --
GET -> conditional PATCH -> 412 -> fresh -> retry -> read-back. The orchestration
routes EVERY hop THROUGH W01's :func:`~kiro_crew.connections.control_plane.executor.execute`
(via a composed :data:`Transport`), so the trusted binding identity, the vault
custody fencing, the pre-send gates and the unknown-outcome mapping ALL run --
it never calls a raw sender itself. It is not a new general-purpose runtime; it
orchestrates this one operation.

AUTHENTICITY (from W01, not fabricated here)
============================================
The auth chain is W01's: ``BindingSecretSelector`` refuses a call whose
``binding_fingerprint`` is not the composed one BEFORE any vault read, and the
transport reveals the credential into ``Authorization`` for exactly one send.
Routing every hop through ``execute`` is what makes that hold; a hop that called
a sender directly would attach no credential and pass no gate. Correlation is
the executor's own call: each :class:`ExecutionOutcome` this orchestration reads
is ``execute``'s return for the request the seat produced. ``request-id`` /
``client-request-id`` are never read and are no auth proof.

NOTE ON COMPLETENESS: this wires the version-safe WRITE onto W01's real chain,
but the full connector auth stack (L03 auth-code, L04 rotation fencing,
principal->binding resolution) is W01's and NOT complete; nothing here should be
read as "the auth chain is done".

THE VERSION-SAFE PROTOCOL
=========================
* Read ``eTag`` / ``cTag`` (distinct kinds; ``If-Match`` acceptance per endpoint).
* BEFORE the write, compare the intent's baseline against the INITIAL GET's
  actual field values: if a field already moved, CONFLICT there -- do not send an
  ``If-Match`` that would match the moved state and clobber it.
* Conditional write only where evidence supports it (SharePoint list item;
  OneDrive driveitem metadata -- both a real 412 contract, eTag [+cTag for
  driveitem]). ``excel.range.write`` has no eTag mechanism and is REFUSED.
* 412 recovery is CONFLICT-FIRST over the fresh re-read.
* Read-back verifies the intended fields hold ON THE TARGET RESOURCE (its id
  asserted) and never claims write attribution.
* A non-idempotent write that returns 500 is UNKNOWN (commit-ambiguous), which
  W01 leaves to the vendor: :func:`graph_500_unknown_transport` sets it.

Field comparison is PER TYPED COLUMN; an undocumented typed column (lookup /
person-or-group / multi-value) is REFUSED rather than guessed. ``column_kind``
is required.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from kiro_crew.connections.control_plane.executor import (
    ExecutionOutcome,
    Transport,
    TransportResponse,
    is_non_idempotent_effect,
)
from kiro_crew.connections.control_plane.operation import CredentialMode, OperationDescriptor
from kiro_crew.connections.control_plane.production import (
    HttpReply,
    HttpRequest,
    neutral_decode,
)
from kiro_crew.connections.control_plane.result import (
    CollectionPayload,
    ObjectPayload,
    OperationResult,
    result_with_payload,
)
from kiro_crew.connections.control_plane.writes import ATTEMPT_UNKNOWN
from kiro_crew.connections.vendors.microsoft.graph.payload import parse_collection

# --- version-identifier + identity keys on a read reply body ----------------
ODATA_ETAG = "@odata.etag"
FIELD_ETAG = "eTag"
FIELD_CTAG = "cTag"
FIELD_ID = "id"
ODATA_ID = "@odata.id"

# request_args keys the RequestLocator seat reads for THIS operation.
ARG_METHOD = "method"
ARG_PATH = "path"
ARG_IF_MATCH = "if_match"
ARG_BODY = "body"


class VersionKind(str, Enum):
    """``ETAG`` (any change) vs ``CTAG`` (content). Distinct; If-Match per endpoint."""

    ETAG = "etag"
    CTAG = "ctag"


class ColumnKind(str, Enum):
    """How a ``fields``-facet column is compared. Typed columns are REFUSED, not guessed."""

    SCALAR = "scalar"
    LOOKUP = "lookup"
    PERSON_OR_GROUP = "person_or_group"
    MULTIVALUE = "multivalue"


_UNDOCUMENTED_COLUMN_KINDS = frozenset(
    {ColumnKind.LOOKUP, ColumnKind.PERSON_OR_GROUP, ColumnKind.MULTIVALUE}
)


class ConcurrencyError(ValueError):
    """A version-safe write precondition was violated, or a guarantee refused."""


@dataclass(frozen=True)
class VersionTag:
    kind: VersionKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise ConcurrencyError("version tag value must be a non-empty string")


class ConcurrencyMode(str, Enum):
    """``LISTITEM_ETAG`` / ``DRIVEITEM_ETAG_OR_CTAG`` (both real 412) / ``NONE_LAST_WRITE_WINS``."""

    LISTITEM_ETAG = "listitem_etag"
    DRIVEITEM_ETAG_OR_CTAG = "driveitem_etag_or_ctag"
    NONE_LAST_WRITE_WINS = "none_last_write_wins"


_IF_MATCH_VALIDATORS: Mapping[ConcurrencyMode, frozenset[VersionKind]] = MappingProxyType(
    {
        ConcurrencyMode.LISTITEM_ETAG: frozenset({VersionKind.ETAG}),
        ConcurrencyMode.DRIVEITEM_ETAG_OR_CTAG: frozenset({VersionKind.ETAG, VersionKind.CTAG}),
    }
)


def supports_if_match(mode: ConcurrencyMode) -> bool:
    return mode in _IF_MATCH_VALIDATORS


def accepts_validator(mode: ConcurrencyMode, kind: VersionKind) -> bool:
    return kind in _IF_MATCH_VALIDATORS.get(mode, frozenset())


def has_412_contract(mode: ConcurrencyMode) -> bool:
    return mode in _IF_MATCH_VALIDATORS


def extract_version(body: Mapping[str, Any]) -> Optional[VersionTag]:
    """Read a version tag from a reply body (eTag preferred, cTag distinct)."""

    etag = _optional_str(body, ODATA_ETAG)
    if etag is None:
        etag = _optional_str(body, FIELD_ETAG)
    if etag is not None:
        return VersionTag(kind=VersionKind.ETAG, value=etag)
    ctag = _optional_str(body, FIELD_CTAG)
    if ctag is not None:
        return VersionTag(kind=VersionKind.CTAG, value=ctag)
    return None


def extract_resource_id(body: Mapping[str, Any]) -> Optional[str]:
    """Read the resource id (``id`` / ``@odata.id``) from a reply body."""

    rid = _optional_str(body, FIELD_ID)
    if rid is None:
        rid = _optional_str(body, ODATA_ID)
    return rid


@dataclass(frozen=True)
class FieldChange:
    baseline: Any
    intended: Any
    column_kind: ColumnKind  # REQUIRED: no silent SCALAR fallback.


@dataclass(frozen=True)
class WriteIntent:
    """The baseline-anchored change THIS write intends, keyed by field name.

    ``resource_id`` -- the id of the resource this write targets, so a read-back
    can assert it read back the SAME resource. ``changes`` -- the full required
    field set for the operation (no field-count cap).
    """

    resource_id: str
    changes: Mapping[str, FieldChange]

    def __post_init__(self) -> None:
        if not isinstance(self.resource_id, str) or not self.resource_id.strip():
            raise ConcurrencyError("a write intent must carry a non-empty resource_id")
        if not self.changes:
            raise ConcurrencyError("a write intent must name at least one field to change")
        object.__setattr__(self, "changes", MappingProxyType(dict(self.changes)))

    def merge_patch_body(self) -> Mapping[str, Any]:
        return {name: change.intended for name, change in self.changes.items()}


# =============================================================================
# SEAT 1 -- RequestLocator: shape a concrete Graph HttpRequest (no credential).
# =============================================================================
def graph_request_locator(
    *,
    service_id: str,
    credential_mode: str,
    descriptor: OperationDescriptor,
    request_args: Mapping[str, Any],
    request_idempotency_key: str = "",
    endpoint_host: str,
) -> HttpRequest:
    """Fill W01's RequestLocator seat: shape one Graph :class:`HttpRequest`.

    Reads ``request_args`` for ``method`` / ``path`` (A's ``build_path`` result,
    root-relative) / optional ``if_match`` / optional ``body``. Assembles the
    absolute ``https`` URL from ``endpoint_host`` (bound at composition) and the
    path. Sets NO credential header: per W01's contract the transport adds
    ``Authorization`` itself. ``endpoint_host`` is keyword-bound by the composer
    (``functools.partial``); the other kwargs are what the transport passes.
    """

    method = str(request_args.get(ARG_METHOD, "")).strip()
    path = str(request_args.get(ARG_PATH, ""))
    if not method:
        raise ConcurrencyError("request_args['method'] is required")
    if not path.startswith("/"):
        raise ConcurrencyError("request_args['path'] must be a root-relative Graph path")
    host = endpoint_host.strip()
    if not host:
        raise ConcurrencyError("endpoint_host must be a non-empty Graph service host")
    headers: dict[str, str] = {}
    if_match = request_args.get(ARG_IF_MATCH)
    if if_match is not None:
        if not str(if_match).strip():
            raise ConcurrencyError("if_match must be non-empty when provided")
        headers["If-Match"] = str(if_match)
    body = request_args.get(ARG_BODY)
    if body is not None:
        headers["Content-Type"] = "application/json"
        if not isinstance(body, (bytes, bytearray)):
            body = _json_bytes(body)
    return HttpRequest(
        method=method.upper(), url=f"https://{host}{path}", headers=headers, body=body
    )


def conditional_write_args(
    mode: ConcurrencyMode,
    path: str,
    version: Optional[VersionTag],
    intent: WriteIntent,
) -> Mapping[str, Any]:
    """Build the ``request_args`` for a version-safe conditional PATCH.

    Refuses Excel (no mechanism), a missing version (no blind write), and a
    per-endpoint-unaccepted validator -- BEFORE any request is shaped.
    """

    if mode is ConcurrencyMode.NONE_LAST_WRITE_WINS:
        raise ConcurrencyError(
            "excel.range.write is last-write-wins: Graph documents NO built-in "
            "optimistic-concurrency (eTag) mechanism for Excel ranges, unlike "
            "SharePoint list items. A version-safe conditional write cannot be "
            "built for this operation and must not be faked."
        )
    if not supports_if_match(mode):  # pragma: no cover - exhaustive guard
        raise ConcurrencyError(f"unhandled concurrency mode {mode!r}")
    if version is None:
        raise ConcurrencyError(
            f"{mode.value} is a conditional-write endpoint but no version was "
            "read; refusing an unconditional (blind) write with no If-Match"
        )
    if not accepts_validator(mode, version.kind):
        accepted = ", ".join(sorted(k.value for k in _IF_MATCH_VALIDATORS[mode]))
        raise ConcurrencyError(
            f"{mode.value} does not accept a {version.kind.value} as an If-Match "
            f"validator (accepts: {accepted}); this rule is per-endpoint"
        )
    return {
        ARG_METHOD: "PATCH",
        ARG_PATH: path,
        ARG_IF_MATCH: version.value,
        ARG_BODY: intent.merge_patch_body(),
    }


# =============================================================================
# SEAT 2 -- ResultDecode: map a 2xx HttpReply to an OperationResult.
# =============================================================================
# SEAT 2 -- ResultDecode: map a 2xx HttpReply to an OperationResult WITH payload.
# =============================================================================
# W01 landed the neutral payload slot (result.py RESULT_SCHEMA_VERSION 3): an
# ``OperationResult`` now carries ``payload`` -- exactly one of CollectionPayload
# / ObjectPayload / BytesPayload, or None. The rows a 2xx returned now have a
# real home, so this seat builds the envelope with :func:`result_with_payload`
# and the data reaches a caller through ``ExecutionOutcome.payload``. The cursor
# stays SINGLE-SOURCE on ``OperationResult.next_cursor`` (an explicit keyword to
# result_with_payload); CollectionPayload carries items ONLY, never a cursor.
def graph_result_decode(reply: HttpReply) -> OperationResult:
    """Fill W01's ResultDecode seat: the L01 envelope WITH its payload.

    * A Graph collection body (``{"value": [...]}``) -> a
      :class:`CollectionPayload` of its items, with the ``@odata.nextLink``
      opaque cursor as ``next_cursor`` (single-source, on the envelope only;
      ``partial`` when a cursor remains, else ``ok``). Rows are read through A's
      :func:`parse_collection`.
    * A single-object body (a list item's ``fields``, a drive item's metadata)
      -> an :class:`ObjectPayload` of that object (``ok``, no cursor -- an object
      is not a paged shape).
    * An empty / non-JSON body (a 204, a write acknowledgement) -> ``None``
      payload via W01's :func:`neutral_decode`.

    Never guesses a cursor and never puts a cursor anywhere but the envelope.
    """

    parsed = _json_or_none(reply.body)
    if isinstance(parsed, Mapping) and "value" in parsed:
        page = parse_collection(parsed)
        cursor = page.next_link
        return result_with_payload(
            CollectionPayload(items=tuple(page.value)),
            status="partial" if cursor is not None else "ok",
            next_cursor=cursor,
        )
    if isinstance(parsed, Mapping):
        # A single resource object (the read target's own fields).
        return result_with_payload(ObjectPayload(object=dict(parsed)), status="ok")
    # No JSON body (204 / empty ack): defer to W01's neutral decode (payload None).
    return neutral_decode(reply)


# =============================================================================
# D9 -- vendor 500-unknown transport wrapper.
# =============================================================================
def graph_500_unknown_transport(inner: Transport) -> Transport:
    """Wrap a composed :data:`Transport` so a 500 on a non-idempotent write is UNKNOWN.

    W01 deliberately leaves HTTP 500 out of its ambiguous-transit set: whether a
    500 is pre- or post-commit is PROVIDER knowledge, so it documents that "a
    vendor owner that knows its API commits first must set ``write_outcome``
    itself". Microsoft Graph does not guarantee a 500 is pre-commit for a write,
    so a 500 on a non-idempotent effect is commit-AMBIGUOUS: this wrapper marks
    it :data:`ATTEMPT_UNKNOWN`, so L07 refuses to blind-replay (a wrong "not
    applied" would duplicate the write). It touches ONLY the 500 case and only
    for a non-idempotent effect; every other response passes through unchanged.
    """

    def _wrapped(*, descriptor: OperationDescriptor, **kwargs: Any) -> TransportResponse:
        response = inner(descriptor=descriptor, **kwargs)
        if (
            response.http_status == 500
            and response.write_outcome is None
            and is_non_idempotent_effect(descriptor["effect"])
        ):
            return TransportResponse(
                http_status=response.http_status,
                result=response.result,
                preconditions=response.preconditions,
                etag=response.etag,
                retry_after_seconds=response.retry_after_seconds,
                detail=response.detail,
                write_outcome=ATTEMPT_UNKNOWN,
            )
        return response

    return _wrapped


# =============================================================================
# 412 recovery + the pre-send baseline check -- CONFLICT-FIRST.
# =============================================================================
PRECONDITION_FAILED = 412


@dataclass(frozen=True)
class Conflict:
    """A surfaced conflict the caller must resolve; NOTHING is (re)sent."""

    moved_fields: tuple[str, ...]
    reason: str


def baseline_conflict(intent: WriteIntent, current_body: Mapping[str, Any]) -> Optional[Conflict]:
    """Check the intent's baseline against a resource's CURRENT field values.

    Run BEFORE the conditional write, over the initial GET's body. If any
    intended field's current value already differs from the baseline this write
    assumed, that is a concurrent change: return a :class:`Conflict` so the write
    is never sent (an ``If-Match`` on the already-moved version would MATCH and
    clobber, which the 412 path cannot catch because no 412 fires). ``None`` when
    every intended field still holds its baseline. Also verifies identity: a body
    whose id is not the intent's target is a conflict.
    """

    rid = extract_resource_id(current_body)
    if rid is None or rid != intent.resource_id:
        return Conflict(
            moved_fields=(),
            reason=f"initial read identity {rid!r} != target {intent.resource_id!r}",
        )
    moved = tuple(
        name
        for name, change in intent.changes.items()
        if name not in current_body
        or not _field_values_equal(change, change.baseline, current_body[name])
    )
    if moved:
        return Conflict(
            moved_fields=moved,
            reason="initial read shows intended field(s) already moved off "
            "baseline: " + ", ".join(moved),
        )
    return None


@dataclass(frozen=True)
class RetryPlan:
    should_retry: bool
    reason: str
    fresh_version: Optional[VersionTag] = None
    conflict: Optional[Conflict] = None


def recover_from_precondition_failed(
    mode: ConcurrencyMode,
    intent: WriteIntent,
    re_read_body: Mapping[str, Any],
) -> RetryPlan:
    """Plan the 412 recovery over the fresh re-read body. CONFLICT-FIRST.

    Retry ONLY when identity matches AND every intended field's fresh value still
    equals its baseline. Any moved field, an identity mismatch, or no fresh
    version -> :class:`Conflict`, resend nothing. A typed column with no
    documented schema RAISES (never a false "unmoved").
    """

    if not has_412_contract(mode):
        return RetryPlan(should_retry=False, reason="mode has no 412 contract")
    conflict = baseline_conflict(intent, re_read_body)
    if conflict is not None:
        return RetryPlan(should_retry=False, reason=conflict.reason, conflict=conflict)
    fresh = extract_version(re_read_body)
    if fresh is None:
        return RetryPlan(
            should_retry=False,
            reason="412 conflict: re-read carries no version for a fresh If-Match",
            conflict=Conflict(moved_fields=(), reason="no fresh version in re-read"),
        )
    return RetryPlan(
        should_retry=True,
        reason="412 resolved: no intended field moved; retry with the fresh version",
        fresh_version=fresh,
    )


# =============================================================================
# Read-back verification -- identity asserted, per typed column.
# =============================================================================
@dataclass(frozen=True)
class ReadBackVerdict:
    verified: bool
    identity_ok: bool
    mismatches: tuple[str, ...]
    reason: str


def verify_read_back(intent: WriteIntent, read_back_body: Mapping[str, Any]) -> ReadBackVerdict:
    """Verify the target post-condition on the READ-BACK body, identity first.

    Asserts the read-back is the intent's TARGET resource (its id), then that
    every intended field holds its intended value (per typed column; an
    undocumented typed column RAISES). A moved version tag is not used. On
    success the claim is narrow: the post-condition HOLDS on the identified
    resource -- NOT that this write produced it.
    """

    rid = extract_resource_id(read_back_body)
    if rid is None or rid != intent.resource_id:
        return ReadBackVerdict(
            verified=False,
            identity_ok=False,
            mismatches=(),
            reason=f"read-back identity {rid!r} != target {intent.resource_id!r}",
        )
    mismatches = tuple(
        name
        for name, change in intent.changes.items()
        if name not in read_back_body
        or not _field_values_equal(change, change.intended, read_back_body[name])
    )
    if mismatches:
        return ReadBackVerdict(
            verified=False,
            identity_ok=True,
            mismatches=mismatches,
            reason="intended fields not holding their value: " + ", ".join(mismatches),
        )
    return ReadBackVerdict(
        verified=True,
        identity_ok=True,
        mismatches=(),
        reason="target post-condition holds on the identified resource "
        "(not a claim that this write produced it)",
    )


# =============================================================================
# ORCHESTRATION -- routed THROUGH W01's execute (custody + gates on every hop).
# =============================================================================
#: A dispatch is one authorized call: the caller binds it to W01's ``execute``
#: (with the descriptor/handle/permitted/layers/governance/transport composed
#: from the two seats), so every hop runs custody + gates + unknown-outcome. It
#: takes the operation ``request_args`` (method/path/if_match/body) and returns
#: the executor's :class:`ExecutionOutcome` plus the read body -- read from
#: ``outcome.payload`` (W01's neutral payload slot), NEVER by indexing ``result``
#: or capturing the raw reply.
Dispatch = Callable[[Mapping[str, Any]], "DispatchResult"]


@dataclass(frozen=True)
class DispatchResult:
    """What one authorized ``execute`` hop returns to the orchestrator.

    ``outcome`` -- the executor's :class:`ExecutionOutcome` (result / error /
    precondition / write_outcome / payload / view). ``body`` -- the resource's
    field values for a READ hop, taken from ``outcome.payload`` (W01's neutral
    payload slot). For a single-resource GET the payload is an
    :class:`~kiro_crew.connections.control_plane.result.ObjectPayload` and
    ``body`` is its ``.object``; ``None`` when the hop returned no object payload
    (an error, a 412, a write acknowledgement with no body). It is read through
    ``outcome.payload``, NOT by indexing ``result`` and NOT from any captured
    reply or side store.
    """

    outcome: ExecutionOutcome
    body: Optional[Mapping[str, Any]]


def build_graph_write_dispatch(
    *,
    descriptor: OperationDescriptor,
    handle: "Any",
    endpoint_host: str,
    selector: "Any",
    vault: "Any",
    offered_mode: CredentialMode,
    permitted: "Any",
    layers: "Any",
    governance_scope: str,
    governance_item: str,
    now: Optional[float] = None,
) -> Dispatch:
    """PRODUCTION dispatch entry: bind this operation to W01's ``execute``.

    This is the shipped path -- a module-level entry, not a test closure. It
    composes W01's real transport from the two vendor seats
    (:func:`graph_request_locator`, :func:`graph_result_decode`) plus the D9
    :func:`graph_500_unknown_transport` wrapper and W01's real
    :func:`~kiro_crew.connections.control_plane.production.urllib_http_send`, then
    returns a :class:`Dispatch` that runs ONE ``execute`` per call. Every hop
    passes W01's custody, pre-send gates, trusted-binding identity and
    unknown-outcome mapping; nothing here issues a raw send or touches a secret.

    ``DispatchResult.body`` is read from ``outcome.payload`` -- W01's neutral
    payload slot (landed at RESULT_SCHEMA_VERSION 3). A single-resource read
    decodes to an ObjectPayload and its ``.object`` is the resource's fields, so
    the orchestrator's baseline / read-back steps operate on REAL data. The body
    is taken through ``outcome.payload``, NEVER by indexing ``result``, NEVER from
    a captured reply, a side store, or ``outcome.metadata`` (a closed rate-limit
    allowlist, not a data channel). Identity is taken from ``outcome.view`` (the
    trusted :class:`TrustedHandleView`), preferred over any caller-assembled one.

    ``handle`` / ``selector`` / ``permitted`` / ``layers`` are W01 types passed in
    by the composing caller (kept as ``Any`` here so this vendor module does not
    re-import W01's whole type surface). ``now`` is for a deterministic test only.

    NOTE: W01's auth chain (L03 auth-code, L04 rotation fencing,
    principal->binding) is NOT complete and carries reported gaps, and W01's own
    fresh install is still being corrected; this entry rides W01's chain but does
    not make it complete or safe on its own.
    """

    import functools

    from kiro_crew.connections.control_plane.executor import execute as _execute
    from kiro_crew.connections.control_plane.production import (
        build_production_transport,
        urllib_http_send,
    )

    locator = functools.partial(graph_request_locator, endpoint_host=endpoint_host)
    transport = graph_500_unknown_transport(
        build_production_transport(
            selector=selector,
            vault=vault,
            locator=locator,
            http_send=urllib_http_send,
            decode=graph_result_decode,
        )
    )

    def _dispatch(request_args: Mapping[str, Any]) -> DispatchResult:
        outcome = _execute(
            descriptor,
            handle,
            transport,
            now=now,
            offered_mode=offered_mode,
            permitted=permitted,
            layers=layers,
            governance_scope=governance_scope,
            governance_item=governance_item,
            request_args=request_args,
        )
        # Read the body from W01's neutral payload slot -- ``outcome.payload`` --
        # NOT by indexing ``result`` and NOT from any captured reply. A single
        # resource read decodes to an ObjectPayload; its ``.object`` is the
        # resource's fields the baseline / read-back steps compare against.
        body: Optional[Mapping[str, Any]] = None
        payload = outcome.payload
        if isinstance(payload, ObjectPayload):
            body = payload.object
        return DispatchResult(outcome=outcome, body=body)

    return _dispatch


@dataclass(frozen=True)
class WriteSequenceOutcome:
    """The result of one version-safe write sequence routed through the executor."""

    applied: bool
    conflict: Optional[Conflict]
    verified: bool
    write_outcome: Optional[str]
    attempts: int
    reason: str


def run_version_safe_write(
    *,
    mode: ConcurrencyMode,
    path: str,
    intent: WriteIntent,
    dispatch: Dispatch,
    max_412_retries: int = 1,
) -> WriteSequenceOutcome:
    """Drive GET -> baseline check -> conditional PATCH -> 412 -> fresh -> retry -> read-back.

    Every hop goes through ``dispatch``, which the caller binds to W01's
    ``execute`` -- so custody, the pre-send gates, the trusted-binding identity
    and the unknown-outcome mapping run on every request. This function issues no
    raw send and no credential; without the executor no ``Authorization`` is
    attached at all.

    An operation with no optimistic-concurrency mechanism
    (``NONE_LAST_WRITE_WINS`` / ``excel.range.write``) is refused BEFORE step 1,
    so it issues ZERO requests -- not even the initial GET. A version-safe write
    on such an operation cannot exist, so the whole sequence is refused, not just
    the PATCH.
    """

    # Step 0 (F2): concurrency-contract gate BEFORE any request. An operation
    # with no If-Match mechanism (Excel range) cannot have a version-safe write,
    # so it is refused here and NOTHING is dispatched -- no initial GET, no PATCH.
    if not has_412_contract(mode):
        raise ConcurrencyError(
            f"{mode.value} has no optimistic-concurrency (eTag) mechanism "
            "(excel.range.write is last-write-wins); a version-safe write "
            "sequence cannot be run and issues zero requests"
        )

    # Step 1: initial GET (authorized). Verify it SUCCEEDED before reading it.
    get = dispatch({ARG_METHOD: "GET", ARG_PATH: path})
    if get.outcome.error is not None or get.body is None:
        return WriteSequenceOutcome(
            applied=False,
            conflict=None,
            verified=False,
            write_outcome=get.outcome.write_outcome,
            attempts=0,
            reason="initial GET did not return a readable body (authorization or "
            "transport error); nothing sent",
        )

    # Step 1b (D7): baseline conflict on the INITIAL GET's actual values.
    pre = baseline_conflict(intent, get.body)
    if pre is not None:
        return WriteSequenceOutcome(
            applied=False,
            conflict=pre,
            verified=False,
            write_outcome=None,
            attempts=0,
            reason=pre.reason,
        )

    version = extract_version(get.body)
    attempts = 0
    retries_left = max_412_retries
    while True:
        # Step 2: conditional write (refuses Excel/missing/unaccepted here).
        write = dispatch(conditional_write_args(mode, path, version, intent))
        attempts += 1
        outcome = write.outcome

        if outcome.ok:
            # Step 3: independent read-back; verify the read-back's OWN outcome
            # first (F1), then identity + fields. An error read-back is not a
            # verification even if its body happens to carry matching values.
            rb = dispatch({ARG_METHOD: "GET", ARG_PATH: path})
            if rb.outcome.error is not None or rb.body is None:
                return WriteSequenceOutcome(
                    applied=True,
                    conflict=None,
                    verified=False,
                    write_outcome=outcome.write_outcome,
                    attempts=attempts,
                    reason="write applied but the independent read-back failed "
                    "(authorization/transport error); post-condition NOT verified",
                )
            verdict = verify_read_back(intent, rb.body)
            return WriteSequenceOutcome(
                applied=True,
                conflict=None,
                verified=verdict.verified,
                write_outcome=outcome.write_outcome,
                attempts=attempts,
                reason=verdict.reason,
            )

        if outcome.precondition is not None:
            # Step 4: 412 -> re-GET -> conflict-first recovery. The re-read's OWN
            # outcome is guarded first (F1): a failed re-read is not a safe-retry
            # basis, even if its body carries values matching the baseline.
            re_read = dispatch({ARG_METHOD: "GET", ARG_PATH: path})
            if re_read.outcome.error is not None or re_read.body is None:
                return WriteSequenceOutcome(
                    applied=False,
                    conflict=Conflict((), "re-read after 412 failed or unreadable"),
                    verified=False,
                    write_outcome=None,
                    attempts=attempts,
                    reason="re-read after 412 failed (authorization/transport "
                    "error) or returned no body; refusing to retry on it",
                )
            plan = recover_from_precondition_failed(mode, intent, re_read.body)
            if plan.should_retry and retries_left > 0:
                version = plan.fresh_version
                retries_left -= 1
                continue
            return WriteSequenceOutcome(
                applied=False,
                conflict=plan.conflict,
                verified=False,
                write_outcome=None,
                attempts=attempts,
                reason=plan.reason if plan.conflict else "412 retry budget exhausted",
            )

        # Step 5 (D9): any other error -> carry the executor's write_outcome
        # (unknown for a commit-ambiguous 500 on a non-idempotent write) so the
        # caller does NOT record a wrong "not applied". Not applied, no retry.
        return WriteSequenceOutcome(
            applied=False,
            conflict=None,
            verified=False,
            write_outcome=outcome.write_outcome,
            attempts=attempts,
            reason="write failed (see executor error); "
            + (
                "outcome UNKNOWN — do not blind-replay"
                if outcome.write_outcome == ATTEMPT_UNKNOWN
                else "left to W01's typed error boundary"
            ),
        )


# --- helpers ----------------------------------------------------------------
def _field_values_equal(change: FieldChange, a: Any, b: Any) -> bool:
    if change.column_kind in _UNDOCUMENTED_COLUMN_KINDS:
        raise ConcurrencyError(
            f"cannot compare a {change.column_kind.value} column: the Graph "
            "fields facet documents its serialization only generically, with no "
            "per-type schema; refusing to guess equality (a false 'unmoved' "
            "would auto-retry and clobber)"
        )
    return a == b


def _json_bytes(obj: Mapping[str, Any]) -> bytes:
    import json

    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _json_or_none(body: bytes) -> Optional[Any]:
    import json

    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _optional_str(body: Mapping[str, Any], key: str) -> Optional[str]:
    if key not in body:
        return None
    value = body[key]
    if not isinstance(value, str) or not value.strip():
        raise ConcurrencyError(f"{key} must be a non-empty string when present")
    return value.strip()
