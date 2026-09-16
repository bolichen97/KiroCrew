"""Zoom dispatch: drive a real Zoom meetings operation through W01's executor.

WHAT THIS OWNS
==============
This is the piece that makes a Zoom meetings operation ACTUALLY INVOKED --
located, dispatched through W01's real executor and transport, decoded, and
paged -- with no naked sender anywhere. ``locator.py`` shapes the request and
``decoder.py`` reads the reply; this module is the caller that wires them into
:func:`~kiro_crew.connections.control_plane.executor.execute` and
:class:`~kiro_crew.connections.control_plane.executor.PageWalk`, over the
production transport composed by
:func:`~kiro_crew.connections.control_plane.production.build_production_transport`.
It takes the SHAPE of ``vendors/github/dispatch.py``, not its GitHub semantics.

It CONSUMES, and RE-IMPLEMENTS NOTHING, of W01's judgment chain:

* auth / handle trust / credential-mode permit / five-layer governance /
  write-replay all run inside ``execute`` -- this module supplies the inputs and
  never re-decides any of them;
* custody is W01's ``BindingCustodyGate`` (a function of the trusted handle
  view) + L04's ``BindingStore.select_secret``, fenced per call to the trusted
  binding identity -- multi-binding goes through W01's per-binding live-store
  selection, never a local substitute;
* the transport is W01's ``build_production_transport`` with Zoom's own
  ``locate`` / decoder injected -- the ONLY sender. Nothing here touches
  ``urllib`` / ``requests`` / ``httpx``. It never builds a second auth sender,
  HTTP client, or transport, and never a second runtime.

THE TWO ZOOM-SPECIFIC DECISIONS THIS MODULE MAKES
=================================================
1. Which decoder an operation needs (:func:`decode_for`): the cursor ``list``
   decodes as a collection, the cursor-less ``get`` / ``create`` / ``update`` as
   a single object.
2. The HOST-READBACK gate on a create/update (:func:`verify_created_host`): an
   account-level Server-to-Server credential does NOT, by being account-level,
   prove the call hit the intended human host, so a create/update reads
   ``host_id`` back off its response object and asserts it equals the requested
   target. An unverified ``(auth_mode, host)`` pair stays ``unknown`` in either
   direction (W11-A's :data:`~kiro_crew.connections.vendors.zoom.identity.HOST_REACHABILITY_UNKNOWN`),
   never inferred from the credential's mode. This uses the W11-C predicate
   :func:`~kiro_crew.connections.vendors.zoom.meetings.verify_host_readback`; it
   is a check on the OUTCOME, never a second dispatch decision.

FAILURE IS NEVER BLIND-REPLAYED
===============================
A non-idempotent Zoom write (``create`` / ``update`` targeting a series) whose
outcome is uncertain must NOT be reissued -- reissuing a create can build the
meeting twice. This module does not decide that itself: W01's production
transport sets ``write_outcome=unknown`` on an ambiguous mid-flight failure, and
W01's L07 :func:`~kiro_crew.connections.control_plane.writes.replay_decision`
(run inside ``execute`` when the caller passes a prior ``attempt_record``)
REFUSES a replay of an ``unknown`` outcome unless the caller explicitly asserts
idempotence. This module's contribution is only to (a) hand the executor the
prior attempt record when replaying, (b) build the next attempt record from the
executor's returned ``write_outcome`` via :func:`attempt_from_outcome`, and (c)
NOT assert idempotence for a plain create (Zoom create is not idempotent: it has
no client-honored idempotency key, so a retry builds a second meeting). The
idempotency assertion is left to a caller that genuinely holds a Zoom
idempotency guarantee, never presumed here.

SCHEMA VERSIONS THIS BUILDS AGAINST
===================================
Pinned so a shape change in the seam this consumes is a visible break:

* ``EXECUTOR_SCHEMA_VERSION == 4`` -- ``ExecutionOutcome.payload`` + the
  ``write_outcome`` / ``metadata`` fields this reads.
* ``PRODUCTION_SCHEMA_VERSION == 4`` -- ``build_production_transport`` takes a
  ``BindingCustodyGate`` + an L04 ``BindingStore`` and sets ``write_outcome``.
* ``RESULT_SCHEMA_VERSION == 3`` -- the single-authoritative ``next_cursor`` +
  the ``payload`` union.
* ``OPERATION_SCHEMA_VERSION == 2`` -- the ``OperationDescriptor`` TypedDict.

:func:`assert_schema_versions` checks these at composition so a mismatch is a
loud failure, not a silently wrong decode.

WHAT THIS DELIBERATELY DOES NOT OWN
===================================
No auth, no custody, no retry, no fencing, no error classification, no
pagination engine, no ambiguous-write DECISION -- all W01's. No auth/binding/
approval body: those are W01 (chat380). No credential ever reaches this module:
it hands the transport a ``vault``, a ``gate`` and the live ``store``; the
secret is resolved inside the transport, revealed once into a header there, and
never seen here. It opens no socket, sends no real business meeting, and writes
no production account.

See ``docs/system-specs/modules/connector-zoom.md``.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional, cast

from kiro_crew.connections.control_plane.auth_modes import PermittedModes
from kiro_crew.connections.control_plane.executor import (
    EXECUTOR_SCHEMA_VERSION,
    Clock,
    ExecutionOutcome,
    PageWalk,
    Transport,
    advance_page,
    execute,
)
from kiro_crew.connections.control_plane.handle import DerivedHandle
from kiro_crew.connections.control_plane.lifecycle import BindingStore
from kiro_crew.connections.control_plane.operation import (
    OPERATION_SCHEMA_VERSION,
    CredentialMode,
    OperationDescriptor,
)
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    PRODUCTION_SCHEMA_VERSION,
    BindingCustodyGate,
    ResultDecode,
    SecretStore,
    build_production_transport,
)
from kiro_crew.connections.control_plane.result import RESULT_SCHEMA_VERSION
from kiro_crew.connections.control_plane.writes import (
    ATTEMPT_FAILED_NOT_APPLIED,
    ATTEMPT_SUCCEEDED,
    ATTEMPT_UNKNOWN,
    AttemptOutcome,
    AttemptRecord,
    args_fingerprint,
    record_attempt,
)
from kiro_crew.connections.vendors.zoom.decoder import (
    decode_list_page,
    decode_single,
)
from kiro_crew.connections.vendors.zoom.identity import HOST_REACHABILITY_UNKNOWN
from kiro_crew.connections.vendors.zoom.locator import locate
from kiro_crew.connections.vendors.zoom.meetings import (
    OP_CREATE,
    OP_GET,
    OP_LIST,
    OP_UPDATE,
    HostVerification,
)
from kiro_crew.connections.vendors.zoom.meetings import descriptor as _meetings_descriptor
from kiro_crew.connections.vendors.zoom.meetings import (
    verify_host_readback,
)

#: The provider slug whose vault-secret family a Zoom binding's credential
#: belongs to (matches ``registry`` / ``create_binding(slug=...)``). L04's
#: ``select_secret`` reads the ``secret_ref`` off the LIVE store record per
#: binding; the slug is how the binding's secret is seeded, not what the
#: transport resolves against.
ZOOM_SLUG = "zoom"

#: The neutral service range Zoom operations route at (L01 closed set).
ZOOM_SERVICE_ID = "zoom"

#: The mutating operations whose outcome the host-readback gate applies to, and
#: whose ``unknown`` replay L07 must gate.
_WRITE_OPERATIONS = frozenset({OP_CREATE, OP_UPDATE})

#: The schema versions of the W01 seam this dispatch was built against. Named so
#: a downstream reader sees exactly what shapes it pins, and
#: :func:`assert_schema_versions` can fail loudly on a drift.
BUILT_AGAINST_EXECUTOR_SCHEMA = 4
BUILT_AGAINST_PRODUCTION_SCHEMA = 4
BUILT_AGAINST_RESULT_SCHEMA = 3
BUILT_AGAINST_OPERATION_SCHEMA = 2


class ZoomDispatchError(RuntimeError):
    """A Zoom dispatch could not be composed against the W01 seam.

    Raised by :func:`assert_schema_versions` on a schema drift and by
    :func:`decode_for` / :func:`control_plane_descriptor` for an unknown
    ``operation_id``. NOT a vendor error (those are the executor's typed
    boundary) -- a composition / shaping fault this module refuses to proceed
    past.
    """


def assert_schema_versions() -> None:
    """Fail loudly if the consumed W01 seam is not the version this pins.

    A schema constant this module encodes against having moved means the
    envelope, the transport contract, or the descriptor shape changed under it,
    and a silently-wrong decode is worse than a refusal to compose. Called at the
    top of :func:`build_zoom_transport` so no dispatch runs against a drifted
    seam.
    """

    mismatches = []
    if EXECUTOR_SCHEMA_VERSION != BUILT_AGAINST_EXECUTOR_SCHEMA:
        mismatches.append(
            f"executor schema is {EXECUTOR_SCHEMA_VERSION}, built against "
            f"{BUILT_AGAINST_EXECUTOR_SCHEMA}"
        )
    if PRODUCTION_SCHEMA_VERSION != BUILT_AGAINST_PRODUCTION_SCHEMA:
        mismatches.append(
            f"production schema is {PRODUCTION_SCHEMA_VERSION}, built against "
            f"{BUILT_AGAINST_PRODUCTION_SCHEMA}"
        )
    if RESULT_SCHEMA_VERSION != BUILT_AGAINST_RESULT_SCHEMA:
        mismatches.append(
            f"result schema is {RESULT_SCHEMA_VERSION}, built against "
            f"{BUILT_AGAINST_RESULT_SCHEMA}"
        )
    if OPERATION_SCHEMA_VERSION != BUILT_AGAINST_OPERATION_SCHEMA:
        mismatches.append(
            f"operation schema is {OPERATION_SCHEMA_VERSION}, built against "
            f"{BUILT_AGAINST_OPERATION_SCHEMA}"
        )
    if mismatches:
        raise ZoomDispatchError(
            "Zoom dispatch was built against a different W01 seam version: "
            + "; ".join(mismatches)
            + " -- re-verify the shapes before dispatching"
        )


def control_plane_descriptor(operation_id: str) -> OperationDescriptor:
    """Return the executor's five-field descriptor for a Zoom meetings operation.

    A thin pass-through to the W11-C descriptor table
    (:func:`~kiro_crew.connections.vendors.zoom.meetings.descriptor`), which
    already holds the shared-vocabulary ``service_id`` / ``operation_kind`` /
    ``effect`` / ``credential_modes`` for each of the four actions. This module
    OWNS no second copy of them. An unknown ``operation_id`` is refused as a
    :class:`ZoomDispatchError` (the meetings table raises ``KeyError``, which is
    re-raised in this module's own fault type for a uniform caller boundary).
    """

    try:
        return _meetings_descriptor(operation_id)
    except KeyError as exc:
        raise ZoomDispatchError(
            f"operation {operation_id!r} is not a known Zoom meetings operation"
        ) from exc


def decode_for(operation_id: str) -> ResultDecode:
    """Pick the Zoom decoder a given operation needs.

    ``list`` -> :func:`~kiro_crew.connections.vendors.zoom.decoder.decode_list_page`
    (a cursor collection); ``get`` / ``create`` / ``update`` ->
    :func:`~kiro_crew.connections.vendors.zoom.decoder.decode_single` (a single
    object, cursor-less). An unknown operation is refused rather than defaulted,
    so an unclassified endpoint cannot silently decode as a single object.
    """

    if operation_id == OP_LIST:
        return decode_list_page
    if operation_id in (OP_GET, OP_CREATE, OP_UPDATE):
        return decode_single
    raise ZoomDispatchError(f"operation {operation_id!r} is not a known Zoom meetings operation")


def build_zoom_transport(
    *,
    operation_id: str,
    gate: BindingCustodyGate,
    store: BindingStore,
    vault: SecretStore,
    http_send: Optional[Any] = None,
) -> Transport:
    """Compose the production transport for ONE Zoom operation.

    Asserts the W01 seam is the version this pins, then hands
    :func:`~kiro_crew.connections.control_plane.production.build_production_transport`
    Zoom's own :func:`~kiro_crew.connections.vendors.zoom.locator.locate` locator
    and the operation's :func:`decode_for` decoder. Custody is W01's: the
    ``gate`` (a function of the call's trusted handle view, composed for one
    binding identity), the live L04 ``store`` and the ``vault`` go straight to
    the production module, which per call fences the binding via the gate,
    resolves the credential from the LIVE STORE's own record
    (``store.select_secret``), and reveals it into a header there -- no
    credential is seen here. The returned :class:`Transport` is the ONLY sender;
    this module never opens a socket.

    ``http_send`` is W01's own
    :data:`~kiro_crew.connections.control_plane.production.HttpSend` injection
    seam, forwarded unchanged: left unset it is the real ``urllib_http_send``
    (the production path); a test injects a controlled sender so no socket opens.
    Injecting a sender is NOT a naked sender -- the send still goes through W01's
    transport, which resolves custody and attaches the credential; the seam only
    replaces the socket at the bottom.

    A ``gate`` composed for the WRONG binding refuses every call inside the
    transport (W01's ``BindingIdentityMismatchError`` -> a typed ``auth``
    failure) BEFORE the store or vault is asked, so multi-binding is W01's
    per-binding fence + live-store selection, not a local one.
    """

    assert_schema_versions()
    decode = decode_for(operation_id)
    kwargs: dict[str, Any] = dict(
        gate=gate,
        store=store,
        vault=vault,
        locator=locate,
        decode=decode,
    )
    if http_send is not None:
        kwargs["http_send"] = http_send
    return build_production_transport(**kwargs)


def dispatch_operation(
    *,
    operation_id: str,
    handle: DerivedHandle,
    transport: Transport,
    offered_mode: CredentialMode,
    permitted: PermittedModes,
    layers: LayerCeilings,
    governance_scope: str,
    governance_item: str,
    request_args: Optional[Mapping[str, Any]] = None,
    request_idempotency_key: str = "",
    attempt_record: Optional[AttemptRecord] = None,
    clock: Optional[Clock] = None,
) -> ExecutionOutcome:
    """Invoke ONE Zoom operation through W01's executor -- a single call.

    A thin, faithful pass-through to
    :func:`~kiro_crew.connections.control_plane.executor.execute`: it builds the
    control-plane descriptor from the meetings table and forwards every gate
    input unchanged, so the full judgment chain (handle trust -> caller/view
    agreement -> credential-mode permit -> five-layer governance -> write replay)
    runs inside the executor and the transport is reached only if every gate
    passes. Nothing is re-decided here.

    ``attempt_record`` is the prior non-idempotent-write attempt, passed straight
    to the executor's L07 write-replay gate: a prior ``unknown`` refuses a reissue
    (a create would build a second meeting) unless the caller asserted idempotence
    on that record. ``clock`` is forwarded only when supplied (a deterministic
    test injects one); left unset, the executor reads its default server clock
    fresh per call.
    """

    descriptor = control_plane_descriptor(operation_id)
    kwargs: dict[str, Any] = dict(
        offered_mode=offered_mode,
        permitted=permitted,
        layers=layers,
        governance_scope=governance_scope,
        governance_item=governance_item,
        request_args=request_args or {},
        request_idempotency_key=request_idempotency_key,
        attempt_record=attempt_record,
    )
    if clock is not None:
        kwargs["clock"] = clock
    return execute(descriptor, handle, transport, **kwargs)


def open_page_walk(
    *,
    operation_id: str,
    handle: DerivedHandle,
    transport: Transport,
    offered_mode: CredentialMode,
    permitted: PermittedModes,
    layers: LayerCeilings,
    governance_scope: str,
    governance_item: str,
    base_args: Optional[Mapping[str, Any]] = None,
    clock: Optional[Clock] = None,
) -> PageWalk:
    """Open a W01 :class:`PageWalk` for the paginated Zoom ``list`` operation.

    Refuses any operation but ``list``: ``get`` / ``create`` / ``update`` are
    cursor-less, and opening a walk on one would ask the executor to follow a
    ``next_page_token`` that never appears -- the exact cursor-less defect the
    paging unit's negative fault test 3 pins, upheld here on the dispatch side.

    Constructs the executor's own paging driver with the operation's
    control-plane descriptor and the same gate inputs :func:`dispatch_operation`
    forwards. The walk re-runs the full gate chain on every page and carries
    ``base_args`` (the caller's filters) onto each one, so page 2+ is the same
    query as page 1 -- W01's guarantee, not re-implemented here. Drive it with
    :func:`walk_pages` (or W01's :func:`advance_page` directly).
    """

    if operation_id != OP_LIST:
        raise ZoomDispatchError(
            f"operation {operation_id!r} is not cursor-paged; only {OP_LIST!r} opens a "
            "page walk (get/create/update are cursor-less)"
        )
    descriptor = control_plane_descriptor(operation_id)
    walk_kwargs: dict[str, Any] = dict(
        descriptor=descriptor,
        handle=handle,
        transport=transport,
        offered_mode=offered_mode,
        permitted=permitted,
        layers=layers,
        governance_scope=governance_scope,
        governance_item=governance_item,
        base_args=dict(base_args or {}),
    )
    if clock is not None:
        walk_kwargs["clock"] = clock
    return PageWalk(**walk_kwargs)


def walk_pages(walk: PageWalk, *, max_pages: int = 100) -> List[ExecutionOutcome]:
    """Drive a :class:`PageWalk` to completion, returning each page's outcome.

    Calls W01's :func:`~kiro_crew.connections.control_plane.executor.advance_page`
    until the walk sets ``done`` (a terminal page, a denied gate, a transport
    error). It adds no paging logic of its own -- W01's ``PageWalk`` decides
    cursor advance, repeated-cursor termination and per-page re-authorization;
    this only pumps it and bounds the loop.

    ``max_pages`` is a defensive ceiling so a caller cannot spin unboundedly even
    if a provider misbehaved past W01's own repeated-cursor guard; reaching it
    raises :class:`ZoomDispatchError` rather than looping forever.
    """

    outcomes: List[ExecutionOutcome] = []
    for _ in range(max_pages):
        if walk.done:
            break
        outcomes.append(advance_page(walk))
        if walk.done:
            break
    else:
        raise ZoomDispatchError(f"page walk did not terminate within {max_pages} pages")
    return outcomes


# ---------------------------------------------------------------------------
# Host-readback gate on a create/update outcome (credential mode never settles
# host reachability)
# ---------------------------------------------------------------------------
def verify_created_host(
    outcome: ExecutionOutcome,
    target_host_id: Optional[str],
) -> HostVerification:
    """Assert a create/update landed on the intended host, from its response.

    The correctness check the spec requires on every create-path operation: an
    account-level Server-to-Server credential does not, by being account-level,
    prove the call hit the requested human host, so the only sound check is to
    read ``host_id`` back off the response object and compare it to the target.

    Reads the readback ``host_id`` from the outcome's object payload (the
    executor carries the decoded single-object success on
    :attr:`ExecutionOutcome.payload`; the same ``host_id`` the decoder's
    :func:`~kiro_crew.connections.vendors.zoom.decoder.readback_host_id` reads off
    a raw reply) and defers the comparison to the W11-C predicate
    :func:`~kiro_crew.connections.vendors.zoom.meetings.verify_host_readback`:

    * a matching ``host_id`` -> ``verified``;
    * a different one -> ``mismatch`` (the silent wrong-host write this gate
      catches);
    * either side absent (no object, no ``host_id``, no target) ->
      :data:`~kiro_crew.connections.vendors.zoom.identity.HOST_REACHABILITY_UNKNOWN`,
      never inferred from the credential mode.

    A non-success outcome (a denied gate, a transport error, a 412) carries no
    object, so its readback host is ``None`` and the result is ``unknown`` -- a
    write that did not produce a verified object is never reported verified.
    """

    readback = _readback_host_from_outcome(outcome)
    return verify_host_readback(target_host_id, readback)


def _readback_host_from_outcome(outcome: ExecutionOutcome) -> Optional[str]:
    """Read ``host_id`` off a create/update outcome's object payload, or ``None``.

    The payload the executor carries is an
    :class:`~kiro_crew.connections.control_plane.result.ObjectPayload` on a
    single-object success; a collection, bytes, ``None``, or a non-success
    outcome all yield ``None`` (no verified host to read).
    """

    payload = outcome.payload
    obj = getattr(payload, "object", None)
    if not isinstance(obj, Mapping):
        return None
    host_id = obj.get("host_id")
    return host_id if isinstance(host_id, str) and host_id else None


# ---------------------------------------------------------------------------
# Write-replay: build the next attempt record from the executor's outcome
# ---------------------------------------------------------------------------
def attempt_from_outcome(
    *,
    operation_id: str,
    request_args: Mapping[str, Any],
    outcome: ExecutionOutcome,
    request_idempotency_key: str = "",
    idempotent: bool = False,
) -> AttemptRecord:
    """Build the L07 :class:`AttemptRecord` to keep for a write's NEXT attempt.

    A caller records this after a non-idempotent write so a later retry runs
    through the executor's L07 gate correctly. The recorded outcome is derived
    from the executor's :attr:`ExecutionOutcome.write_outcome` -- carried through
    from the transport -- NOT re-inferred here:

    * ``write_outcome == "unknown"`` (the transport could not tell whether the
      effect landed -- a timeout, a 502/503/504, a refused redirect) -> a record
      whose replay L07 will REFUSE unless ``idempotent`` is asserted. This is the
      case blind retry gets wrong, and it is the transport's determination, not
      this module's.
    * a clean success (``ok`` and no ``write_outcome`` claim) -> ``succeeded``
      with the recorded result, so a later replay REUSES it rather than
      duplicating the effect.
    * a determinate failure with no ``unknown`` claim -> ``failed_not_applied``:
      the write provably did not land, so a reissue is safe.

    ``idempotent`` defaults to ``False`` -- a plain Zoom create is NOT idempotent
    (no client-honored idempotency key; a retry builds a second meeting), so
    idempotence is asserted ONLY by a caller that genuinely holds a Zoom
    idempotency guarantee, never presumed here.
    """

    outcome_value = _attempt_outcome_of(outcome)
    recorded = outcome.result if outcome_value == ATTEMPT_SUCCEEDED else None
    return record_attempt(
        operation_id=operation_id,
        args_fingerprint=args_fingerprint(dict(request_args)),
        idempotency_key=request_idempotency_key,
        outcome=outcome_value,
        recorded_result=recorded,
        idempotent=idempotent,
    )


def _attempt_outcome_of(outcome: ExecutionOutcome) -> AttemptOutcome:
    """Map an :class:`ExecutionOutcome` to the L07 :data:`AttemptOutcome`.

    The transport's ``write_outcome`` is authoritative when present: an
    ``unknown`` from the transport stays ``unknown`` (the effect is genuinely
    undetermined), and this module never downgrades it to ``failed_not_applied``
    -- doing so would hand L07 a determinate "did not land" the wire never gave,
    licensing a duplicate write. Absent a transport claim, a success is
    ``succeeded`` and any other terminal (error / precondition) is
    ``failed_not_applied`` (a determinate non-2xx that did not apply the effect).
    """

    if outcome.write_outcome == ATTEMPT_UNKNOWN:
        return cast("AttemptOutcome", ATTEMPT_UNKNOWN)
    if outcome.ok:
        return cast("AttemptOutcome", ATTEMPT_SUCCEEDED)
    # A determinate failure with no unknown claim: the effect provably did not
    # apply (a 4xx/deny/412), so a reissue is safe.
    return cast("AttemptOutcome", ATTEMPT_FAILED_NOT_APPLIED)


__all__ = [
    "BUILT_AGAINST_EXECUTOR_SCHEMA",
    "BUILT_AGAINST_OPERATION_SCHEMA",
    "BUILT_AGAINST_PRODUCTION_SCHEMA",
    "BUILT_AGAINST_RESULT_SCHEMA",
    "HOST_REACHABILITY_UNKNOWN",
    "ZOOM_SERVICE_ID",
    "ZOOM_SLUG",
    "ZoomDispatchError",
    "assert_schema_versions",
    "attempt_from_outcome",
    "build_zoom_transport",
    "control_plane_descriptor",
    "decode_for",
    "dispatch_operation",
    "open_page_walk",
    "verify_created_host",
    "walk_pages",
]
