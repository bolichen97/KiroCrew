"""Microsoft Graph optimistic-concurrency version-safe write protocol (vendor seats).

WHAT THIS OWNS -- THE TWO VENDOR SEATS W01 LEAVES OPEN
======================================================
W01's executor (``connections/control_plane/executor.py`` +
``production.py``) owns the decision chain, credential custody, and the real
HTTP sender. It deliberately leaves two seats VENDOR-OWNED and injected, because
turning an operation into a concrete request and reading a 2xx body back are
per-provider:

* :data:`~kiro_crew.connections.control_plane.production.RequestLocator`
  ``= Callable[..., HttpRequest]`` -- shape the concrete Graph request.
* :data:`~kiro_crew.connections.control_plane.production.ResultDecode`
  ``= Callable[..., OperationResult]`` -- map a 2xx reply to the L01 envelope;
  W01 marks it vendor-owned for anything CURSOR-SHAPED, which is where A's paging
  (``vendors/microsoft/graph/paging.py``) meets it.

This module FILLS those two seats for the Graph optimistic-concurrency write
operations and carries the pure protocol logic they build on. It does NOT
implement transport, set ``Authorization``, copy a W01 module, or build a vault.

WHERE AUTHENTICITY ACTUALLY COMES FROM (not from this module)
=============================================================
An earlier iteration tried to prove a call's origin with a caller-supplied
"correlation id" echoed in a caller-supplied response Mapping. Both sides were
the caller's, so it proved nothing -- and W01's own transport says why it never
could: ``HttpRequest.headers`` are "vendor headers WITHOUT the credential; the
transport adds ``Authorization`` itself so a locator never touches a secret". A
vendor layer does not own auth, so nothing it echoes can attest a call. That
echo layer is REMOVED. Authenticity is established by the two things this module
does not fabricate:

1. **Trusted binding identity.** W01's executor passes the ``TrustedHandleView``
   to the transport, and ``BindingSecretSelector`` REFUSES a call whose
   ``binding_fingerprint`` (a keyed HMAC) is not the composed one, BEFORE any
   vault read. Identity comes from there, not from a quadruple this module lets
   a caller assemble.
2. **The sender call relationship.** The reply this module reads back is the
   :class:`HttpReply` W01's sender RETURNED for the :class:`HttpRequest` this
   module's :data:`RequestLocator` produced -- a call-return binding in the
   executor's own code path. A read-back verdict is therefore about the reply to
   the request that was issued, not about "some bytes". ``request-id`` and
   ``client-request-id`` are NOT relied on: they are not necessarily equal and
   are not an auth proof.

THE VERSION-SAFE PROTOCOL (pure logic, on real replies)
=======================================================
* Read the version identifier (``eTag`` / ``cTag``) from a reply; the two kinds
  are DISTINCT and ``If-Match`` acceptance is decided PER ENDPOINT.
* Conditional write only where evidence supports it (SharePoint list item;
  OneDrive driveitem metadata -- both a real 412 contract, equal in force,
  accepting eTag [+ cTag for driveitem]). ``excel.range.write`` has NO eTag
  mechanism and a conditional write is REFUSED.
* 412 recovery is CONFLICT-FIRST: retry only when every intended field's
  baseline still equals its fresh value; otherwise surface the conflict and
  resend nothing (never a blind etag-swap replay).
* Read-back verifies the target fields hold the intended values on the reply
  that answered the read request; it never claims write ATTRIBUTION.

Field comparison is PER TYPED COLUMN: a scalar compares directly, a typed
column (lookup / person-or-group / multi-value) has no documented per-type
equality schema, so comparing it is REFUSED rather than guessed (a false
"unmoved" would auto-retry and clobber). ``column_kind`` is REQUIRED.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Optional

from kiro_crew.connections.control_plane.production import (
    HttpReply,
    HttpRequest,
    neutral_decode,
)
from kiro_crew.connections.control_plane.result import OperationResult
from kiro_crew.connections.vendors.microsoft.graph.payload import (
    ODATA_NEXT_LINK,
    parse_collection,
)

# --- version-identifier keys on a read reply body ---------------------------
ODATA_ETAG = "@odata.etag"
FIELD_ETAG = "eTag"
FIELD_CTAG = "cTag"
FIELD_ID = "id"
ODATA_ID = "@odata.id"


class VersionKind(str, Enum):
    """Which version-like tag a :class:`VersionTag` carries. Closed set.

    ``ETAG`` -- entity tag (any change). ``CTAG`` -- content tag. Kept distinct;
    ``If-Match`` acceptance is per-endpoint, never global.
    """

    ETAG = "etag"
    CTAG = "ctag"


class ColumnKind(str, Enum):
    """How a SharePoint ``fields``-facet column is compared. Closed set.

    ``SCALAR`` compares directly. ``LOOKUP`` / ``PERSON_OR_GROUP`` /
    ``MULTIVALUE`` have no documented per-type equality schema, so a comparison
    is REFUSED rather than guessed. Required on every :class:`FieldChange`.
    """

    SCALAR = "scalar"
    LOOKUP = "lookup"
    PERSON_OR_GROUP = "person_or_group"
    MULTIVALUE = "multivalue"


_UNDOCUMENTED_COLUMN_KINDS = frozenset(
    {ColumnKind.LOOKUP, ColumnKind.PERSON_OR_GROUP, ColumnKind.MULTIVALUE}
)


class ConcurrencyError(ValueError):
    """A version-safe write precondition was violated, or a guarantee refused.

    A shaping/precondition fault only -- NOT a vendor error (vendor errors are
    W01's typed boundary).
    """


@dataclass(frozen=True)
class VersionTag:
    """A validated version identifier read from a reply body."""

    kind: VersionKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise ConcurrencyError("version tag value must be a non-empty string")


class ConcurrencyMode(str, Enum):
    """The optimistic-concurrency contract of a single operation. Closed set.

    ``LISTITEM_ETAG`` -- ``sharepoint.listitem.update``; ``If-Match`` = eTag.
    ``DRIVEITEM_ETAG_OR_CTAG`` -- ``onedrive.driveitem.metadata.update``; a real
    412 contract equal in force, ``If-Match`` = eTag OR cTag.
    ``NONE_LAST_WRITE_WINS`` -- ``excel.range.write``; no mechanism, refused.
    """

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
    """Whether ``mode`` has an ``If-Match`` conditional-write mechanism at all."""

    return mode in _IF_MATCH_VALIDATORS


def accepts_validator(mode: ConcurrencyMode, kind: VersionKind) -> bool:
    """Whether ``mode``'s endpoint accepts a ``kind`` version as ``If-Match``."""

    return kind in _IF_MATCH_VALIDATORS.get(mode, frozenset())


def has_412_contract(mode: ConcurrencyMode) -> bool:
    """Whether ``mode`` has a real 412 conditional-write contract (both writers)."""

    return mode in _IF_MATCH_VALIDATORS


def extract_version(body: Mapping[str, Any]) -> Optional[VersionTag]:
    """Read a version identifier from a reply body, preferring the entity tag.

    Prefers ``eTag`` (``@odata.etag`` annotation, else the ``eTag`` field), falls
    back to a ``cTag`` reported as ``CTAG`` kind (never relabelled). Returns
    ``None`` when absent; raises for a present-but-malformed value.
    """

    etag = _optional_str(body, ODATA_ETAG)
    if etag is None:
        etag = _optional_str(body, FIELD_ETAG)
    if etag is not None:
        return VersionTag(kind=VersionKind.ETAG, value=etag)
    ctag = _optional_str(body, FIELD_CTAG)
    if ctag is not None:
        return VersionTag(kind=VersionKind.CTAG, value=ctag)
    return None


@dataclass(frozen=True)
class FieldChange:
    """One intended field change, with the BASELINE it was decided against.

    ``baseline`` -- the field's value in the read that produced the ``If-Match``
    version. ``intended`` -- the value this write sets. ``column_kind`` -- how it
    is compared (REQUIRED, no default: an untagged typed column must never be
    silently compared as a scalar).
    """

    baseline: Any
    intended: Any
    column_kind: ColumnKind


@dataclass(frozen=True)
class WriteIntent:
    """The baseline-anchored change THIS write intends, keyed by field name."""

    changes: Mapping[str, FieldChange]

    def __post_init__(self) -> None:
        if not self.changes:
            raise ConcurrencyError("a write intent must name at least one field to change")
        object.__setattr__(self, "changes", MappingProxyType(dict(self.changes)))

    def merge_patch_body(self) -> Mapping[str, Any]:
        """The PATCH merge body -- each named field's INTENDED value."""

        return {name: change.intended for name, change in self.changes.items()}


# =============================================================================
# SEAT 1 -- RequestLocator: shape a concrete Graph HttpRequest (no credential).
# =============================================================================
def graph_request_locator(
    *,
    method: str,
    endpoint_host: str,
    path: str,
    if_match: Optional[str] = None,
    body: Optional[bytes] = None,
    extra_headers: Optional[Mapping[str, str]] = None,
) -> HttpRequest:
    """Shape one concrete Graph :class:`HttpRequest`. Fills W01's RequestLocator seat.

    Assembles the absolute ``https`` URL from ``endpoint_host`` (the Graph cloud
    host the executor is bound to) and ``path`` (A's ``build_path`` result, root
    relative with a leading ``/``), the vendor headers, and the request body. It
    attaches ``If-Match`` when the caller passes a version validator, and NOTHING
    resembling a credential: per W01's contract the transport adds
    ``Authorization`` itself, so a locator never touches a secret.
    """

    host = endpoint_host.strip()
    if not host:
        raise ConcurrencyError("endpoint_host must be a non-empty Graph service host")
    if not path.startswith("/"):
        raise ConcurrencyError("path must be a root-relative Graph path (build_path result)")
    headers: dict[str, str] = {}
    if extra_headers:
        headers.update(extra_headers)
    for banned in ("authorization", "proxy-authorization", "cookie"):
        if any(k.lower() == banned for k in headers):
            raise ConcurrencyError(
                f"a locator must not set {banned!r}: the transport owns credentials"
            )
    if if_match is not None:
        if not if_match.strip():
            raise ConcurrencyError("If-Match value must be non-empty when provided")
        headers["If-Match"] = if_match
    url = f"https://{host}{path}"
    return HttpRequest(method=method.upper(), url=url, headers=headers, body=body)


def conditional_write_request(
    *,
    mode: ConcurrencyMode,
    endpoint_host: str,
    path: str,
    version: Optional[VersionTag],
    intent: WriteIntent,
    encode_body: "Any" = None,
) -> HttpRequest:
    """Build the version-safe conditional-write :class:`HttpRequest` for ``mode``.

    * ``NONE_LAST_WRITE_WINS`` (Excel range): REFUSES -- no eTag mechanism.
    * A conditional-write mode with a MISSING version: REFUSES (no blind write,
      no empty ``If-Match``).
    * A version whose KIND the endpoint does not accept: REFUSES (per-endpoint).
    * Otherwise: a PATCH with ``If-Match: <version.value>`` and the intent's
      merge body encoded by ``encode_body`` (defaults to compact JSON bytes).
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
            "read; refusing to send an unconditional (blind) write with no "
            "If-Match -- version safety must not silently degrade"
        )
    if not accepts_validator(mode, version.kind):
        accepted = ", ".join(sorted(k.value for k in _IF_MATCH_VALIDATORS[mode]))
        raise ConcurrencyError(
            f"{mode.value} does not accept a {version.kind.value} as an If-Match "
            f"validator (accepts: {accepted}); this rule is per-endpoint"
        )
    encoder = encode_body if encode_body is not None else _json_bytes
    return graph_request_locator(
        method="PATCH",
        endpoint_host=endpoint_host,
        path=path,
        if_match=version.value,
        body=encoder(intent.merge_patch_body()),
        extra_headers={"Content-Type": "application/json"},
    )


# =============================================================================
# SEAT 2 -- ResultDecode: map a 2xx HttpReply to an OperationResult.
# =============================================================================
def graph_result_decode(reply: HttpReply) -> OperationResult:
    """Map a 2xx Graph :class:`HttpReply` to an :class:`OperationResult`.

    Fills W01's ResultDecode seat, cursor-shaped: a collection body is read
    through A's :func:`parse_collection`, and the presence of ``@odata.nextLink``
    becomes ``status='partial'`` with the opaque link as ``next_cursor`` (more
    pages remain), else ``status='ok'`` with ``next_cursor=None``. A body that is
    not a Graph collection envelope (a single-item read, an empty write ack)
    falls back to W01's :func:`neutral_decode`, which never guesses a cursor.
    """

    parsed = _json_or_none(reply.body)
    if isinstance(parsed, Mapping) and "value" in parsed:
        page = parse_collection(parsed)
        if page.next_link is not None:
            return {"status": "partial", "next_cursor": page.next_link}
        return {"status": "ok", "next_cursor": None}
    # Not a collection: defer to W01's neutral decode (204/empty/单项 body).
    return neutral_decode(reply)


# =============================================================================
# 412 recovery -- CONFLICT-FIRST, over the REAL reply the sender returned.
# =============================================================================
PRECONDITION_FAILED = 412


@dataclass(frozen=True)
class Conflict:
    """A surfaced 412 conflict the caller must resolve; NOT auto-resent."""

    moved_fields: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class RetryPlan:
    """The outcome of a 412 recovery decision.

    ``should_retry`` is True only when every intended field's fresh value still
    equals its baseline; then ``fresh_version`` is the version to build the retry
    ``If-Match`` from. Otherwise ``conflict`` holds the surfaced conflict and
    nothing is resent.
    """

    should_retry: bool
    reason: str
    fresh_version: Optional[VersionTag] = None
    conflict: Optional[Conflict] = None


def recover_from_precondition_failed(
    mode: ConcurrencyMode,
    reply: HttpReply,
    intent: WriteIntent,
    re_read_reply: HttpReply,
) -> RetryPlan:
    """Plan the 412 recovery over the REAL replies the sender returned.

    ``reply`` is the reply to the conditional write (its status is inspected for
    412); ``re_read_reply`` is the reply to an INDEPENDENT re-GET the caller
    issued after the 412 -- the sender-call relationship is what ties each reply
    to its request, so this decision is about the answers to the requests
    actually issued, not arbitrary bytes.

    CONFLICT-FIRST: on a 412 for a conditional-write mode, retry ONLY when every
    intended field's fresh value (from ``re_read_reply``'s body) still equals its
    baseline. Any moved field -> :class:`Conflict`, resend nothing. A typed
    column with no documented schema RAISES (refuse, never guess a false
    "unmoved"). A non-412, or a mode with no 412 contract, does not retry here.
    """

    if not has_412_contract(mode):
        return RetryPlan(
            should_retry=False,
            reason="mode has no 412 contract; not handled by this layer",
        )
    if reply.status != PRECONDITION_FAILED:
        return RetryPlan(should_retry=False, reason="not a 412 precondition failure")

    fresh_body = _json_or_none(re_read_reply.body)
    if not isinstance(fresh_body, Mapping):
        return RetryPlan(
            should_retry=False,
            reason="412 conflict: the re-read reply has no readable body to "
            "compare fresh field values against; surfacing the conflict",
            conflict=Conflict(moved_fields=(), reason="re-read body unreadable"),
        )

    moved = tuple(
        name
        for name, change in intent.changes.items()
        if name not in fresh_body
        or not _field_values_equal(change, change.baseline, fresh_body[name])
    )
    if moved:
        return RetryPlan(
            should_retry=False,
            reason="412 conflict: a concurrent writer changed intended field(s) "
            + ", ".join(moved)
            + "; refusing to overwrite -- surface the conflict for resolution",
            conflict=Conflict(
                moved_fields=moved,
                reason="fresh value(s) differ from the baseline this write "
                "assumed on: " + ", ".join(moved),
            ),
        )

    fresh_version = extract_version(fresh_body)
    if fresh_version is None:
        return RetryPlan(
            should_retry=False,
            reason="412 conflict: the re-read carries no version to build a fresh "
            "If-Match from; surfacing the conflict rather than a blind retry",
            conflict=Conflict(moved_fields=(), reason="no fresh version in re-read"),
        )
    return RetryPlan(
        should_retry=True,
        reason="412 resolved: no intended field moved off its baseline; retry "
        "with the fresh version",
        fresh_version=fresh_version,
    )


# =============================================================================
# Read-back verification -- over the reply that answered the read request.
# =============================================================================
@dataclass(frozen=True)
class ReadBackVerdict:
    """The outcome of an independent read-back after a conditional write.

    ``verified`` is True only when every intended field holds its intended value
    in the read-back reply's body. ``mismatches`` names the fields that did not.
    On success the claim is narrow: the target post-condition HOLDS on the
    resource the read request addressed -- NOT that THIS write produced it.
    """

    verified: bool
    mismatches: tuple[str, ...]
    reason: str


def verify_read_back(intent: WriteIntent, read_back_reply: HttpReply) -> ReadBackVerdict:
    """Verify the target post-condition on the reply that answered the read-back.

    ``read_back_reply`` is the :class:`HttpReply` the sender returned for the
    read-back GET the caller issued -- the sender-call relationship is the tie
    between this reply and that request, so the verdict is about the read this
    write's caller performed, not stray bytes. It asserts every intended field
    equals its intended value (per typed column; an undocumented typed column
    RAISES). A moved version tag is not used. It never claims attribution.
    """

    body = _json_or_none(read_back_reply.body)
    if not isinstance(body, Mapping):
        return ReadBackVerdict(
            verified=False,
            mismatches=tuple(intent.changes),
            reason="read-back reply has no readable body to verify against",
        )
    mismatches = tuple(
        name
        for name, change in intent.changes.items()
        if name not in body or not _field_values_equal(change, change.intended, body[name])
    )
    if mismatches:
        return ReadBackVerdict(
            verified=False,
            mismatches=mismatches,
            reason="these intended fields do not hold their intended value: "
            + ", ".join(mismatches),
        )
    return ReadBackVerdict(
        verified=True,
        mismatches=(),
        reason="target post-condition holds on the read-back resource "
        "(not a claim that this write produced it)",
    )


# --- helpers ----------------------------------------------------------------
def _field_values_equal(change: FieldChange, a: Any, b: Any) -> bool:
    """Compare two values for one field PER TYPED COLUMN; refuse undocumented types."""

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


# ``ODATA_NEXT_LINK`` is A's paging constant, re-referenced so a reader sees the
# cursor axis this decoder defers to; imported to keep the dependency explicit.
_CURSOR_ANNOTATION = ODATA_NEXT_LINK
