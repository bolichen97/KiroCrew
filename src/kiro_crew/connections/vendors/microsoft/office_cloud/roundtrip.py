"""W07 · office_cloud — the cloud Office-content round-trip, both locations.

WHAT THIS OWNS
==============
The end-to-end CONTENT round-trip for ``docx`` / ``pptx`` / ``xlsx`` files that
live in a cloud drive — SharePoint document libraries AND OneDrive — as ONE
horizontal capability. It is the cloud half that sits ON TOP of the offline
engine: it reads the real file bytes from the drive, hands them to B's OOXML
engine (docx/pptx) or C's xlsx engine for a targeted, byte-preserving edit or a
template create, commits the edited bytes back with the endpoint's OWN
conditional-commit mechanism, and then reads the content back INDEPENDENTLY to
verify the edit landed on the target resource.

    read real bytes  ->  parser create / targeted in-place edit
                     ->  the SUPPORTED conditional commit
                     ->  independent content read-back

WHAT IT REUSES (never re-implements)
====================================
* **Every network hop goes through W06's production Dispatch**
  (:func:`~kiro_crew.connections.vendors.microsoft.graph.concurrency.build_graph_write_dispatch`),
  which routes through W01's ``execute`` — so the trusted-binding identity, the
  vault custody fencing, the pre-send gates and the unknown-outcome mapping all
  run on every request. This module issues NO raw send and touches NO secret.
* **The body of every hop is read from ``outcome.payload``** — W01's neutral
  payload slot. A content GET decodes (via W06's ``graph_result_decode`` ->
  W01's ``neutral_decode``) to a
  :class:`~kiro_crew.connections.control_plane.result.BytesPayload` carrying the
  file bytes byte-for-byte; a metadata GET decodes to an
  :class:`~kiro_crew.connections.control_plane.result.ObjectPayload`. NEVER by
  indexing ``result``, NEVER from ``outcome.metadata`` (a closed rate-limit
  allowlist), NEVER from a captured reply or a side store.
* **The docx/pptx engine is B's** (``office_documents.engine``) and the **xlsx
  engine is C's** (``office_documents.xlsx``), imported and called — not copied,
  not forked. They operate on local file PATHS, so this module materializes the
  downloaded bytes to a private temp file, edits there, and reads the edited
  bytes back off disk.

THE CONDITIONAL COMMIT, PER THE ENDPOINT'S OWN DOCS
===================================================
Verified per-operation on the official pages, NEVER extrapolated from a sibling:

* **File content** (``GET``/``PUT`` ``…/items/{id}/content``): the download is a
  ``GET`` of the item's ``/content``; the commit is a ``PUT`` of the new bytes to
  the same ``/content``. The endpoint's OWN documented conditional mechanism is
  the ``If-Match`` header carrying the item's ``eTag``/``cTag``: a mismatch
  returns ``412 Precondition Failed`` (Microsoft Graph ``driveItem`` update
  conditional-header contract; the official Q&A confirms the same header on the
  ``PUT …/content`` overwrite). So a version-safe content commit sends the eTag
  read from the item's metadata and a stale eTag is a 412 conflict, refused —
  never a blind overwrite that clobbers a concurrent change.
* **Simple upload only** (files ≤ 250 MB, the shape every Office test document
  here is). A file over 250 MB requires an upload SESSION
  (``driveItem: createUploadSession``); that is a DIFFERENT operation with its
  own chunk/range semantics and is deliberately out of scope here rather than
  faked from the simple-upload contract.
* **``excel.range.write`` stays REFUSED.** The Graph Excel range write documents
  NO eTag / optimistic-concurrency mechanism, so a version-safe conditional
  write cannot exist for it — W06's ``run_version_safe_write`` refuses it before
  any request. That refusal is a WORKBOOK-RANGE fact and is unchanged here. The
  xlsx CONTENT round-trip is a different operation (driveItem bytes), and it
  carries the If-Match/412 content contract like docx and pptx.

TWO LOCATIONS, ONE CAPABILITY
=============================
SharePoint and OneDrive file content are the SAME ``driveItem`` content
endpoints; only the drive LOCATOR differs — ``/me/drive`` or
``/drives/{drive-id}`` for OneDrive, ``/sites/{site-id}/drive`` for SharePoint.
:class:`DriveLocator` is the one place that difference lives; everything after it
is location-agnostic, which is exactly why "both locations" is a requirement and
not an option (``office_documents`` and ``excel_shared_engine`` are horizontal
capability groups spanning both, not a 13th provider).

NOT LIVE / NOT COMPLETE
=======================
This orchestrates real bytes over W01's real transport; it does NOT build auth,
vault or transport, does NOT fake a live call, and NEVER touches a real cloud
business account. W01's auth chain (L03 auth-code, L04 rotation, principal ->
binding) is NOT complete and carries reported gaps; riding it here does not make
it complete.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Union

from kiro_crew.connections.control_plane.result import (
    BytesPayload,
    ObjectPayload,
)
from kiro_crew.connections.vendors.microsoft.graph.concurrency import (
    ARG_BODY,
    ARG_IF_MATCH,
    ARG_METHOD,
    ARG_PATH,
    ColumnKind,
    ConcurrencyError,
    ConcurrencyMode,
    Dispatch,
    DispatchResult,
    FieldChange,
    WriteIntent,
    extract_resource_id,
    extract_version,
    run_version_safe_write,
)

# B's offline OOXML engine (docx/pptx) and C's xlsx engine — imported, not forked.
from kiro_crew.connections.vendors.microsoft.office_documents import engine as _ood_engine
from kiro_crew.connections.vendors.microsoft.office_documents import xlsx as _ood_xlsx


class OfficeFormat(str, Enum):
    """The three cloud Office content formats this round-trip covers."""

    DOCX = "docx"
    PPTX = "pptx"
    XLSX = "xlsx"


#: The media type the commit declares for each format's bytes. Graph's simple
#: upload takes the binary stream; the OOXML content types are declared so a
#: consumer reads what the provider was TOLD, never a guess sniffed from bytes.
_MEDIA_TYPE: Mapping[OfficeFormat, str] = {
    OfficeFormat.DOCX: ("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    OfficeFormat.PPTX: (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation"
    ),
    OfficeFormat.XLSX: ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
}

_SUFFIX: Mapping[OfficeFormat, str] = {
    OfficeFormat.DOCX: ".docx",
    OfficeFormat.PPTX: ".pptx",
    OfficeFormat.XLSX: ".xlsx",
}


class CloudRoundtripError(RuntimeError):
    """A cloud Office round-trip could not complete as a version-safe sequence."""


# =============================================================================
# Drive locator — the ONE place the SharePoint-vs-OneDrive difference lives.
# =============================================================================
@dataclass(frozen=True)
class DriveLocator:
    """A root-relative Graph drive locator for one item, location-agnostic after here.

    A driveItem lives in exactly one drive. This carries the drive's root-relative
    Graph prefix and the item id, and derives the two paths the round-trip uses:
    the item's own metadata path (the ``If-Match`` version source) and its
    ``/content`` path (the bytes). Both SharePoint and OneDrive resolve to the
    SAME ``driveItem`` shape; only the prefix differs.

    Build one with :meth:`onedrive_me`, :meth:`onedrive_by_drive` or
    :meth:`sharepoint_site` so a caller never hand-assembles a prefix that half
    the code then parses differently.
    """

    drive_prefix: str  # e.g. "/me/drive", "/drives/{id}", "/sites/{id}/drive"
    item_id: str

    def __post_init__(self) -> None:
        prefix = self.drive_prefix
        if not prefix.startswith("/") or prefix.endswith("/"):
            raise ConcurrencyError(
                "drive_prefix must be a root-relative path with no trailing "
                f"slash, got {prefix!r}"
            )
        if not str(self.item_id).strip():
            raise ConcurrencyError("item_id must be a non-empty driveItem id")

    @classmethod
    def onedrive_me(cls, item_id: str) -> "DriveLocator":
        """OneDrive, the signed-in user's own drive: ``/me/drive/items/{id}``."""
        return cls(drive_prefix="/me/drive", item_id=item_id)

    @classmethod
    def onedrive_by_drive(cls, drive_id: str, item_id: str) -> "DriveLocator":
        """OneDrive addressed by explicit drive id: ``/drives/{drive-id}/items/{id}``."""
        if not str(drive_id).strip():
            raise ConcurrencyError("drive_id must be a non-empty drive id")
        return cls(drive_prefix=f"/drives/{drive_id}", item_id=item_id)

    @classmethod
    def sharepoint_site(cls, site_id: str, item_id: str) -> "DriveLocator":
        """SharePoint document library, the site's default drive:
        ``/sites/{site-id}/drive/items/{id}``."""
        if not str(site_id).strip():
            raise ConcurrencyError("site_id must be a non-empty SharePoint site id")
        return cls(drive_prefix=f"/sites/{site_id}/drive", item_id=item_id)

    @property
    def item_path(self) -> str:
        """The item's metadata path — the ``If-Match`` version source (a GET here
        returns the driveItem object carrying ``eTag``/``cTag``)."""
        return f"{self.drive_prefix}/items/{self.item_id}"

    @property
    def content_path(self) -> str:
        """The item's ``/content`` path — the bytes (GET downloads, PUT replaces)."""
        return f"{self.drive_prefix}/items/{self.item_id}/content"


# =============================================================================
# The offline edit step — dispatched to B's engine (docx/pptx) or C's (xlsx).
# =============================================================================
#: A local-file edit: given the downloaded file's path and a scratch destination,
#: apply the intended change (in-place edit or template create) and return the
#: DocumentKind. The three concrete builders below cover docx/pptx/xlsx by
#: delegating to the sibling engines.
LocalEdit = Callable[[str, str], object]


def docx_pptx_edit(edits: Mapping[int, str]) -> LocalEdit:
    """A docx/pptx in-place text edit via B's engine.

    ``edits`` keys are zero-based paragraph indices (docx) or one-based slide
    numbers (pptx); B's ``edit_in_place`` dispatches on the resolved kind and
    rewrites ONLY the changed part, carrying every other part byte-for-byte.
    """

    def _edit(src_path: str, dst_path: str) -> object:
        return _ood_engine.edit_in_place(src_path, dst_path, dict(edits))

    return _edit


def xlsx_edit(edits: Mapping[str, Mapping[str, object]]) -> LocalEdit:
    """An xlsx targeted cell write via C's engine.

    ``edits`` maps ``sheet_name -> {A1_ref -> literal value}``. C's ``write_cells``
    rewrites only the changed worksheet parts (byte-preserving styles / theme /
    sharedStrings / calcChain / media) and, with ``verify=True``, reopens the
    destination through its INDEPENDENT read path to assert every edited cell
    holds its value. This writes LITERAL values; it does NOT compute — a formula
    recalculation is ``RecalculationUnsupported`` (see C's engine).
    """

    def _edit(src_path: str, dst_path: str) -> object:
        _ood_xlsx.write_cells(src_path, dst_path, {s: dict(c) for s, c in edits.items()})
        return _ood_xlsx.XLSX_KIND

    return _edit


# =============================================================================
# Read the downloaded / read-back CONTENT bytes from outcome.payload.
# =============================================================================
def content_bytes(hop: DispatchResult) -> bytes:
    """Extract the file bytes a content GET returned, from ``outcome.payload``.

    A content download decodes to a
    :class:`~kiro_crew.connections.control_plane.result.BytesPayload` (W06's
    ``graph_result_decode`` routes a non-JSON body to W01's ``neutral_decode``,
    which carries the body byte-for-byte). The bytes are read THROUGH
    ``outcome.payload`` — never by indexing ``result``, never from
    ``outcome.metadata``, never from a captured reply. A hop that did not return
    a BytesPayload (an error, a 302 with no body carried, a JSON object) raises,
    because a round-trip that read no bytes has nothing to edit or verify.
    """

    if hop.outcome.error is not None:
        raise CloudRoundtripError(
            "content GET failed at the executor (authorization/transport error); "
            "no bytes to read"
        )
    payload = hop.outcome.payload
    if not isinstance(payload, BytesPayload):
        raise CloudRoundtripError(
            "content GET did not return a BytesPayload on outcome.payload "
            f"(got {type(payload).__name__}); refusing to read bytes elsewhere"
        )
    return payload.data


def _metadata_object(hop: DispatchResult) -> Mapping[str, Any]:
    """Read a metadata GET's driveItem object from ``outcome.payload``.

    A single-resource GET decodes to an
    :class:`~kiro_crew.connections.control_plane.result.ObjectPayload`; its
    ``.object`` carries ``id`` / ``eTag`` / ``cTag``. W06's Dispatch also lands
    that on :attr:`DispatchResult.body`, and this prefers ``outcome.payload`` as
    the single documented source. Raises on a non-object hop.
    """

    if hop.outcome.error is not None:
        raise CloudRoundtripError("metadata GET failed at the executor; no version to condition on")
    payload = hop.outcome.payload
    if isinstance(payload, ObjectPayload):
        return payload.object
    # W06's DispatchResult.body is itself taken from outcome.payload (ObjectPayload
    # .object); accept it only as the SAME source, never a side channel.
    if hop.body is not None:
        return hop.body
    raise CloudRoundtripError("metadata GET returned no object payload; cannot read eTag/cTag")


# =============================================================================
# The round-trip outcome.
# =============================================================================
@dataclass(frozen=True)
class RoundtripOutcome:
    """The result of one cloud Office CONTENT round-trip.

    ``committed`` — the conditional content PUT was accepted (2xx). ``verified``
    — the INDEPENDENT content read-back parsed and the intended edit holds on the
    target resource. ``conflict`` — set when a stale ``If-Match`` produced a 412
    and the sequence refused to clobber; ``committed``/``verified`` are then
    False and NOTHING was overwritten. ``downloaded_len`` / ``committed_len`` —
    the byte lengths downloaded and committed, for the evidence receipt.
    ``read_back_kind`` — the DocumentKind the read-back parsed as. ``reason`` —
    a human-readable account.
    """

    location: str
    fmt: OfficeFormat
    committed: bool
    verified: bool
    conflict: bool
    downloaded_len: int
    committed_len: int
    read_back_kind: Optional[object]
    reason: str


def _format_of(kind: object) -> OfficeFormat:
    """Resolve an engine's kind marker to an :class:`OfficeFormat`.

    Both B's :class:`DocumentKind` members (``DOCX``/``PPTX``) and C's
    :data:`XLSX_KIND` are string values (``"docx"``/``"pptx"``/``"xlsx"``), which
    are exactly the :class:`OfficeFormat` values — so the marker maps directly. A
    marker outside that closed set is a broken invariant, not a guess.
    """

    try:
        return OfficeFormat(str(kind))
    except ValueError as exc:  # pragma: no cover - guards a broken engine contract
        raise CloudRoundtripError(f"unrecognized document kind {kind!r}") from exc


def _read_back_edit_holds(
    fmt: OfficeFormat,
    read_back_path: str,
    edits: Union[Mapping[int, str], Mapping[str, Mapping[str, object]]],
) -> bool:
    """Re-parse the INDEPENDENT read-back and assert the intended edit holds.

    Uses the sibling engine's OWN reader (B's ``read`` for docx/pptx, C's
    ``read_cells`` for xlsx) — the same independent path a consumer would use,
    not the writer's own claim.
    """

    if fmt in (OfficeFormat.DOCX, OfficeFormat.PPTX):
        content = _ood_engine.read(read_back_path)
        if fmt is OfficeFormat.DOCX:
            by_index = {p.index: p.text for p in content.paragraphs}
            return all(by_index.get(i) == text for i, text in edits.items())
        by_number = {s.number: s.text for s in content.slides}
        return all(by_number.get(n) == text for n, text in edits.items())
    # xlsx
    content = _ood_xlsx.read_cells(read_back_path)
    by_sheet: dict[str, dict[str, object]] = {}
    for sheet in content.sheets:
        by_sheet[sheet.name] = {c.ref: c.value for c in sheet.cells}
    for sheet_name, cell_edits in edits.items():  # type: ignore[union-attr]
        got = by_sheet.get(sheet_name, {})
        for ref, value in cell_edits.items():  # type: ignore[union-attr]
            if not _ood_xlsx._values_match(got.get(ref), value):
                return False
    return True


def run_content_roundtrip(
    *,
    location: str,
    fmt: OfficeFormat,
    locator: DriveLocator,
    dispatch: Dispatch,
    local_edit: LocalEdit,
    read_back_check: Union[Mapping[int, str], Mapping[str, Mapping[str, object]]],
    scratch_dir: Optional[str] = None,
) -> RoundtripOutcome:
    """Drive the whole content round-trip for ONE (location, format).

    Sequence, every network hop through ``dispatch`` (bound by the caller to
    W06's :func:`build_graph_write_dispatch` -> W01's ``execute``):

    1. **metadata GET** ``locator.item_path`` — read the item's ``eTag``/``cTag``
       and assert identity. This is the version the conditional commit conditions
       on. Body from ``outcome.payload`` (ObjectPayload).
    2. **content GET** ``locator.content_path`` — download the real file bytes.
       Body from ``outcome.payload`` (BytesPayload), byte-for-byte.
    3. **offline edit** — materialize the bytes to a private temp file and apply
       ``local_edit`` (B's engine for docx/pptx, C's for xlsx), producing edited
       bytes on disk.
    4. **conditional content PUT** ``locator.content_path`` with
       ``If-Match: <eTag>`` and the edited bytes. A stale eTag -> 412 -> conflict,
       nothing clobbered.
    5. **independent content GET** ``locator.content_path`` — re-download and
       re-parse through the sibling engine's own reader; assert the intended edit
       holds on the target.

    Returns a :class:`RoundtripOutcome`. Raises :class:`CloudRoundtripError` only
    for a broken invariant (a hop that returned the wrong payload shape); a
    412 conflict is a normal ``conflict=True`` outcome, not an exception.
    """

    # --- 1. metadata GET: the eTag the content commit will condition on -------
    meta = dispatch({ARG_METHOD: "GET", ARG_PATH: locator.item_path})
    meta_obj = _metadata_object(meta)
    rid = extract_resource_id(meta_obj)
    if rid is None or rid != locator.item_id:
        raise CloudRoundtripError(f"metadata identity {rid!r} != target item {locator.item_id!r}")
    version = extract_version(meta_obj)
    if version is None:
        raise CloudRoundtripError(
            "driveItem metadata carried no eTag/cTag; refusing a blind (no "
            "If-Match) content overwrite"
        )

    # --- 2. content GET: the real bytes ---------------------------------------
    got = dispatch({ARG_METHOD: "GET", ARG_PATH: locator.content_path})
    original = content_bytes(got)
    downloaded_len = len(original)

    # --- 3. offline edit on a private temp file -------------------------------
    scratch = scratch_dir
    made_scratch = False
    if scratch is None:
        scratch = tempfile.mkdtemp(prefix="kc-office-cloud-")
        made_scratch = True
    suffix = _SUFFIX[fmt]
    src_path = os.path.join(scratch, f"download{suffix}")
    dst_path = os.path.join(scratch, f"edited{suffix}")
    read_back_path = os.path.join(scratch, f"readback{suffix}")
    try:
        with open(src_path, "wb") as fh:
            fh.write(original)
        edited_kind = local_edit(src_path, dst_path)
        resolved_fmt = _format_of(edited_kind)
        if resolved_fmt is not fmt:
            raise CloudRoundtripError(
                f"engine resolved kind {resolved_fmt.value} != requested {fmt.value}"
            )
        with open(dst_path, "rb") as fh:
            edited_bytes = fh.read()
        committed_len = len(edited_bytes)

        # --- 4. conditional content PUT: If-Match, per the endpoint's own docs -
        put = dispatch(
            {
                ARG_METHOD: "PUT",
                ARG_PATH: locator.content_path,
                ARG_IF_MATCH: version.value,
                ARG_BODY: edited_bytes,
            }
        )
        if put.outcome.precondition is not None:
            # A 412: the item moved since we read its eTag. Refuse to clobber.
            return RoundtripOutcome(
                location=location,
                fmt=fmt,
                committed=False,
                verified=False,
                conflict=True,
                downloaded_len=downloaded_len,
                committed_len=committed_len,
                read_back_kind=None,
                reason="content PUT rejected with 412 (stale If-Match); refused "
                "to overwrite a concurrently-changed file",
            )
        if not put.outcome.ok:
            return RoundtripOutcome(
                location=location,
                fmt=fmt,
                committed=False,
                verified=False,
                conflict=False,
                downloaded_len=downloaded_len,
                committed_len=committed_len,
                read_back_kind=None,
                reason="content PUT failed at the executor "
                "(see typed error / write_outcome); not committed",
            )

        # --- 5. INDEPENDENT content read-back -> re-parse -> verify the edit ---
        rb = dispatch({ARG_METHOD: "GET", ARG_PATH: locator.content_path})
        rb_bytes = content_bytes(rb)
        with open(read_back_path, "wb") as fh:
            fh.write(rb_bytes)
        rb_kind = _ood_engine.classify(read_back_path) if fmt is not OfficeFormat.XLSX else None
        if fmt is OfficeFormat.XLSX:
            _ood_xlsx.ensure_xlsx_editable(read_back_path)
        verified = _read_back_edit_holds(fmt, read_back_path, read_back_check)
        return RoundtripOutcome(
            location=location,
            fmt=fmt,
            committed=True,
            verified=verified,
            conflict=False,
            downloaded_len=downloaded_len,
            committed_len=committed_len,
            read_back_kind=rb_kind,
            reason=(
                "content committed and the intended edit holds on the read-back " "target resource"
                if verified
                else "content committed but the read-back did not show the " "intended edit"
            ),
        )
    finally:
        if made_scratch:
            for p in (src_path, dst_path, read_back_path):
                try:
                    os.unlink(p)
                except FileNotFoundError:
                    pass
            try:
                os.rmdir(scratch)
            except OSError:
                pass


# =============================================================================
# The refused workbook-range path (excel.range.write) — kept refused here too.
# =============================================================================
def refuse_excel_range_version_safe_write(*, path: str) -> None:
    """Assert the ``excel.range.write`` conflict-negative: it has NO conditional commit.

    The Graph Excel range write documents no eTag / optimistic-concurrency
    mechanism, so a version-safe conditional write cannot exist for it. Delegates
    to W06's :func:`run_version_safe_write` with
    :data:`ConcurrencyMode.NONE_LAST_WRITE_WINS`, which refuses BEFORE any
    request — zero requests issued. Always raises
    :class:`~kiro_crew.connections.vendors.microsoft.graph.concurrency.ConcurrencyError`;
    it exists so a caller (and the test) exercises the refusal against the SAME
    seam the metadata path uses, rather than re-encoding the rule here.

    This is the WORKBOOK-RANGE fact and is distinct from the xlsx CONTENT
    round-trip, which is a driveItem-bytes operation carrying the If-Match/412
    content contract.
    """

    def _never(_args: Mapping[str, Any]) -> DispatchResult:  # pragma: no cover
        raise AssertionError("excel.range.write must issue ZERO requests: no hop may be dispatched")

    run_version_safe_write(
        mode=ConcurrencyMode.NONE_LAST_WRITE_WINS,
        path=path,
        intent=_EXCEL_RANGE_SENTINEL_INTENT,
        dispatch=_never,
    )


# A sentinel intent so the refusal is reachable without a caller assembling a
# WriteIntent for an operation that can never run. run_version_safe_write refuses
# on the mode BEFORE it reads the intent, so this is never inspected.
_EXCEL_RANGE_SENTINEL_INTENT = WriteIntent(
    resource_id="excel-range",
    changes={"A1": FieldChange(baseline="", intended="", column_kind=ColumnKind.SCALAR)},
)
