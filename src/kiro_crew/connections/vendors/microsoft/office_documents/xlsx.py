"""Offline SpreadsheetML (.xlsx) read, targeted cell write, and reopen-verify.

This is the *local, offline* half of xlsx support. What it is NOT is as much
the point of the slice as what it is, so the contract is stated up front:

* **openpyxl does not calculate formulas.** It hands back either the value the
  writing application cached in the file, or the formula text — never a value
  this engine computed. So every number this module surfaces from a formula
  cell is labelled ``cached`` (read from the file's own value cache) and, when
  no cache is present, the formula text is returned labelled ``formula`` with
  no value at all. This module never fabricates a computed number.
* **It is not the Graph workbook engine.** Microsoft's cloud xlsx path has a
  native Graph ``workbook`` API that computes formulas server-side and speaks
  live-session semantics; that path is a *different* slice and is strictly
  preferred for the cloud scenario. This module refuses any request framed as
  "recalculate", "evaluate", or "live", because honouring it here would be
  impersonating an engine it is not.

Reads reuse the file-sheet endpoint's hardening SHAPE (magic-byte precheck,
:mod:`kiro_crew.zip_vet` inventory bound, decompressed-size caps, defusedxml
via the shared container) rather than re-deriving any of it. Targeted writes go
through :func:`container.rewrite_parts`, so an edit rewrites ONLY the worksheet
part it changes and every other part — styles, theme, sharedStrings, calcChain,
media, drawings — is carried through byte-for-byte. The write is atomic (temp
file + ``os.replace``); it never truncates the destination in place.

The write-back is verified the way the contract demands: after writing, the
destination is reopened through an INDEPENDENT read path
(:func:`read_cells`) and the edited cells are asserted to hold the new values,
so a caller never has to trust the writer's own bookkeeping.
"""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from kiro_crew.zip_vet import ZipInventoryRejected, vet_zip_inventory

from . import constants as C
from . import container
from .errors import DocumentEditError, MalformedDocument, ProtectedDocument, UnsupportedDocument

__all__ = [
    "XLSX_KIND",
    "WORKBOOK_PART",
    "Cell",
    "SheetGrid",
    "XlsxContent",
    "ensure_xlsx_editable",
    "read_cells",
    "write_cells",
    "RecalculationUnsupported",
    "CloudSemanticsUnsupported",
    "refuse_recalculation",
    "refuse_cloud_semantics",
]

# The mandatory main part of a SpreadsheetML package. Its presence is what makes
# a zip an xlsx, the same way ``word/document.xml`` marks a docx.
WORKBOOK_PART = "xl/workbook.xml"
# The relationships part that maps sheet r:id -> worksheet part path.
WORKBOOK_RELS_PART = "xl/_rels/workbook.xml.rels"
SHARED_STRINGS_PART = "xl/sharedStrings.xml"

XLSX_KIND = "xlsx"

# SpreadsheetML namespaces (ECMA-376 / ISO-29500). Not in the sibling's
# constants.py because that module is docx/pptx-scoped; these are xlsx's own.
S_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
S = "{%s}" % S_NS
# The relationship id attribute lives in the officeDocument relationships ns,
# which the sibling already names as R_NS.
R_ID = "{%s}id" % C.R_NS
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
PR = "{%s}" % PKG_REL_NS

# A single cell reference like ``B12`` splits into a column-letters run and a
# 1-based row number.
_CELL_REF_RE = re.compile(r"^([A-Z]+)([1-9][0-9]*)$")


class RecalculationUnsupported(UnsupportedDocument):
    """Raised when a caller asks this offline engine to (re)compute a formula.

    openpyxl does not evaluate formulas; this module never fabricates a
    computed value. A caller wanting real recalculation must use the Graph
    workbook engine (a different slice), not this one.
    """

    reason = "recalculation_unsupported"


class CloudSemanticsUnsupported(UnsupportedDocument):
    """Raised when a caller asks this engine for live / cloud workbook semantics.

    This module handles a local file's bytes offline. It does not open a live
    Graph workbook session and must not claim to; that is a separate slice.
    """

    reason = "cloud_semantics_unsupported"


@dataclass(frozen=True)
class Cell:
    """One worksheet cell as read from the file, never as computed here.

    ``ref`` is the A1 reference (e.g. ``"B2"``). Exactly one of the value
    kinds describes it:

    * ``kind="value"`` — a literal cell value read straight from the file.
    * ``kind="cached"`` — a formula cell whose value is the number/string the
      writing application CACHED in the file. ``formula`` carries the formula
      text; ``value`` carries the cache. This engine did not compute it.
    * ``kind="formula"`` — a formula cell with NO cached value in the file.
      ``value`` is ``None`` and ``formula`` carries the text; nothing was
      computed and nothing is fabricated.
    * ``kind="empty"`` — no value and no formula.
    """

    ref: str
    kind: str
    value: object = None
    formula: str | None = None


@dataclass(frozen=True)
class SheetGrid:
    """One worksheet: its name and its populated cells in row-major order."""

    name: str
    cells: list[Cell] = field(default_factory=list)


@dataclass(frozen=True)
class XlsxContent:
    """The structured read of an .xlsx: its worksheets in workbook order."""

    sheets: list[SheetGrid] = field(default_factory=list)


# ── Rejection gate (xlsx kind resolution, reusing the sibling's markers) ─────


def _magic(path: str, n: int = 8) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def ensure_xlsx_editable(path: str) -> str:
    """Refuse anything that is not a plain, unlocked .xlsx this engine handles.

    Reuses the sibling engine's protection markers (:mod:`.constants`) and typed
    errors (:mod:`.errors`) rather than re-deriving them: legacy OLE2 binaries
    and encrypted-OOXML wrappers (CFB magic), macro-enabled extensions,
    signature parts, macro projects and IRM layers are all refused with the
    same vocabulary the docx/pptx gate uses. The one xlsx-specific step is
    resolving the mandatory main part ``xl/workbook.xml``.

    Returns :data:`XLSX_KIND` on success; raises the matching typed error
    otherwise, BEFORE any write path touches bytes.
    """
    if not os.path.exists(path):
        raise MalformedDocument(f"no such file: {path}")

    ext = Path(path).suffix.lower()
    head = _magic(path)

    # 1. CFB magic = legacy binary (.xls) OR password/agile-encrypted OOXML.
    if head.startswith(C.OLE2_MAGIC):
        if ext in C.LEGACY_BINARY_EXTS:
            raise UnsupportedDocument(
                f"legacy OLE2 binary format ({ext or 'no extension'}); "
                "only Office Open XML (.xlsx) is supported"
            )
        raise ProtectedDocument(
            "compound-file (OLE2) container: password/agile-encrypted OOXML "
            "or a legacy binary; the plain OOXML parts are not readable"
        )

    # 2. Macro-enabled / legacy extension refused on the extension alone.
    if ext in C.MACRO_ENABLED_EXTS:
        raise ProtectedDocument(
            f"macro-enabled workbook ({ext}); refusing to edit a file that "
            "may carry a VBA project"
        )
    if ext in C.LEGACY_BINARY_EXTS:
        raise UnsupportedDocument(f"legacy binary extension ({ext}); only .xlsx is supported")

    # 3. Must be a real zip.
    if not head.startswith(C.ZIP_MAGIC):
        if head.startswith(C.ZIP_EMPTY_MAGIC):
            raise MalformedDocument("empty archive: no OOXML parts")
        raise MalformedDocument("not an Office Open XML container (no zip local-file header)")

    # 4. Bound the declared inventory before opening (zip-bomb / crafted CD).
    try:
        vet_zip_inventory(path, max_members=C.MAX_ARCHIVE_MEMBERS)
    except ZipInventoryRejected as exc:
        raise MalformedDocument(f"archive inventory rejected: {exc.reason}") from exc

    # 5. Inspect members for lock markers and the mandatory workbook part.
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError) as exc:
        raise MalformedDocument(f"cannot read archive: {exc}") from exc

    if any(n.endswith("EncryptedPackage") for n in names):
        raise ProtectedDocument("package contains an EncryptedPackage stream")
    if any(n.startswith(C.SIGNATURE_PART_PREFIX) for n in names):
        raise ProtectedDocument(
            "package carries a digital signature part; editing would invalidate "
            "it (signature presence only — validity is intentionally not checked)"
        )
    if any(n.endswith(C.VBA_PROJECT_SUFFIX) for n in names):
        raise ProtectedDocument("package contains a vbaProject.bin macro project")
    if any(C.DRM_ENCRYPTED_PART_SUFFIX in n for n in names):
        raise ProtectedDocument("package carries an IRM/rights-management protection layer")

    if WORKBOOK_PART not in names:
        raise MalformedDocument(
            "zip container without xl/workbook.xml; not a SpreadsheetML workbook"
        )
    return XLSX_KIND


# ── Read path (reuses the container's hardened part reader + defusedxml) ─────


def _shared_strings(path: str) -> list[str]:
    """Return the workbook's shared-string table, or [] when there is none.

    Cells of type ``s`` reference this table by index. Parsed with the
    container's XXE-safe parser. Rich-text runs (``<r><t>``) are concatenated
    into the plain string.
    """
    try:
        root = container.parse_xml_part(path, SHARED_STRINGS_PART)
    except MalformedDocument:
        # No sharedStrings part is legal: a workbook may inline all strings.
        return []
    out: list[str] = []
    for si in root.findall(f"{S}si"):
        # A shared-string item is either a single <t> or a sequence of <r><t>.
        texts = [t.text or "" for t in si.iter(f"{S}t")]
        out.append("".join(texts))
    return out


def _worksheet_paths(path: str) -> list[tuple[str, str]]:
    """Resolve ``(sheet_name, worksheet_part_path)`` pairs in workbook order.

    Reads ``xl/workbook.xml`` for the sheet names and their r:id, then the
    workbook rels for the r:id -> part-path mapping. Both parts go through the
    hardened parser.
    """
    wb = container.parse_xml_part(path, WORKBOOK_PART)
    sheets_el = wb.find(f"{S}sheets")
    if sheets_el is None:
        return []

    rels = container.parse_xml_part(path, WORKBOOK_RELS_PART)
    rid_to_target: dict[str, str] = {}
    for rel in rels.findall(f"{PR}Relationship"):
        rid = rel.get("Id")
        target = rel.get("Target")
        if rid and target:
            rid_to_target[rid] = target

    pairs: list[tuple[str, str]] = []
    for sheet in sheets_el.findall(f"{S}sheet"):
        name = sheet.get("name") or ""
        rid = sheet.get(R_ID)
        if rid is None:
            continue
        target = rid_to_target.get(rid)
        if target is None:
            continue
        pairs.append((name, _normalize_target(target)))
    return pairs


def _normalize_target(target: str) -> str:
    """Resolve a workbook-rels ``Target`` to a package part path.

    Producers emit three shapes for the same worksheet: package-absolute
    (``/xl/worksheets/sheet1.xml``, leading slash rooted at the package),
    xl-relative (``worksheets/sheet1.xml``, relative to the workbook part's own
    ``xl/`` folder), or already ``xl/…``. All three must map to the stored
    member name ``xl/worksheets/sheet1.xml``.
    """
    if target.startswith("/"):
        # Package-absolute: strip the leading slash to get the member name.
        return target.lstrip("/")
    if target.startswith("xl/"):
        return target
    # xl-relative: the workbook part lives in xl/, so its rels resolve there.
    return f"xl/{target}"


def _cell_from_element(c_el, shared: list[str]) -> Cell:
    """Build a :class:`Cell` from a worksheet ``<c>`` element.

    Never computes anything. A formula cell (``<f>`` present) reports its cache
    only if the ``<v>`` sibling exists; otherwise it reports the formula text
    with no value. The cell type attribute ``t`` selects how ``<v>`` is read
    (shared-string index, inline string, boolean, or numeric/other literal).
    """
    ref = c_el.get("r") or ""
    ctype = c_el.get("t")  # None => numeric; "s" shared; "str"/"inlineStr" string; "b" bool
    f_el = c_el.find(f"{S}f")
    v_el = c_el.find(f"{S}v")
    is_el = c_el.find(f"{S}is")

    def _literal() -> object:
        if ctype == "s":
            # Shared-string index into the table.
            try:
                idx = int(v_el.text) if v_el is not None and v_el.text is not None else -1
            except ValueError:
                return None
            return shared[idx] if 0 <= idx < len(shared) else None
        if ctype == "inlineStr":
            if is_el is not None:
                return "".join(t.text or "" for t in is_el.iter(f"{S}t"))
            return None
        if ctype == "b":
            return bool(int(v_el.text)) if v_el is not None and v_el.text is not None else None
        if ctype == "str":
            return v_el.text if v_el is not None else None
        # Default (numeric / date-serial / error string): return the raw text.
        if v_el is None or v_el.text is None:
            return None
        raw = v_el.text
        try:
            # Prefer int when the serialization is integral, else float.
            return int(raw) if raw.lstrip("-").isdigit() else float(raw)
        except ValueError:
            return raw

    if f_el is not None:
        formula = "=" + (f_el.text or "")
        # A cached value counts ONLY when the <v> carries actual text (or an
        # inline-string cache is present). openpyxl and other producers emit an
        # EMPTY <v></v> placeholder next to a formula they did not evaluate;
        # that empty element is NOT a cache, so it must read as "formula" with
        # no value — never as a cached None the caller might mistake for a real
        # computed result.
        has_cache = (v_el is not None and v_el.text is not None and v_el.text != "") or (
            is_el is not None
        )
        if has_cache:
            return Cell(ref=ref, kind="cached", value=_literal(), formula=formula)
        # No cache: formula text only, no value fabricated.
        return Cell(ref=ref, kind="formula", value=None, formula=formula)

    if (v_el is None or v_el.text is None) and is_el is None:
        return Cell(ref=ref, kind="empty", value=None, formula=None)
    return Cell(ref=ref, kind="value", value=_literal(), formula=None)


def read_cells(path: str) -> XlsxContent:
    """Read an .xlsx into structured, non-computed cell content.

    Rejection-gated. Reads the workbook, its rels, its shared strings and each
    worksheet part directly through the container's hardened, XXE-safe parser,
    so it does not depend on a whole-workbook library for the read path. Every
    formula cell is reported as ``cached`` (file's own cache) or ``formula``
    (no cache) — this function never returns a value it computed.
    """
    ensure_xlsx_editable(path)
    shared = _shared_strings(path)
    sheets: list[SheetGrid] = []
    for name, part in _worksheet_paths(path):
        try:
            ws = container.parse_xml_part(path, part)
        except MalformedDocument:
            # A rels target that does not resolve to a real part: skip it rather
            # than fail the whole read; the workbook is still what it is.
            continue
        sheet_data = ws.find(f"{S}sheetData")
        cells: list[Cell] = []
        if sheet_data is not None:
            for row in sheet_data.findall(f"{S}row"):
                for c_el in row.findall(f"{S}c"):
                    cell = _cell_from_element(c_el, shared)
                    if cell.kind != "empty":
                        cells.append(cell)
        sheets.append(SheetGrid(name=name, cells=cells))
    return XlsxContent(sheets=sheets)


# ── Write path (targeted cell write, byte-preserving every other part) ───────


def _col_row(ref: str) -> tuple[str, int]:
    """Split an A1 reference into ``(column_letters, row_number)``.

    Raises :class:`DocumentEditError` for a malformed reference, before any
    bytes are written.
    """
    m = _CELL_REF_RE.match(ref.strip().upper())
    if not m:
        raise DocumentEditError(f"invalid cell reference: {ref!r}")
    return m.group(1), int(m.group(2))


def _col_to_index(col: str) -> int:
    """Convert column letters (``A``, ``Z``, ``AA``) to a 1-based index."""
    n = 0
    for ch in col:
        n = n * 26 + (ord(ch) - ord("A") + 1)
    return n


def _resolve_worksheet_part(path: str, sheet_name: str) -> str:
    """Return the worksheet part path for *sheet_name*, or raise if absent."""
    for name, part in _worksheet_paths(path):
        if name == sheet_name:
            return part
    raise DocumentEditError(f"workbook has no sheet named {sheet_name!r}")


def _rewrite_worksheet_xml(raw: bytes, edits: dict[str, object]) -> bytes:
    """Return worksheet-part bytes with the cells in *edits* set to literal values.

    *edits* maps an A1 reference to a value (str/int/float/bool). Each addressed
    cell is rewritten as an inline value cell: a string becomes ``t="inlineStr"``
    with an ``<is><t>`` payload, a bool becomes ``t="b"``, a number becomes a
    bare numeric ``<v>``. Any prior formula/value on that cell is dropped for
    that cell only — this engine does not compute, so it will not leave a stale
    cached value beside a value it just overwrote. Rows/cells are created in
    the correct sorted position when absent. Every non-addressed cell, row,
    column definition, merge, style and the sheet's other elements are left
    exactly as parsed.

    Uses ElementTree for the surgical edit and re-serializes ONLY this one
    part; the container carries every OTHER part through byte-for-byte, so the
    whole-package fidelity is preserved even though this part is re-emitted.
    Raised through :class:`DocumentEditError` before any write.
    """
    import xml.etree.ElementTree as ET

    from defusedxml.ElementTree import fromstring

    ET.register_namespace("", S_NS)
    ET.register_namespace("r", C.R_NS)

    root = fromstring(raw)
    sheet_data = root.find(f"{S}sheetData")
    if sheet_data is None:
        raise DocumentEditError("worksheet has no <sheetData> to edit")

    # Index existing rows by their 1-based row number.
    rows_by_num: dict[int, object] = {}
    for row in sheet_data.findall(f"{S}row"):
        r_attr = row.get("r")
        if r_attr and r_attr.isdigit():
            rows_by_num[int(r_attr)] = row

    for ref, value in edits.items():
        col, rownum = _col_row(ref)
        norm_ref = f"{col}{rownum}"
        row = rows_by_num.get(rownum)
        if row is None:
            row = ET.Element(f"{S}row")
            row.set("r", str(rownum))
            rows_by_num[rownum] = row
            _insert_sorted_row(sheet_data, row, rownum)
        c_el = _find_or_make_cell(row, norm_ref, col)
        _set_cell_value(c_el, value)

    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def _insert_sorted_row(sheet_data, row, rownum: int) -> None:
    """Insert *row* into *sheet_data* keeping ascending row-number order."""
    insert_at = len(list(sheet_data))
    for pos, child in enumerate(list(sheet_data)):
        if child is row:
            continue
        r_attr = child.get("r")
        if r_attr and r_attr.isdigit() and int(r_attr) > rownum:
            insert_at = pos
            break
    sheet_data.insert(insert_at, row)


def _find_or_make_cell(row, norm_ref: str, col: str):
    """Return the ``<c>`` for *norm_ref* in *row*, creating it in column order."""
    import xml.etree.ElementTree as ET

    target_idx = _col_to_index(col)
    insert_at = len(list(row))
    for pos, c in enumerate(list(row)):
        cref = c.get("r") or ""
        if cref == norm_ref:
            return c
        m = _CELL_REF_RE.match(cref)
        if m and _col_to_index(m.group(1)) > target_idx:
            insert_at = pos
            break
    c_el = ET.Element(f"{S}c")
    c_el.set("r", norm_ref)
    row.insert(insert_at, c_el)
    return c_el


def _set_cell_value(c_el, value: object) -> None:
    """Set *c_el* to an inline literal *value*, dropping any prior f/v children.

    Never writes a formula and never writes a cached value for a formula: this
    engine does not compute, so an edited cell carries only the literal it was
    given.
    """
    import xml.etree.ElementTree as ET

    for child in list(c_el):
        c_el.remove(child)
    # Reset the type attribute; set it per value kind below.
    if "t" in c_el.attrib:
        del c_el.attrib["t"]

    if isinstance(value, bool):
        c_el.set("t", "b")
        v = ET.SubElement(c_el, f"{S}v")
        v.text = "1" if value else "0"
    elif isinstance(value, (int, float)):
        v = ET.SubElement(c_el, f"{S}v")
        v.text = repr(value) if isinstance(value, float) else str(value)
    else:
        # String: inline string so no sharedStrings surgery is needed. The
        # container carries the existing sharedStrings part through untouched.
        c_el.set("t", "inlineStr")
        is_el = ET.SubElement(c_el, f"{S}is")
        t_el = ET.SubElement(is_el, f"{S}t")
        t_el.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        t_el.text = str(value)


def write_cells(
    src_path: str,
    dst_path: str,
    edits: dict[str, dict[str, object]],
    *,
    verify: bool = True,
) -> XlsxContent | None:
    """Write literal cell values into named sheets, byte-preserving every other part.

    *edits* maps ``sheet_name -> {A1_ref -> value}``. ``src_path`` and
    ``dst_path`` may be equal (in-place). Rejection-gated. Only the worksheet
    parts that actually change are rewritten; every other part — styles, theme,
    sharedStrings, calcChain, media — is carried through byte-for-byte by
    :func:`container.rewrite_parts`, which is atomic (temp file + ``os.replace``)
    so a failure never truncates the destination in place.

    This engine does NOT compute: it writes the literal values it is given. A
    leading ``=`` is written verbatim as text, not as a formula cell, and
    callers wanting real recalculation must use the Graph workbook engine (see
    :class:`RecalculationUnsupported`).

    When *verify* is true (the default), the destination is reopened through the
    INDEPENDENT :func:`read_cells` path and every edited cell is asserted to
    hold the written value; the verified content is returned. A mismatch raises
    :class:`DocumentEditError` — the writer's own success is never trusted
    blindly.
    """
    ensure_xlsx_editable(src_path)
    # Validate references up front so a bad edit fails before any bytes move.
    for cell_edits in edits.values():
        for ref in cell_edits:
            _col_row(ref)

    replacements: dict[str, bytes] = {}
    for sheet_name, cell_edits in edits.items():
        if not cell_edits:
            continue
        part = _resolve_worksheet_part(src_path, sheet_name)
        raw = container.read_part(src_path, part)
        replacements[part] = _rewrite_worksheet_xml(raw, cell_edits)

    if not replacements:
        # No-op (empty edits): produce dst as a faithful copy of src.
        raw = container.read_part(src_path, WORKBOOK_PART)
        container.rewrite_parts(src_path, dst_path, {WORKBOOK_PART: raw})
        return read_cells(dst_path) if verify else None

    container.rewrite_parts(src_path, dst_path, replacements)

    if not verify:
        return None
    return _verify_written(dst_path, edits)


def _verify_written(dst_path: str, edits: dict[str, dict[str, object]]) -> XlsxContent:
    """Reopen *dst_path* via the independent read path and assert every edit landed.

    Raises :class:`DocumentEditError` if any edited cell is missing or holds a
    value other than the one written (numbers compared numerically, everything
    else by string form). Returns the freshly-read content on success.
    """
    content = read_cells(dst_path)
    by_sheet: dict[str, dict[str, Cell]] = {}
    for grid in content.sheets:
        by_sheet[grid.name] = {c.ref: c for c in grid.cells}

    for sheet_name, cell_edits in edits.items():
        got_cells = by_sheet.get(sheet_name, {})
        for ref, expected in cell_edits.items():
            col, rownum = _col_row(ref)
            norm_ref = f"{col}{rownum}"
            cell = got_cells.get(norm_ref)
            if cell is None:
                raise DocumentEditError(
                    f"reopen-verify failed: {sheet_name}!{norm_ref} absent after write"
                )
            if not _values_match(cell.value, expected):
                raise DocumentEditError(
                    f"reopen-verify failed: {sheet_name}!{norm_ref} holds "
                    f"{cell.value!r}, expected {expected!r}"
                )
    return content


def _values_match(got: object, expected: object) -> bool:
    """Whether a read-back value matches what was written."""
    if isinstance(expected, bool):
        return bool(got) == expected
    if isinstance(expected, (int, float)) and isinstance(got, (int, float)):
        return float(got) == float(expected)
    return str(got) == str(expected)


# ── Explicit non-computation / non-cloud contract surface ────────────────────


def refuse_recalculation(what: str = "recalculate") -> None:
    """Refuse a request to compute/evaluate formulas in this offline engine.

    A single call site for the contract: anything framed as recalculation,
    evaluation, or "give me the computed result" is a request this module
    cannot honestly answer, because openpyxl does not compute and this module
    fabricates nothing. Always raises :class:`RecalculationUnsupported`.
    """
    raise RecalculationUnsupported(
        f"this offline xlsx engine cannot {what} formulas; it only reports the "
        "value cached in the file or the formula text. Use the Graph workbook "
        "engine for server-side calculation."
    )


def refuse_cloud_semantics(what: str = "live") -> None:
    """Refuse a request for live / cloud (Graph workbook) semantics.

    Always raises :class:`CloudSemanticsUnsupported`; this module is the local,
    offline path and does not impersonate the Graph workbook engine.
    """
    raise CloudSemanticsUnsupported(
        f"this offline xlsx engine does not provide {what} workbook semantics; "
        "that is the Graph workbook engine's slice."
    )
