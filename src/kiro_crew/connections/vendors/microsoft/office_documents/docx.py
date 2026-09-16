"""Offline WordprocessingML (.docx) read, template-create and in-place edit.

Two deliberately different code paths, for the reason W07's contract states:

* **Structured read** (:func:`read_document`) walks ``word/document.xml`` for
  paragraphs and tables. It can lean on ``python-docx`` (declared) for the
  whole-document read, since a read never has to preserve anything.

* **Targeted in-place edit** (:func:`replace_paragraph_text`) does NOT round-trip
  the whole package through a library. It rewrites ONLY ``word/document.xml`` at
  the part level and copies every other part byte-for-byte (see
  ``container.rewrite_parts``). A whole-package re-serialize would drop or
  reorder theme/styles/media/customXml that the authoring app wrote, so the
  fidelity contract requires the part-level path.

Template creation (:func:`create_from_template`) is a rejection-gated verbatim
copy of a local template file with an optional set of paragraph substitutions
applied through the same part-level editor — never a fresh synthesis that would
lose the template's styling.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import constants as C
from . import container
from .errors import DocumentEditError
from .rejection import DocumentKind, ensure_editable

__all__ = [
    "Paragraph",
    "Table",
    "DocxContent",
    "read_document",
    "create_from_template",
    "replace_paragraph_text",
]


@dataclass(frozen=True)
class Paragraph:
    """One WordprocessingML paragraph: its plain text and its style name."""

    index: int
    text: str
    style: str = ""


@dataclass(frozen=True)
class Table:
    """One table as a row-major grid of cell strings."""

    index: int
    rows: list[list[str]] = field(default_factory=list)


@dataclass(frozen=True)
class DocxContent:
    """The structured read of a .docx: ordered paragraphs and tables."""

    paragraphs: list[Paragraph] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)

    @property
    def text(self) -> str:
        """All paragraph text joined with newlines (tables excluded)."""
        return "\n".join(p.text for p in self.paragraphs)


def _paragraph_text(p_elem) -> str:
    """Concatenate the ``<w:t>`` runs under a ``<w:p>`` element."""
    parts: list[str] = []
    for t in p_elem.iter(f"{C.W}t"):
        if t.text:
            parts.append(t.text)
    return "".join(parts)


def _paragraph_style(p_elem) -> str:
    """The referenced paragraph-style id, or '' when none is set."""
    pPr = p_elem.find(f"{C.W}pPr")
    if pPr is None:
        return ""
    pStyle = pPr.find(f"{C.W}pStyle")
    if pStyle is None:
        return ""
    return pStyle.get(f"{C.W}val", "")


def read_document(path: str) -> DocxContent:
    """Read a .docx into structured paragraphs and tables.

    Rejection-gated: a protected/unsupported/malformed file raises the matching
    typed error before any parse. Reads ``word/document.xml`` directly with the
    hardened parser so it does not depend on a whole-document library for the
    read path, and walks the body in document order.
    """
    ensure_editable(path, expected_kind=DocumentKind.DOCX)
    root = container.parse_xml_part(path, C.DOCX_MAIN_PART)
    body = root.find(f"{C.W}body")
    if body is None:
        return DocxContent()

    paragraphs: list[Paragraph] = []
    tables: list[Table] = []
    p_index = 0
    t_index = 0
    for child in body:
        tag = child.tag
        if tag == f"{C.W}p":
            paragraphs.append(
                Paragraph(
                    index=p_index,
                    text=_paragraph_text(child),
                    style=_paragraph_style(child),
                )
            )
            p_index += 1
        elif tag == f"{C.W}tbl":
            rows: list[list[str]] = []
            for tr in child.findall(f"{C.W}tr"):
                cells: list[str] = []
                for tc in tr.findall(f"{C.W}tc"):
                    cell_text = "\n".join(_paragraph_text(p) for p in tc.findall(f"{C.W}p"))
                    cells.append(cell_text)
                rows.append(cells)
            tables.append(Table(index=t_index, rows=rows))
            t_index += 1
    return DocxContent(paragraphs=paragraphs, tables=tables)


def _rewrite_document_xml(raw: bytes, edits: dict[int, str]) -> bytes:
    """Return ``word/document.xml`` bytes with paragraph *edits* applied.

    *edits* maps a zero-based body-paragraph index to its new plain text. The
    rewrite touches ONLY the addressed paragraphs' runs: it collapses each
    target paragraph's runs to a single ``<w:r><w:t>`` carrying the new text,
    preserving the paragraph's ``<w:pPr>`` (style, numbering) so formatting
    survives. Non-addressed paragraphs, tables, sectPr and everything else are
    left exactly as parsed.

    Raised through :class:`DocumentEditError` when an index is out of range, so
    the caller learns before any bytes are written.
    """
    import xml.etree.ElementTree as ET

    # Register the OOXML namespaces so ET emits the canonical ``w:`` prefix
    # rather than inventing ``ns0``. defusedxml parses; ET writes the subtree.
    ET.register_namespace("w", C.W_NS)
    ET.register_namespace("r", C.R_NS)

    from defusedxml.ElementTree import fromstring

    root = fromstring(raw)
    body = root.find(f"{C.W}body")
    if body is None:
        raise DocumentEditError("document has no <w:body> to edit")

    p_elems = [child for child in body if child.tag == f"{C.W}p"]
    max_index = len(p_elems) - 1
    for idx in edits:
        if idx < 0 or idx > max_index:
            raise DocumentEditError(f"paragraph index {idx} out of range (0..{max_index})")

    for idx, new_text in edits.items():
        p = p_elems[idx]
        pPr = p.find(f"{C.W}pPr")
        # Drop existing runs and run-level children, keep pPr.
        for child in list(p):
            if child.tag != f"{C.W}pPr":
                p.remove(child)
        run = ET.SubElement(p, f"{C.W}r")
        t = ET.SubElement(run, f"{C.W}t")
        # Preserve leading/trailing whitespace exactly as Word requires.
        t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        t.text = new_text
        # Ensure pPr stays first if it existed (schema requires pPr before runs).
        if pPr is not None:
            p.remove(pPr)
            p.insert(0, pPr)

    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def replace_paragraph_text(
    src_path: str,
    dst_path: str,
    edits: dict[int, str],
) -> None:
    """Replace the text of specific paragraphs, byte-preserving every other part.

    *edits* maps zero-based body-paragraph index to new text. ``src_path`` and
    ``dst_path`` may be equal (in-place). Rejection-gated. Raises
    :class:`DocumentEditError` for an out-of-range index BEFORE writing, so a
    bad edit never truncates the destination.
    """
    ensure_editable(src_path, expected_kind=DocumentKind.DOCX)
    if not edits:
        # A no-op edit still produces dst as a faithful copy of src.
        raw = container.read_part(src_path, C.DOCX_MAIN_PART)
        container.rewrite_parts(src_path, dst_path, {C.DOCX_MAIN_PART: raw})
        return
    raw = container.read_part(src_path, C.DOCX_MAIN_PART)
    new_xml = _rewrite_document_xml(raw, edits)
    container.rewrite_parts(src_path, dst_path, {C.DOCX_MAIN_PART: new_xml})


def create_from_template(
    template_path: str,
    dst_path: str,
    edits: dict[int, str] | None = None,
) -> None:
    """Create a new .docx from a local template, optionally substituting text.

    The template is a real .docx on disk (rejection-gated). Its every part is
    carried into the new file byte-for-byte; only the paragraphs named in
    *edits* are changed, through the same part-level editor
    (:func:`replace_paragraph_text`). This preserves the template's styles,
    theme and layout — a template create is a faithful copy plus targeted fills,
    never a fresh synthesis.
    """
    ensure_editable(template_path, expected_kind=DocumentKind.DOCX)
    replace_paragraph_text(template_path, dst_path, edits or {})
