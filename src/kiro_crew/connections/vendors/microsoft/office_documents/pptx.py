"""Offline PresentationML (.pptx) read, template-create and in-place edit.

Pure standard library (``zipfile`` + hardened XML): ``python-pptx`` is
deliberately NOT a dependency of the gateway process, and adding it — or adding
``.pptx`` to the knowledge folder-scan ``SUPPORTED`` set — is an out-of-scope
behavior change (Dependency License Gate, bundle size, folder-scan semantics).
This module reads a deck by walking its slide parts, exactly matching how a pptx
is actually structured: there is no single presentation-body endpoint, each
slide is its own ``ppt/slides/slideN.xml`` part, and a slide's speaker notes
live in a separate ``ppt/notesSlides/notesSlideN.xml`` part reached through the
slide's relationships file.

Edits and template creation follow the docx module's discipline: rewrite only
the addressed slide part(s), copy every other part byte-for-byte.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import constants as C
from . import container
from .errors import DocumentEditError
from .rejection import DocumentKind, ensure_editable

__all__ = [
    "Slide",
    "PptxContent",
    "read_presentation",
    "create_from_template",
    "replace_slide_text",
]

_SLIDE_RE = re.compile(r"^ppt/slides/slide(\d+)\.xml$")
_NOTES_REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide"


@dataclass(frozen=True)
class Slide:
    """One slide: its number, body text runs, and speaker notes."""

    number: int
    text: str = ""
    notes: str = ""


@dataclass(frozen=True)
class PptxContent:
    """The structured read of a .pptx: slides in presentation order."""

    slides: list[Slide] = field(default_factory=list)

    @property
    def text(self) -> str:
        """All slide body text joined, one block per slide."""
        return "\n\n".join(s.text for s in self.slides if s.text)


def _slide_parts(names: list[str]) -> list[tuple[int, str]]:
    """Return ``(number, part_name)`` for each slide, sorted by slide number."""
    found: list[tuple[int, str]] = []
    for name in names:
        m = _SLIDE_RE.match(name)
        if m:
            found.append((int(m.group(1)), name))
    found.sort(key=lambda pair: pair[0])
    return found


def _text_of(root) -> str:
    """Concatenate DrawingML ``<a:t>`` runs, one line per run-bearing paragraph."""
    lines: list[str] = []
    for para in root.iter(f"{C.A}p"):
        runs = [t.text for t in para.iter(f"{C.A}t") if t.text]
        if runs:
            lines.append("".join(runs))
    return "\n".join(lines)


def _notes_part_for_slide(path: str, slide_part: str, names: set[str]) -> str | None:
    """Resolve a slide's notes part via its ``.rels``, or None if it has none.

    A slide ``ppt/slides/slideN.xml`` carries its relationships in
    ``ppt/slides/_rels/slideN.xml.rels``; the notes relationship's Target is
    resolved relative to ``ppt/slides/``.
    """
    m = _SLIDE_RE.match(slide_part)
    if not m:
        return None
    rels_part = f"ppt/slides/_rels/slide{m.group(1)}.xml.rels"
    if rels_part not in names:
        return None
    try:
        rels_root = container.parse_xml_part(path, rels_part)
    except Exception:
        return None
    for rel in rels_root:
        if rel.get("Type") == _NOTES_REL_TYPE:
            target = rel.get("Target", "")
            # Targets are relative to ppt/slides/; normalize ../notesSlides/...
            normalized = _normalize_rel_target("ppt/slides/", target)
            if normalized in names:
                return normalized
    return None


def _normalize_rel_target(base_dir: str, target: str) -> str:
    """Resolve a relationship Target against *base_dir* into a package part path."""
    segments = (base_dir.rstrip("/") + "/" + target).split("/")
    stack: list[str] = []
    for seg in segments:
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack:
                stack.pop()
            continue
        stack.append(seg)
    return "/".join(stack)


def read_presentation(path: str) -> PptxContent:
    """Read a .pptx into structured slides with body text and speaker notes.

    Rejection-gated. Pure stdlib: walks each ``ppt/slides/slideN.xml`` part in
    slide-number order and, per slide, resolves its notes part through the
    slide's ``.rels`` file. A slide with no notes carries ``notes == ""``.
    """
    ensure_editable(path, expected_kind=DocumentKind.PPTX)
    names = container.part_names(path)
    name_set = set(names)
    slides: list[Slide] = []
    for number, part in _slide_parts(names):
        root = container.parse_xml_part(path, part)
        body_text = _text_of(root)
        notes_text = ""
        notes_part = _notes_part_for_slide(path, part, name_set)
        if notes_part is not None:
            try:
                notes_root = container.parse_xml_part(path, notes_part)
                notes_text = _text_of(notes_root)
            except Exception:
                notes_text = ""
        slides.append(Slide(number=number, text=body_text, notes=notes_text))
    return PptxContent(slides=slides)


def _rewrite_slide_xml(raw: bytes, new_text: str) -> bytes:
    """Return a slide part's bytes with its FIRST text run set to *new_text*.

    Replaces the text of the first ``<a:t>`` run found (document order) and
    drops any additional runs within that same paragraph, leaving the shape,
    its properties and every other paragraph/shape untouched. Raises
    :class:`DocumentEditError` if the slide carries no text run to replace.
    """
    import xml.etree.ElementTree as ET

    ET.register_namespace("a", C.A_NS)
    ET.register_namespace("p", C.P_NS)
    ET.register_namespace("r", C.R_NS)

    from defusedxml.ElementTree import fromstring

    root = fromstring(raw)
    # Find the first paragraph that carries at least one run.
    for para in root.iter(f"{C.A}p"):
        runs = [r for r in para if r.tag == f"{C.A}r"]
        if not runs:
            continue
        first = runs[0]
        t = first.find(f"{C.A}t")
        if t is None:
            continue
        t.text = new_text
        # Remove trailing runs in this paragraph so the new text stands alone.
        for extra in runs[1:]:
            para.remove(extra)
        return ET.tostring(root, encoding="UTF-8", xml_declaration=True)
    raise DocumentEditError("slide has no text run to replace")


def replace_slide_text(
    src_path: str,
    dst_path: str,
    edits: dict[int, str],
) -> None:
    """Replace the first text run of specific slides, byte-preserving other parts.

    *edits* maps a one-based slide number to its new text. ``src_path`` and
    ``dst_path`` may be equal. Rejection-gated. Raises :class:`DocumentEditError`
    for an unknown slide number or a slide with no editable run, BEFORE writing.
    """
    ensure_editable(src_path, expected_kind=DocumentKind.PPTX)
    names = container.part_names(src_path)
    by_number = {num: part for num, part in _slide_parts(names)}

    if not edits:
        # No-op edit still produces a faithful copy.
        first_part = next(iter(by_number.values()), None)
        if first_part is None:
            raise DocumentEditError("presentation has no slides")
        raw = container.read_part(src_path, first_part)
        container.rewrite_parts(src_path, dst_path, {first_part: raw})
        return

    replacements: dict[str, bytes] = {}
    for number, new_text in edits.items():
        part = by_number.get(number)
        if part is None:
            raise DocumentEditError(f"slide {number} does not exist (have {sorted(by_number)})")
        raw = container.read_part(src_path, part)
        replacements[part] = _rewrite_slide_xml(raw, new_text)
    container.rewrite_parts(src_path, dst_path, replacements)


def create_from_template(
    template_path: str,
    dst_path: str,
    edits: dict[int, str] | None = None,
) -> None:
    """Create a new .pptx from a local template, optionally substituting text.

    Faithful copy of the template's every part plus targeted per-slide text
    fills through :func:`replace_slide_text`; never a fresh synthesis.
    """
    ensure_editable(template_path, expected_kind=DocumentKind.PPTX)
    replace_slide_text(template_path, dst_path, edits or {})
