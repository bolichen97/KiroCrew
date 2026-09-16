"""The protected / unsupported-format rejection gate.

Every read, template-create and edit entry point runs a file through
:func:`classify` first, and refuses anything that is not a plain, unlocked
OOXML container this engine can safely handle. This is the campaign's one
``required=True`` Office operation: a document engine that silently mangled a
password-protected, macro-enabled, signed, IRM-protected or legacy-binary file
would produce output that opens broken, so the contract is **explicit refusal,
never silent corruption**.

Detection is by PRESENCE only, and deliberately so for signatures: whether a
signature is cryptographically *valid* is a different question this engine does
not answer. Academic work has shown structural signature presence and
cryptographic validity genuinely diverge, so conflating them would let this
engine make a claim it cannot back. It reports that a signature part EXISTS and
refuses to edit past it; it never asserts the signature verifies.
"""

from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass
from pathlib import Path

from kiro_crew.zip_vet import ZipInventoryRejected, vet_zip_inventory

from . import constants as C
from .errors import MalformedDocument, ProtectedDocument, UnsupportedDocument

__all__ = ["DocumentKind", "Classification", "classify", "ensure_editable"]


class DocumentKind:
    """The container kind :func:`classify` resolved."""

    DOCX = "docx"
    PPTX = "pptx"


@dataclass(frozen=True)
class Classification:
    """The verdict of the rejection gate for one file.

    ``kind`` is the resolved :class:`DocumentKind` when ``ok`` is true. When
    ``ok`` is false, ``reason`` and ``detail`` say why, matching the error the
    strict entry points raise via :func:`ensure_editable`.
    """

    ok: bool
    kind: str | None = None
    reason: str | None = None
    detail: str = ""


def _magic(path: str, n: int = 8) -> bytes:
    """Read the first *n* bytes of *path*, or ``b""`` if it cannot be read."""
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _reject(reason: str, detail: str) -> Classification:
    return Classification(ok=False, reason=reason, detail=detail)


def classify(path: str) -> Classification:
    """Classify *path* as a handleable OOXML document or a refusal.

    Never raises for a document reason: it returns a :class:`Classification`.
    (It can still propagate nothing — an unreadable path becomes a
    ``malformed_document`` verdict rather than an ``OSError``.) The strict
    wrapper :func:`ensure_editable` turns a non-ok verdict into the matching
    typed exception.

    Order matters: the cheapest, most decisive signals run first. Legacy binary
    and encrypted-OOXML files are not zips at all, so they are caught by magic
    bytes before any zip parse; the inventory vet then bounds a real zip before
    it is opened; only then are the in-archive lock markers inspected.
    """
    ext = Path(path).suffix.lower()
    head = _magic(path)

    # 1. Legacy OLE2 binaries and encrypted-OOXML wrappers share the CFB magic.
    #    Neither is a zip; refuse before any zip machinery sees them.
    if head.startswith(C.OLE2_MAGIC):
        if ext in C.LEGACY_BINARY_EXTS:
            return _reject(
                UnsupportedDocument.reason,
                f"legacy OLE2 binary format ({ext or 'no extension'}); "
                "only Office Open XML (.docx/.pptx) is supported",
            )
        # A CFB that is not a recognised legacy extension is the
        # password/agile-encrypted OOXML wrapper (its stream is EncryptedPackage).
        return _reject(
            ProtectedDocument.reason,
            "compound-file (OLE2) container: password/agile-encrypted OOXML "
            "or a legacy binary; the plain OOXML parts are not readable",
        )

    # 2. Macro-enabled or legacy extension with no matching magic — still refuse
    #    on the extension alone, because .docm/.pptm carry macro intent.
    if ext in C.MACRO_ENABLED_EXTS:
        return _reject(
            ProtectedDocument.reason,
            f"macro-enabled document ({ext}); refusing to edit a file that "
            "may carry a VBA project",
        )
    if ext in C.LEGACY_BINARY_EXTS:
        return _reject(
            UnsupportedDocument.reason,
            f"legacy binary extension ({ext}); only .docx/.pptx are supported",
        )

    # 3. Must be a real zip. An empty-archive EOCD or non-PK head is malformed.
    if not head.startswith(C.ZIP_MAGIC):
        if head.startswith(C.ZIP_EMPTY_MAGIC):
            return _reject(MalformedDocument.reason, "empty archive: no OOXML parts")
        return _reject(
            MalformedDocument.reason,
            "not an Office Open XML container (no zip local-file header)",
        )

    # 4. Bound the declared inventory before opening (zip-bomb / crafted CD).
    try:
        vet_zip_inventory(path, max_members=C.MAX_ARCHIVE_MEMBERS)
    except ZipInventoryRejected as exc:
        return _reject(MalformedDocument.reason, f"archive inventory rejected: {exc.reason}")

    # 5. Inspect the member list for lock markers and to resolve the kind.
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError) as exc:
        return _reject(MalformedDocument.reason, f"cannot read archive: {exc}")

    # Encrypted package stream can also appear as a zip member name in some
    # producers; treat its presence as protection.
    if any(n.endswith("EncryptedPackage") for n in names):
        return _reject(ProtectedDocument.reason, "package contains an EncryptedPackage stream")
    # Digital signature parts: presence only, validity never asserted.
    if any(n.startswith(C.SIGNATURE_PART_PREFIX) for n in names):
        return _reject(
            ProtectedDocument.reason,
            "package carries a digital signature part; editing would invalidate "
            "it (signature presence only — validity is intentionally not checked)",
        )
    # Macro project part regardless of extension.
    if any(n.endswith(C.VBA_PROJECT_SUFFIX) for n in names):
        return _reject(
            ProtectedDocument.reason,
            "package contains a vbaProject.bin macro project",
        )
    # IRM / rights-management leaves a DataSpaces protection part.
    if any(C.DRM_ENCRYPTED_PART_SUFFIX in n for n in names):
        return _reject(
            ProtectedDocument.reason,
            "package carries an IRM/rights-management protection layer",
        )

    # 6. Resolve the kind from the mandatory main part.
    if C.DOCX_MAIN_PART in names:
        return Classification(ok=True, kind=DocumentKind.DOCX)
    if C.PPTX_PRESENTATION_PART in names:
        return Classification(ok=True, kind=DocumentKind.PPTX)

    return _reject(
        MalformedDocument.reason,
        "zip container with neither word/document.xml nor ppt/presentation.xml; "
        "not a docx or pptx",
    )


def ensure_editable(path: str, *, expected_kind: str | None = None) -> str:
    """Classify *path* and raise the matching typed error unless it is handleable.

    Returns the resolved :class:`DocumentKind` on success. ``expected_kind``, when
    given, additionally rejects a valid-but-wrong-kind file (a pptx handed to a
    docx entry point) as :class:`UnsupportedDocument`.
    """
    if not os.path.exists(path):
        raise MalformedDocument(f"no such file: {path}")
    verdict = classify(path)
    if not verdict.ok:
        if verdict.reason == ProtectedDocument.reason:
            raise ProtectedDocument(verdict.detail)
        if verdict.reason == UnsupportedDocument.reason:
            raise UnsupportedDocument(verdict.detail)
        raise MalformedDocument(verdict.detail)
    if expected_kind is not None and verdict.kind != expected_kind:
        raise UnsupportedDocument(
            f"expected a {expected_kind} document but the file is a {verdict.kind}"
        )
    return verdict.kind  # type: ignore[return-value]
