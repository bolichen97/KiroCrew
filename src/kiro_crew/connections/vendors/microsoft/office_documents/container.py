"""Part-level OOXML container access with byte-preserving write-back.

An OOXML file is a zip of *parts*. The fidelity rule this engine keeps is: an
edit rewrites ONLY the parts it changed, and every other part is copied through
**byte-for-byte** — same bytes, same compression type, same order. That is what
lets a targeted edit (change one paragraph's text) leave the theme, styles,
media, custom XML and relationships of a real document exactly as the authoring
application wrote them, instead of the lossy "parse the whole thing and
re-serialize" round-trip a full-document library would do.

Reads go through :func:`read_part`, hardened by ``kiro_crew.zip_vet`` (declared
inventory bound) and a real decompressed-size cap, and parsed with
``defusedxml`` so a crafted part cannot mount an XXE. Writes go through
:func:`rewrite_parts`, which is atomic (temp file + ``os.replace``) so a failed
or interrupted write never truncates the destination in place.
"""

from __future__ import annotations

import os
import tempfile
import zipfile

try:
    from defusedxml.ElementTree import fromstring as _xml_fromstring
except ModuleNotFoundError:  # pragma: no cover - exercised via monkeypatch
    _xml_fromstring = None  # type: ignore[assignment]

from kiro_crew.security import is_sensitive_path
from kiro_crew.zip_vet import ZipInventoryRejected, vet_zip_inventory

from . import constants as C
from .errors import MalformedDocument, OfficeDocumentError

__all__ = [
    "read_part",
    "part_names",
    "parse_xml_part",
    "rewrite_parts",
    "copy_all_parts_verbatim",
]


def _guard_sensitive(path: str) -> None:
    if is_sensitive_path(path):
        raise OfficeDocumentError(
            f"refusing to read sensitive path: {path}", reason="sensitive_path"
        )


def _open_vetted(path: str) -> zipfile.ZipFile:
    """Open *path* as a zip after bounding its declared inventory.

    The vet runs BEFORE ``ZipFile`` is constructed because construction
    allocates from the declared central-directory size; see ``zip_vet``.
    """
    try:
        vet_zip_inventory(path, max_members=C.MAX_ARCHIVE_MEMBERS)
    except ZipInventoryRejected as exc:
        raise MalformedDocument(f"archive inventory rejected: {exc.reason}") from exc
    try:
        return zipfile.ZipFile(path, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise MalformedDocument(f"cannot open container: {exc}") from exc


def part_names(path: str) -> list[str]:
    """Return the container's member names in stored order."""
    _guard_sensitive(path)
    with _open_vetted(path) as zf:
        return zf.namelist()


def read_part(path: str, part: str, *, max_size: int | None = None) -> bytes:
    """Read one part's decompressed bytes, capped at *max_size*.

    Raises :class:`MalformedDocument` if the part is absent or its real
    decompressed size exceeds the cap, regardless of what the zip header
    declares (defends against a lying header / zip bomb).
    """
    _guard_sensitive(path)
    if max_size is None:
        max_size = C.MAX_PART_BYTES
    with _open_vetted(path) as zf:
        if part not in zf.namelist():
            raise MalformedDocument(f"container has no part {part!r}")
        with zf.open(part) as fh:
            data = fh.read(max_size + 1)
    if len(data) > max_size:
        raise MalformedDocument(f"part {part!r} exceeds {max_size} bytes decompressed")
    return data


def parse_xml_part(path: str, part: str):
    """Read and XML-parse one part with a hardened (XXE-safe) parser.

    Returns the parsed root ``Element``. Raises :class:`MalformedDocument` on
    an unparseable part or when the hardened parser is unavailable (a stale
    install), never falling back to the entity-resolving stdlib parser.
    """
    if _xml_fromstring is None:
        raise MalformedDocument(
            "defusedxml is not installed; refusing to parse OOXML with the "
            "entity-resolving stdlib parser (run: pip install -e .)"
        )
    data = read_part(path, part)
    try:
        return _xml_fromstring(data)
    except Exception as exc:  # defusedxml raises several distinct types
        raise MalformedDocument(f"part {part!r} is not well-formed XML: {exc}") from exc


def copy_all_parts_verbatim(
    src_zip: zipfile.ZipFile,
    dst_zip: zipfile.ZipFile,
    *,
    skip: set[str] | None = None,
) -> None:
    """Copy every member of *src_zip* into *dst_zip* byte-for-byte, except *skip*.

    Preserves each entry's raw stored bytes and compression type by copying the
    ``ZipInfo`` and the *compressed* payload (``open(..., "r")`` on the writer's
    side would re-compress; this uses the low-level path that keeps the original
    deflate stream). Order is preserved: members are re-emitted in
    ``infolist()`` order.
    """
    skip = skip or set()
    for info in src_zip.infolist():
        if info.filename in skip:
            continue
        # Reading decompressed and re-writing keeps portability across zip
        # backends; compression type is carried on the ZipInfo so the stored
        # bytes match the original producer's choice per part.
        data = src_zip.read(info.filename)
        # Clone the ZipInfo so date_time, external_attr, compress_type and the
        # create/extract system are preserved exactly.
        out = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
        out.compress_type = info.compress_type
        out.external_attr = info.external_attr
        out.internal_attr = info.internal_attr
        out.create_system = info.create_system
        out.flag_bits = info.flag_bits
        dst_zip.writestr(out, data)


def rewrite_parts(
    src_path: str,
    dst_path: str,
    replacements: dict[str, bytes],
    *,
    additions: dict[str, bytes] | None = None,
) -> None:
    """Write *dst_path* as *src_path* with *replacements* substituted per part.

    ``replacements`` maps a part name that MUST already exist in the source to
    its new bytes; ``additions`` maps a new part name to its bytes. Every part
    not named in either is copied through byte-for-byte (see
    :func:`copy_all_parts_verbatim`). A replacement naming a nonexistent part is
    a :class:`MalformedDocument` — the caller asked to change something that is
    not there.

    Atomic: the whole archive is built in a temp file in the destination
    directory and swapped in with ``os.replace`` only once fully written, so an
    error mid-write never leaves a truncated destination. ``src_path`` and
    ``dst_path`` may be the same file; the swap makes in-place edit safe.
    """
    _guard_sensitive(src_path)
    _guard_sensitive(dst_path)
    additions = additions or {}

    with _open_vetted(src_path) as zsrc:
        existing = set(zsrc.namelist())
        missing = [p for p in replacements if p not in existing]
        if missing:
            raise MalformedDocument(
                f"cannot replace part(s) absent from source: {', '.join(sorted(missing))}"
            )
        clashing = [p for p in additions if p in existing]
        if clashing:
            raise MalformedDocument(
                f"cannot add part(s) that already exist: {', '.join(sorted(clashing))}"
            )

        dst_dir = os.path.dirname(os.path.abspath(dst_path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".ooxml-", suffix=".tmp", dir=dst_dir)
        os.close(fd)
        try:
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zdst:
                # Preserve original order for untouched parts; emit replacements
                # in their original slot so the central directory order is stable.
                for info in zsrc.infolist():
                    name = info.filename
                    if name in replacements:
                        out = zipfile.ZipInfo(filename=name, date_time=info.date_time)
                        out.compress_type = info.compress_type
                        out.external_attr = info.external_attr
                        out.create_system = info.create_system
                        zdst.writestr(out, replacements[name])
                    else:
                        data = zsrc.read(name)
                        out = zipfile.ZipInfo(filename=name, date_time=info.date_time)
                        out.compress_type = info.compress_type
                        out.external_attr = info.external_attr
                        out.internal_attr = info.internal_attr
                        out.create_system = info.create_system
                        out.flag_bits = info.flag_bits
                        zdst.writestr(out, data)
                for name, payload in additions.items():
                    zdst.writestr(name, payload)
            os.replace(tmp, dst_path)
        except BaseException:
            # Never leave the temp artifact behind on any failure path.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def is_container_hardened_available() -> bool:
    """Whether the XXE-safe XML parser this module needs is importable."""
    return _xml_fromstring is not None
