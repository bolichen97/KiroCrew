"""W07 · office_cloud — cloud Office-content round-trip across SharePoint & OneDrive.

The cloud half of the Office capability set: it takes the offline OOXML engine
(B's ``office_documents.engine`` for docx/pptx, C's ``office_documents.xlsx``)
and drives a full CONTENT round-trip against a cloud drive —

    read the real file bytes  ->  parser create / targeted in-place edit
                              ->  the SUPPORTED conditional commit (If-Match/412)
                              ->  INDEPENDENT content read-back

— for ``docx`` / ``pptx`` / ``xlsx`` in BOTH SharePoint document libraries and
OneDrive. SharePoint and OneDrive file content are the same Graph ``driveItem``
content endpoints; only the drive locator differs (:class:`DriveLocator`), which
is why "both locations" is a horizontal-capability requirement, not an option.

Every network hop routes through W06's production Dispatch
(:func:`~kiro_crew.connections.vendors.microsoft.graph.concurrency.build_graph_write_dispatch`)
into W01's ``execute``; the body of every hop is read from ``outcome.payload``
(a content download as a
:class:`~kiro_crew.connections.control_plane.result.BytesPayload`, a metadata
read as an
:class:`~kiro_crew.connections.control_plane.result.ObjectPayload`), never from a
captured reply, ``outcome.metadata``, or a side store. This module builds NO
auth, vault or transport, and never touches a real cloud account.
"""

from __future__ import annotations

from .roundtrip import (
    CloudRoundtripError,
    DriveLocator,
    LocalEdit,
    OfficeFormat,
    RoundtripOutcome,
    content_bytes,
    docx_pptx_edit,
    refuse_excel_range_version_safe_write,
    run_content_roundtrip,
    xlsx_edit,
)

__all__ = [
    "OfficeFormat",
    "DriveLocator",
    "RoundtripOutcome",
    "LocalEdit",
    "CloudRoundtripError",
    "run_content_roundtrip",
    "docx_pptx_edit",
    "xlsx_edit",
    "content_bytes",
    "refuse_excel_range_version_safe_write",
]
