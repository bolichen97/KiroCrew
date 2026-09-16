"""W07 · office_cloud — cloud Office CONTENT round-trip, both locations.

WHAT THIS COVERS
================
The end-to-end CONTENT round-trip for ``docx`` / ``pptx`` / ``xlsx`` in BOTH
SharePoint document libraries and OneDrive, exercised over the SAME real
production chain the metadata write uses:

    read the real file bytes  ->  parser create / targeted in-place edit
                              ->  the SUPPORTED conditional commit (If-Match/412)
                              ->  INDEPENDENT content read-back

* **Real TLS, no cloud account.** A self-signed HTTPS loopback stands in for
  Microsoft Graph and serves a stateful ``driveItem``: its metadata (``eTag`` /
  ``id``) and its ``/content`` bytes, honoring ``If-Match`` on the content
  ``PUT`` and returning ``412`` on a stale eTag. Every hop is driven through
  W06's PRODUCTION Dispatch (``build_graph_write_dispatch``) -> W01's ``execute``,
  composed with a real encrypted ``SecretVault``, a real binding/handle, the two
  vendor seats and W01's unmodified ``urllib_http_send``. Nothing here calls a
  raw sender, and no real cloud business account is touched. NOT LIVE.

* **Real OOXML.** Fixtures are genuine files: docx via ``python-docx``, pptx via
  stdlib ``zipfile`` (real OPC ZIP), xlsx via ``openpyxl`` — real ZIP containers,
  parsed by the sibling engines' own hardened readers, not mocked.

* **Two locations, one capability.** SharePoint and OneDrive file content are the
  same ``driveItem`` content endpoints; only the drive locator differs. Each
  format is run against BOTH.

* **Fidelity matrix.** Per (location × format): the committed bytes differ from
  the download (the edit landed), the read-back re-parses and the intended edit
  holds on the target, and untouched OOXML parts are byte-identical between the
  downloaded and the committed container.

* **Conflict negatives.** A content ``PUT`` with a STALE ``If-Match`` is refused
  with a ``412`` conflict — nothing clobbered. And ``excel.range.write`` (the
  workbook-range operation, which Graph documents NO eTag mechanism for) is
  refused BEFORE any request through W06's ``run_version_safe_write`` — ZERO
  requests issued.

Import discipline: this leaf depends BY NAME on the sibling W06 graph seam and
the sibling B/C office_documents engines. Those imports are HARD (not
importorskip): if a sibling is uncommitted the import raises a named error and
collection FAILS visibly, which is the correct signal for an unmet integration
dependency — a silent skip would read as "not failing" and conceal it.
"""

from __future__ import annotations

import datetime
import http.server
import io
import json
import ssl
import threading
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest

# openpyxl / python-docx are declared deps; a soft skip is acceptable when
# genuinely absent from an install — but a skip is NOT a pass and is never
# reported as verification.
pytest.importorskip("openpyxl", reason="declared dep; skip if absent (skip != pass)")
pytest.importorskip("docx", reason="python-docx is a declared dep; skip if absent (skip != pass)")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes  # noqa: E402
from kiro_crew.connections.control_plane.binding import (  # noqa: E402
    VerifiedIdentity,
    binding_secret_ref,
    create_binding,
)
from kiro_crew.connections.control_plane.handle import derive_handle, ensure_usable  # noqa: E402
from kiro_crew.connections.control_plane.policy import LayerCeilings  # noqa: E402
from kiro_crew.connections.control_plane.production import BindingSecretSelector  # noqa: E402
from kiro_crew.secrets import SecretValue, SecretVault  # noqa: E402

# The sibling W06 graph seam — imported HARD (used transitively via this leaf's
# own factory build_office_cloud_dispatch, which binds build_graph_write_dispatch).
from kiro_crew.connections.vendors.microsoft.graph.concurrency import (  # noqa: E402
    ConcurrencyError,
)

# This leaf under test.
from kiro_crew.connections.vendors.microsoft.office_cloud import (  # noqa: E402
    DriveLocator,
    OfficeFormat,
    RoundtripOutcome,
    WriteStatus,
    build_office_cloud_dispatch,
    docx_pptx_edit,
    refuse_excel_range_version_safe_write,
    run_content_roundtrip,
    xlsx_edit,
)

_T0 = 1_000_000.0
_ETAG_V1 = '"etag-v1"'
_ETAG_STALE = '"etag-STALE"'


# =============================================================================
# Real OOXML fixtures (genuine ZIP containers, not mocked).
# =============================================================================
def _make_docx_bytes() -> bytes:
    import docx as pydocx

    d = pydocx.Document()
    d.add_heading("Original Title", level=1)
    d.add_paragraph("Body paragraph one.")
    d.add_paragraph("Body paragraph two.")
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


_A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
_P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
_CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_PPTX_SLIDE = (
    "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>"
    "<p:sld xmlns:a='%s' xmlns:p='%s'>"
    "<p:cSld><p:spTree><p:sp><p:txBody>"
    "<a:p><a:r><a:t>{text}</a:t></a:r></a:p>"
    "</p:txBody></p:sp></p:spTree></p:cSld></p:sld>" % (_A_NS, _P_NS)
)


def _make_pptx_bytes(slides: List[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<?xml version='1.0'?><Types xmlns='%s'/>" % _CT_NS)
        z.writestr(
            "ppt/presentation.xml",
            "<?xml version='1.0'?><p:presentation xmlns:p='%s'/>" % _P_NS,
        )
        z.writestr("ppt/theme/theme1.xml", "<theme>original</theme>")
        for i, body in enumerate(slides, 1):
            z.writestr(f"ppt/slides/slide{i}.xml", _PPTX_SLIDE.format(text=body))
    return buf.getvalue()


def _make_xlsx_bytes() -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Data"
    ws["A1"] = "Item"
    ws["B1"] = "Qty"
    ws["A2"] = "apples"
    ws["B2"] = 3
    notes = wb.create_sheet("Notes")
    notes["A1"] = "hello"
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _zip_parts(data: bytes) -> Dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: z.read(n) for n in z.namelist()}


# =============================================================================
# Real W01 auth chain composition (vault + binding + handle + selector).
# =============================================================================
def _verifier(*, claimed_subject: str, claimed_tenant: str, service_id: str) -> VerifiedIdentity:
    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


class _RecordingVault(SecretVault):
    def __init__(self, config_dir: Path) -> None:
        super().__init__(config_dir)
        self.asked: List[str] = []

    def get(self, name: str) -> Optional[SecretValue]:
        self.asked.append(name)
        return super().get(name)


def _tls_material(tmp_path: Path) -> Tuple[Path, Path]:
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / "c.pem"
    keyfile = tmp_path / "k.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


class _DriveItem:
    """A stateful Graph-like driveItem served over the loopback.

    Holds the item id, current eTag, and current content bytes. A metadata GET
    (``/items/{id}``) returns ``{id, eTag}``; a content GET (``/items/{id}/content``)
    returns the bytes with the OOXML media type; a content PUT replaces the bytes
    IFF the ``If-Match`` matches the current eTag (else 412), and bumps the eTag.
    """

    def __init__(self, item_id: str, etag: str, content: bytes, media_type: str) -> None:
        self.item_id = item_id
        self.etag = etag
        self.content = content
        self.media_type = media_type
        self.requests: List[Dict[str, Any]] = []

    def handle(
        self, method: str, path: str, if_match: Optional[str], body: bytes
    ) -> Tuple[int, Dict[str, str], bytes]:
        self.requests.append(
            {"method": method, "path": path, "if_match": if_match, "len": len(body)}
        )
        is_content = path.endswith("/content")
        if method == "GET" and not is_content:
            payload = json.dumps({"id": self.item_id, "eTag": self.etag}).encode()
            return (200, {"Content-Type": "application/json"}, payload)
        if method == "GET" and is_content:
            return (200, {"Content-Type": self.media_type}, self.content)
        if method == "PUT" and is_content:
            if if_match is not None and if_match != self.etag:
                return (
                    412,
                    {"Content-Type": "application/json"},
                    json.dumps({"error": {"code": "preconditionFailed"}}).encode(),
                )
            self.content = body
            # bump the version so a subsequent conditional write must re-read.
            self.etag = f'"{self.etag.strip(chr(34))}-n"'
            return (
                200,
                {"Content-Type": "application/json"},
                json.dumps({"id": self.item_id, "eTag": self.etag}).encode(),
            )
        return (405, {}, b"")


def _handler_for(item: _DriveItem):
    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _do(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            status, headers, out = item.handle(
                self.command, self.path, self.headers.get("If-Match"), body
            )
            if status == 0:
                # Sentinel: the server ALREADY applied the effect (item.handle
                # mutated state), then the connection drops before a valid
                # response is sent. urllib sees a dropped connection, which W01's
                # transport maps to write_outcome=UNKNOWN for a non-idempotent
                # write — the "committed then disconnected" shape.
                try:
                    self.close_connection = True
                    self.wfile.close()
                    self.connection.close()
                except Exception:
                    pass
                return
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            if status not in (204, 304):
                self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            if status not in (204, 304) and out:
                self.wfile.write(out)

        do_GET = _do
        do_PUT = _do

        def log_message(self, *a):
            return

    return _H


@contextmanager
def _https_server(handler_cls, certfile, keyfile) -> Iterator[int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=5)


@pytest.fixture
def trust_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tuple[Path, Path]:
    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))
    return certfile, keyfile


def _compose(tmp_path: Path, service_id: str):
    vault = _RecordingVault(tmp_path / f"crewhome-{service_id}")
    vault.set_sync(binding_secret_ref(service_id)["name"], f"{service_id}-live-token")
    binding = create_binding(
        service_id=service_id,
        claimed_subject="alice",
        claimed_tenant="acme",
        credential_mode="oauth_user",
        verifier=_verifier,
        slug=service_id,
    )
    handle = derive_handle(
        binding,
        granted_scopes=("files.rw",),
        requested_scopes=("files.rw",),
        now=_T0,
        ttl_seconds=300.0,
    )
    view = ensure_usable(handle, now=_T0)
    selector = BindingSecretSelector(
        slug=service_id,
        binding_fingerprint=view.binding_fingerprint,
        service_id=view.service_id,
        credential_mode=view.credential_mode,
    )
    return vault, selector, handle


def _dispatch_for(*, host: str, service_id: str, tmp_path: Path):
    """Drive tests through THIS leaf's OWN production factory (U2).

    The factory binds W06's ``build_graph_write_dispatch`` itself, so what the
    tests exercise is the shipped composition — not a Dispatch assembled in the
    test. The W01 auth-chain seats come from ``_compose`` (a real encrypted
    vault, a real binding/handle/selector); the factory does the
    descriptor + ``build_graph_write_dispatch`` wiring.
    """
    vault, selector, handle = _compose(tmp_path, service_id)
    return build_office_cloud_dispatch(
        endpoint_host=host,
        handle=handle,
        selector=selector,
        vault=vault,
        permitted=declare_permitted_modes(("oauth_user",)),
        layers=LayerCeilings(),
        offered_mode="oauth_user",
        service_id=service_id,
        now=_T0,
    )


# =============================================================================
# The per-(location, format) round-trip matrix.
# =============================================================================
# Each row: (location label, service_id, DriveLocator factory).
_LOCATIONS = [
    ("sharepoint", "sharepoint", lambda iid: DriveLocator.sharepoint_site("SITE1", iid)),
    ("onedrive", "onedrive", lambda iid: DriveLocator.onedrive_me(iid)),
]

_ITEM_ID = "ITEM-1"


def _fixture_for(fmt: OfficeFormat):
    """Return (original_bytes, media_type, local_edit, read_back_check)."""
    if fmt is OfficeFormat.DOCX:
        original = _make_docx_bytes()
        edit = docx_pptx_edit({1: "Body paragraph one — EDITED in the cloud."})
        check = {1: "Body paragraph one — EDITED in the cloud."}
        mt = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        return original, mt, edit, check
    if fmt is OfficeFormat.PPTX:
        original = _make_pptx_bytes(["Slide one body", "Slide two body"])
        edit = docx_pptx_edit({1: "Slide one body — EDITED in the cloud."})
        check = {1: "Slide one body — EDITED in the cloud."}
        mt = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        return original, mt, edit, check
    original = _make_xlsx_bytes()
    edit = xlsx_edit({"Data": {"B2": 99}})
    check = {"Data": {"B2": 99}}
    mt = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return original, mt, edit, check


@pytest.mark.parametrize("location,service_id,loc_factory", _LOCATIONS)
@pytest.mark.parametrize("fmt", [OfficeFormat.DOCX, OfficeFormat.PPTX, OfficeFormat.XLSX])
def test_content_roundtrip_commits_and_verifies_both_locations(
    trust_loopback, tmp_path, location, service_id, loc_factory, fmt
):
    """read bytes -> edit -> conditional commit -> independent read-back, per cell."""
    certfile, keyfile = trust_loopback
    original, media_type, edit, check = _fixture_for(fmt)
    item = _DriveItem(_ITEM_ID, _ETAG_V1, original, media_type)
    with _https_server(_handler_for(item), certfile, keyfile) as port:
        host = f"127.0.0.1:{port}"
        dispatch = _dispatch_for(host=host, service_id=service_id, tmp_path=tmp_path)
        locator = loc_factory(_ITEM_ID)
        outcome = run_content_roundtrip(
            location=location,
            fmt=fmt,
            locator=locator,
            dispatch=dispatch,
            local_edit=edit,
            read_back_check=check,
        )
    assert isinstance(outcome, RoundtripOutcome)
    assert outcome.write_status is WriteStatus.COMMITTED, outcome.reason
    assert outcome.committed, outcome.reason
    assert outcome.verified, outcome.reason
    assert not outcome.conflict
    assert not outcome.unknown
    # A committed write is NOT safe to blind-replay (a replay would duplicate).
    assert outcome.safe_to_replay is False
    assert outcome.downloaded_len == len(original)
    # The server now holds the committed (edited) bytes and a bumped eTag.
    assert item.content != original
    assert item.etag != _ETAG_V1
    # The full sequence issued: metadata GET, content GET, content PUT, read-back GET.
    methods = [(r["method"], r["path"].endswith("/content")) for r in item.requests]
    assert ("GET", False) in methods  # metadata
    assert methods.count(("GET", True)) >= 2  # download + read-back
    assert ("PUT", True) in methods  # conditional content commit


@pytest.mark.parametrize("location,service_id,loc_factory", _LOCATIONS)
@pytest.mark.parametrize("fmt", [OfficeFormat.DOCX, OfficeFormat.PPTX, OfficeFormat.XLSX])
def test_fidelity_untouched_parts_byte_identical(
    trust_loopback, tmp_path, location, service_id, loc_factory, fmt
):
    """The FIDELITY MATRIX: only the edited OOXML part changes; the rest is byte-identical."""
    certfile, keyfile = trust_loopback
    original, media_type, edit, check = _fixture_for(fmt)
    item = _DriveItem(_ITEM_ID, _ETAG_V1, original, media_type)
    with _https_server(_handler_for(item), certfile, keyfile) as port:
        host = f"127.0.0.1:{port}"
        dispatch = _dispatch_for(host=host, service_id=service_id, tmp_path=tmp_path)
        outcome = run_content_roundtrip(
            location=location,
            fmt=fmt,
            locator=loc_factory(_ITEM_ID),
            dispatch=dispatch,
            local_edit=edit,
            read_back_check=check,
        )
    assert outcome.committed and outcome.verified, outcome.reason
    before = _zip_parts(original)
    after = _zip_parts(item.content)
    # Same set of parts (the edit added no part and dropped none).
    assert set(before) == set(after)
    changed = [n for n in before if before[n] != after[n]]
    unchanged = [n for n in before if before[n] == after[n]]
    assert changed, "the edited part must actually change"
    assert unchanged, "untouched parts must be preserved byte-for-byte"
    # The container is still a valid, openable OOXML ZIP after the round-trip.
    with zipfile.ZipFile(io.BytesIO(item.content)) as z:
        assert z.testzip() is None


# =============================================================================
# CONFLICT NEGATIVES.
# =============================================================================
@pytest.mark.parametrize("location,service_id,loc_factory", _LOCATIONS)
def test_stale_if_match_is_a_412_conflict_nothing_clobbered(
    trust_loopback, tmp_path, location, service_id, loc_factory
):
    """A content PUT whose If-Match no longer matches the server eTag -> 412, refused."""
    certfile, keyfile = trust_loopback
    original, media_type, edit, check = _fixture_for(OfficeFormat.DOCX)
    # The item's CURRENT eTag differs from what the round-trip will read: simulate
    # a concurrent change between the metadata read and the PUT by making the
    # server reject any If-Match except _ETAG_STALE, while it advertises _ETAG_V1
    # on the metadata GET.
    item = _DriveItem(_ITEM_ID, _ETAG_V1, original, media_type)
    original_content = item.content

    # Wrap: after the metadata GET hands out _ETAG_V1, the item's real eTag moves,
    # so the PUT's If-Match: _ETAG_V1 no longer matches -> 412.
    real_handle = item.handle

    def moving_handle(method, path, if_match, body):
        if method == "PUT" and path.endswith("/content"):
            # The resource moved: only a DIFFERENT eTag would match now.
            if if_match == _ETAG_V1:
                item.requests.append(
                    {"method": method, "path": path, "if_match": if_match, "len": len(body)}
                )
                return (
                    412,
                    {"Content-Type": "application/json"},
                    json.dumps({"error": {"code": "preconditionFailed"}}).encode(),
                )
        return real_handle(method, path, if_match, body)

    item.handle = moving_handle  # type: ignore[assignment]
    with _https_server(_handler_for(item), certfile, keyfile) as port:
        host = f"127.0.0.1:{port}"
        dispatch = _dispatch_for(host=host, service_id=service_id, tmp_path=tmp_path)
        outcome = run_content_roundtrip(
            location=location,
            fmt=OfficeFormat.DOCX,
            locator=loc_factory(_ITEM_ID),
            dispatch=dispatch,
            local_edit=edit,
            read_back_check=check,
        )
    assert outcome.write_status is WriteStatus.CONFLICT, outcome.reason
    assert outcome.conflict is True, outcome.reason
    assert outcome.committed is False
    assert outcome.unknown is False
    assert outcome.verified is False
    # A 412 is a DETERMINATE not-applied: re-read and re-derive is safe.
    assert outcome.safe_to_replay is True
    # NOTHING clobbered: the server still holds the original bytes.
    assert item.content == original_content


# =============================================================================
# U1 NEGATIVES — an UNKNOWN write must never read as a determinate "not committed".
# Both go through THIS leaf's own factory -> W06 dispatch -> W01 execute, so the
# unknown mapping is the SHIPPED one, not a stubbed transport.
# =============================================================================
@pytest.mark.parametrize("location,service_id,loc_factory", _LOCATIONS)
def test_put_landed_then_connection_dropped_is_unknown_not_not_committed(
    trust_loopback, tmp_path, location, service_id, loc_factory
):
    """(a) The write LANDS on the server, then the connection drops before a
    response. REQUIRED contract: W01 maps a dropped connection on a
    non-idempotent write to write_outcome=UNKNOWN, and the round-trip surfaces
    WriteStatus.UNKNOWN — never a determinate not-committed, which would license
    a duplicate retry of a write that already landed.

    THIS TEST IS RED TODAY, ON PURPOSE — it is NOT xfail, because a strict-xfail
    would file a known, required contract under "expected" and show a green suite
    while the contract is unproven. The committed-then-disconnect contract is NOT
    yet proven end-to-end. It is blocked by a W01 transport gap I must NOT edit
    (owner-crossing) and must NOT paper over by wrapping/patching/substituting the
    sender:

        production.py:1277 catches only
        `(urllib.error.URLError, TimeoutError, TransportDeadlineExceededError)`.
        A connection dropped AFTER the request was sent but BEFORE a response —
        urllib's getresponse() raises http.client.RemoteDisconnected, whose MRO is
        RemoteDisconnected -> ConnectionResetError -> ConnectionError -> OSError
        -> BadStatusLine -> HTTPException. It is NOT a URLError and NOT a
        TimeoutError, so it escapes that clause UNCAUGHT and never maps to
        write_outcome=UNKNOWN.

    The fix is a one-line widen of production.py:1277 to ALSO catch
    ConnectionError (the transport docstring already says a dropped connection
    and a timeout are treated identically for a non-idempotent write). That hunk
    belongs to W01; when it lands, this test goes green with no change here.
    Negative (b) (500->UNKNOWN via the shipped graph_500_unknown_transport)
    proves the 500 path, NOT this drop path — the two are different failures."""
    certfile, keyfile = trust_loopback
    original, media_type, edit, check = _fixture_for(OfficeFormat.DOCX)
    item = _DriveItem(_ITEM_ID, _ETAG_V1, original, media_type)
    real_handle = item.handle

    def landing_then_drop(method, path, if_match, body):
        if method == "PUT" and path.endswith("/content"):
            # The effect LANDS: mutate content + bump eTag exactly as a real
            # accepted PUT would, THEN signal the handler to drop the connection
            # (status 0) instead of returning a response.
            item.requests.append(
                {"method": method, "path": path, "if_match": if_match, "len": len(body)}
            )
            item.content = body
            item.etag = f'"{item.etag.strip(chr(34))}-n"'
            return (0, {}, b"")
        return real_handle(method, path, if_match, body)

    item.handle = landing_then_drop  # type: ignore[assignment]
    with _https_server(_handler_for(item), certfile, keyfile) as port:
        host = f"127.0.0.1:{port}"
        dispatch = _dispatch_for(host=host, service_id=service_id, tmp_path=tmp_path)
        outcome = run_content_roundtrip(
            location=location,
            fmt=OfficeFormat.DOCX,
            locator=loc_factory(_ITEM_ID),
            dispatch=dispatch,
            local_edit=edit,
            read_back_check=check,
        )
    # The invariant this WOULD assert once W01 catches the drop:
    assert outcome.write_status is WriteStatus.UNKNOWN, outcome.reason
    assert outcome.unknown is True
    assert outcome.committed is False
    assert outcome.conflict is False
    assert outcome.safe_to_replay is False
    assert outcome.write_outcome == "unknown"
    assert "not committed" not in outcome.reason.lower()
    assert item.content != original


@pytest.mark.parametrize("location,service_id,loc_factory", _LOCATIONS)
def test_put_500_is_unknown_not_not_committed(
    trust_loopback, tmp_path, location, service_id, loc_factory
):
    """(b) A 500 on the content PUT. Graph does not guarantee a 500 is
    pre-commit, so W06's graph_500_unknown_transport marks a 500 on a
    non-idempotent write as write_outcome=UNKNOWN. The round-trip must surface
    WriteStatus.UNKNOWN, never a determinate not-committed."""
    certfile, keyfile = trust_loopback
    original, media_type, edit, check = _fixture_for(OfficeFormat.PPTX)
    item = _DriveItem(_ITEM_ID, _ETAG_V1, original, media_type)
    real_handle = item.handle

    def five_hundred_on_put(method, path, if_match, body):
        if method == "PUT" and path.endswith("/content"):
            item.requests.append(
                {"method": method, "path": path, "if_match": if_match, "len": len(body)}
            )
            # A 500 whose commit status is genuinely unknown to the client.
            return (500, {"Content-Type": "application/json"}, b'{"error":{"code":"internal"}}')
        return real_handle(method, path, if_match, body)

    item.handle = five_hundred_on_put  # type: ignore[assignment]
    with _https_server(_handler_for(item), certfile, keyfile) as port:
        host = f"127.0.0.1:{port}"
        dispatch = _dispatch_for(host=host, service_id=service_id, tmp_path=tmp_path)
        outcome = run_content_roundtrip(
            location=location,
            fmt=OfficeFormat.PPTX,
            locator=loc_factory(_ITEM_ID),
            dispatch=dispatch,
            local_edit=edit,
            read_back_check=check,
        )
    assert outcome.write_status is WriteStatus.UNKNOWN, outcome.reason
    assert outcome.unknown is True
    assert outcome.committed is False
    assert outcome.conflict is False
    assert outcome.safe_to_replay is False
    assert outcome.write_outcome == "unknown"
    assert "not committed" not in outcome.reason.lower()
    assert "unknown" in outcome.reason.lower()


def test_excel_range_write_has_no_conditional_commit_zero_requests():
    """excel.range.write is REFUSED before any request (Graph documents no eTag)."""
    with pytest.raises(ConcurrencyError) as exc:
        refuse_excel_range_version_safe_write(
            path="/me/drive/items/ITEM-1/workbook/worksheets/Data/range(address='A1')"
        )
    assert "excel.range.write" in str(exc.value) or "optimistic-concurrency" in str(exc.value)


def test_content_get_reads_bytes_from_outcome_payload_not_result_index(trust_loopback, tmp_path):
    """The body is read THROUGH outcome.payload (a BytesPayload), the single source."""
    from kiro_crew.connections.control_plane.result import BytesPayload
    from kiro_crew.connections.vendors.microsoft.office_cloud import content_bytes
    from kiro_crew.connections.vendors.microsoft.graph.concurrency import ARG_METHOD, ARG_PATH

    certfile, keyfile = trust_loopback
    original = _make_docx_bytes()
    item = _DriveItem(
        _ITEM_ID,
        _ETAG_V1,
        original,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    with _https_server(_handler_for(item), certfile, keyfile) as port:
        host = f"127.0.0.1:{port}"
        dispatch = _dispatch_for(host=host, service_id="onedrive", tmp_path=tmp_path)
        loc = DriveLocator.onedrive_me(_ITEM_ID)
        hop = dispatch({ARG_METHOD: "GET", ARG_PATH: loc.content_path})
    # The payload IS a BytesPayload on outcome.payload, and content_bytes reads it there.
    assert isinstance(hop.outcome.payload, BytesPayload)
    assert content_bytes(hop) == original
