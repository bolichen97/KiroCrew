"""W01 · L09: all three payload shapes over a REAL TLS wire, then READ BACK.

Why this file exists as well as ``test_connections_control_plane_data_channel.py``:
that suite injects the sender (``http_send=sender``). An injected callable is the
right unit-lane seam, but it cannot be the EVIDENCE that a payload travels a real
sender -- it *is* the fake standing in for one. Everything between
:func:`~kiro_crew.connections.control_plane.production.urllib_http_send` and the
socket (the opener it builds, the guarded redirect handler, the capped chunked
read, ``http.client``'s header folding, TLS itself) is skipped by construction, so
"the bytes arrived" proved only that a Python function returned what a test told
it to.

So every test here is the real path, with nothing standing in:

* the REAL sender -- :func:`urllib_http_send`, imported and passed UNMODIFIED, no
  wrapper, no monkeypatch;
* a REAL TLS server -- :class:`http.server.ThreadingHTTPServer` wrapped in an
  :class:`ssl.SSLContext` with a self-signed cert minted per test by
  ``cryptography``, trusted through ``SSL_CERT_FILE`` with certificate AND
  hostname verification LEFT ON (``test_verification_is_really_on`` proves the
  trust file is load-bearing by removing it and watching the send fail);
* the REAL production factory -- :func:`build_production_transport`;
* a REAL on-disk AES-256-GCM :class:`kiro_crew.secrets.SecretVault`;
* a FRESH-INSTALL posture -- the process runs from a cwd OUTSIDE the source tree
  and imports the package off an absolute ``PYTHONPATH`` entry, so nothing here
  can be working only because it was launched from a dev checkout. The in-process
  tests assert that posture; ``test_a_fresh_interpreter_outside_the_source_tree...``
  proves it the hard way, in a child interpreter that imports the package for the
  first time with ``cwd`` set to a temp dir.

**READBACK.** Each shape asserts twice: once on what the consumer received, and
once RE-READ from the payload afterwards against what the server actually WROTE
(the handler records the exact bytes it put on the wire). A single assertion at
receive time cannot distinguish "the channel carried the data" from "the channel
carried something that happened to satisfy the assertion"; comparing against the
server's own record is what closes that.
"""

from __future__ import annotations

import datetime
import http.server
import json
import ssl
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kiro_crew.connections.control_plane import production as production_module
from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes
from kiro_crew.connections.control_plane.executor import PageWalk, execute
from kiro_crew.connections.control_plane.handle import (
    DerivedHandle,
    derive_handle,
    ensure_usable,
)
from kiro_crew.connections.control_plane.operation import Effect, OperationDescriptor
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    BindingSecretSelector,
    BytesPayload,
    HttpReply,
    HttpRequest,
    build_production_transport,
    decode_json_body,
    neutral_decode,
    urllib_http_send,
)
from kiro_crew.connections.control_plane.result import (
    CollectionPayload,
    ObjectPayload,
    OperationResult,
    result_with_payload,
)
from kiro_crew.secrets import SecretVault

_T0 = 1_000_000.0
_GRANTED = ("mail.read", "mail.send")

#: A genuinely binary body: a real ZIP local-file header (what an ``xlsx`` starts
#: with), every byte value 0..255 -- so a NUL is in there -- and an invalid-UTF-8
#: tail. A text coercion cannot survive it, which is the point.
_XLSX_BYTES = (
    b"PK\x03\x04\x14\x00\x08\x08\x00\x00" + bytes(range(256)) + b"\xff\xfe\xfd\x00PK\x05\x06"
)
_XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


# =============================================================================
# real TLS material + a real TLS server that RECORDS what it served
# =============================================================================
def _tls_material(directory: Path) -> Tuple[Path, Path]:
    """Mint a self-signed cert valid for ``localhost`` / ``127.0.0.1``.

    Self-signed means the cert is its own CA, so pointing ``SSL_CERT_FILE`` at it
    is enough for the stdlib client to trust it with verification and hostname
    checking left ON -- which is what keeps this a real TLS path rather than a
    disabled one.
    """

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
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certfile = directory / "loopback-cert.pem"
    keyfile = directory / "loopback-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


class _Served:
    """The server's OWN record of what it put on the wire, per path.

    This is the readback oracle. Asserting a received payload against a constant
    in the test body proves the constant and the assertion agree; asserting it
    against what the SERVER wrote is what proves the channel carried that.
    """

    def __init__(self) -> None:
        self.bodies: Dict[str, bytes] = {}
        self.paths: List[str] = []
        self.authorization: List[Optional[str]] = []

    def record(self, path: str, headers: Mapping[str, str], body: bytes) -> None:
        self.paths.append(path)
        self.authorization.append(
            next((v for k, v in headers.items() if k.lower() == "authorization"), None)
        )
        self.bodies[path] = body


def _handler_for(
    served: _Served, script: Mapping[str, Tuple[int, Dict[str, str], bytes]]
) -> Callable[..., http.server.BaseHTTPRequestHandler]:
    """A handler that answers per REQUEST PATH from ``script`` and records it."""

    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _respond(self) -> None:
            if self.path not in script:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status, headers, body = script[self.path]
            served.record(self.path, {k: v for k, v in self.headers.items()}, body)
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            if status not in (204, 304):
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if status not in (204, 304) and body:
                self.wfile.write(body)

        do_GET = _respond
        do_POST = _respond

        def log_message(self, *args: Any) -> None:
            return

    return _H


@contextmanager
def _https_server(handler_cls: Any, certfile: Path, keyfile: Path) -> Iterator[int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certfile), str(keyfile))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# =============================================================================
# fresh-install posture + the real vault
# =============================================================================
@pytest.fixture
def fresh_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run from a cwd OUTSIDE the source tree, for every test in this file.

    Nothing on the control plane should read the current directory, and this is
    where that is checked rather than assumed: a relative import root, a
    ``Path("src/...")`` in a helper, or a cert path resolved against ``.`` would
    all fail here and pass in a dev checkout.
    """

    workdir = tmp_path / "elsewhere"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    return workdir


@pytest.fixture
def trust_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tuple[Path, Path]:
    """TLS material for the loopback server, trusted by the stdlib client."""

    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))
    return certfile, keyfile


@pytest.fixture
def real_vault(tmp_path: Path) -> SecretVault:
    """A REAL, isolated, AES-256-GCM vault on disk holding the binding secret."""

    from kiro_crew.connections.control_plane.binding import binding_secret_ref

    vault = SecretVault(tmp_path / "crewhome")
    vault.set_sync(binding_secret_ref("outlook")["name"], "outlook-live-token")
    store = tmp_path / "crewhome" / ".vault" / "secrets.enc"
    # Guard for the guard: a stub vault would make every custody claim vacuous.
    assert store.is_file() and b"outlook-live-token" not in store.read_bytes()
    return vault


# =============================================================================
# the real control-plane composition
# =============================================================================
def _verifier(*, claimed_subject: str, claimed_tenant: str, service_id: str) -> Dict[str, str]:
    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


def _handle() -> DerivedHandle:
    from kiro_crew.connections.control_plane.binding import create_binding

    binding = create_binding(
        service_id="outlook",
        claimed_subject="alice",
        claimed_tenant="acme",
        credential_mode="oauth_user",
        verifier=_verifier,  # type: ignore[arg-type]
        slug="outlook",
    )
    return derive_handle(
        binding,
        granted_scopes=_GRANTED,
        requested_scopes=("mail.read",),
        now=_T0,
        ttl_seconds=300.0,
    )


def _selector_for(handle: DerivedHandle) -> BindingSecretSelector:
    view = ensure_usable(handle, now=_T0)
    return BindingSecretSelector(
        slug="outlook",
        binding_fingerprint=view.binding_fingerprint,
        service_id=view.service_id,
        credential_mode=view.credential_mode,
    )


def _descriptor(effect: Effect = "read") -> OperationDescriptor:
    return {
        "operation_id": "outlook.messages.list",
        "service_id": "outlook",
        "operation_kind": "list",
        "effect": effect,
        "credential_modes": ("oauth_user",),
    }


def _kw(**over: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = dict(
        now=_T0,
        offered_mode="oauth_user",
        permitted=declare_permitted_modes(("oauth_user",)),
        layers=LayerCeilings(),
        governance_scope="tools",
        governance_item="messages.list",
    )
    base.update(over)
    return base


def _path_locator(port: int, path: str):
    """A vendor-shaped locator against the loopback server.

    The page cursor lands in the URL, so the walk's advance is visible in the
    server's own record of which paths it was asked for.
    """

    def _locate(*, request_args: Mapping[str, Any], **_: Any) -> HttpRequest:
        cursor = request_args.get("cursor")
        suffix = f"?page={cursor}" if cursor else ""
        return HttpRequest(
            method="GET",
            url=f"https://localhost:{port}{path}{suffix}",
            headers={"Accept": "*/*"},
        )

    return _locate


def _graph_collection_decode(reply: HttpReply) -> OperationResult:
    """A vendor decode: items from ``value``, cursor from ``@odata.nextLink``.

    The cursor goes to :func:`result_with_payload` as the explicit ``next_cursor``
    -- the envelope is the ONE place it lives, and the payload carries items only.
    """

    body = decode_json_body(reply)
    items = tuple(item for item in body.get("value", []) if isinstance(item, Mapping))
    link = body.get("@odata.nextLink")
    cursor = link if isinstance(link, str) else None
    return result_with_payload(
        CollectionPayload(items=items),
        status="partial" if cursor else "ok",
        next_cursor=cursor,
    )


def _object_decode(reply: HttpReply) -> OperationResult:
    return result_with_payload(ObjectPayload(object=decode_json_body(reply)), status="ok")


def _transport_for(
    handle: DerivedHandle, vault: SecretVault, port: int, path: str, decode: Any
) -> Any:
    """The real production transport over the REAL, unmodified sender."""

    # Pinned here rather than trusted: this is the whole claim of the file.
    assert urllib_http_send is production_module.urllib_http_send
    return build_production_transport(
        selector=_selector_for(handle),
        vault=vault,
        locator=_path_locator(port, path),
        http_send=urllib_http_send,
        decode=decode,
    )


# =============================================================================
# guards for the guards -- the harness is real, and the posture is fresh
# =============================================================================
def test_the_harness_is_real_tls_and_the_posture_is_a_fresh_install(
    fresh_install: Path, trust_loopback: Tuple[Path, Path]
) -> None:
    """Before any payload claim: the wire is TLS and the cwd is not the checkout."""

    certfile, keyfile = trust_loopback
    served = _Served()
    script = {"/probe": (200, {"Content-Type": "application/json"}, b'{"ok":true}')}
    with _https_server(_handler_for(served, script), certfile, keyfile) as port:
        reply = urllib_http_send(
            HttpRequest(method="GET", url=f"https://localhost:{port}/probe", headers={}),
            timeout_seconds=10.0,
        )
    assert reply.status == 200 and reply.body == b'{"ok":true}'
    assert served.paths == ["/probe"]

    # FRESH-INSTALL posture: the cwd is a temp dir, and the source tree is not
    # under it -- so nothing that worked did so by being launched from a checkout.
    cwd = Path.cwd().resolve()
    assert cwd == fresh_install.resolve()
    module_file = Path(production_module.__file__).resolve()
    assert cwd not in module_file.parents and module_file.parent != cwd
    # The package resolves off an ABSOLUTE sys.path entry, not "" / "." / a
    # cwd-relative one, which is what an installed package looks like.
    src_root = module_file.parents[3]  # .../src
    assert src_root.is_absolute() and str(src_root) in [
        str(Path(entry).resolve()) for entry in sys.path if entry
    ]


def test_verification_is_really_on(fresh_install: Path, tmp_path: Path) -> None:
    """The trust file is LOAD-BEARING, so the TLS above is verified, not disabled.

    Without ``SSL_CERT_FILE`` pointing at the self-signed cert the same send FAILS
    to verify. If verification were off (or the sender had an unverified context)
    this would pass and every "over real TLS" claim in this file would be worth
    much less.
    """

    certfile, keyfile = _tls_material(tmp_path)
    served = _Served()
    script: Dict[str, Tuple[int, Dict[str, str], bytes]] = {"/probe": (200, {}, b"{}")}
    with _https_server(_handler_for(served, script), certfile, keyfile) as port:
        with pytest.raises(Exception) as caught:
            urllib_http_send(
                HttpRequest(method="GET", url=f"https://localhost:{port}/probe", headers={}),
                timeout_seconds=10.0,
            )
    assert "CERTIFICATE_VERIFY_FAILED" in str(caught.value)
    assert served.paths == []


# =============================================================================
# (1) COLLECTION -- items AND the single authoritative cursor, over real TLS
# =============================================================================
def test_a_collection_walks_real_tls_and_reads_back_items_and_cursor(
    fresh_install: Path, trust_loopback: Tuple[Path, Path], real_vault: SecretVault
) -> None:
    """Three real pages, over real TLS, then READ BACK against what was served."""

    certfile, keyfile = trust_loopback
    served = _Served()
    json_headers = {"Content-Type": "application/json"}
    page1 = b'{"value":[{"id":"m1","subject":"one"},{"id":"m2","subject":"two"}],'
    page1 += b'"@odata.nextLink":"CURSOR-P2"}'
    page2 = b'{"value":[{"id":"m3","subject":"three"}],"@odata.nextLink":"CURSOR-P3"}'
    page3 = b'{"value":[{"id":"m4","subject":"four"}]}'
    script = {
        "/v1.0/me/messages": (200, json_headers, page1),
        "/v1.0/me/messages?page=CURSOR-P2": (200, json_headers, page2),
        "/v1.0/me/messages?page=CURSOR-P3": (200, json_headers, page3),
    }

    handle = _handle()
    with _https_server(_handler_for(served, script), certfile, keyfile) as port:
        walk = PageWalk(
            descriptor=_descriptor(),
            handle=handle,
            transport=_transport_for(
                handle, real_vault, port, "/v1.0/me/messages", _graph_collection_decode
            ),
            offered_mode="oauth_user",
            permitted=declare_permitted_modes(("oauth_user",)),
            layers=LayerCeilings(),
            governance_scope="tools",
            governance_item="messages.list",
            clock=lambda: _T0,
            base_args={"filter": "isRead eq false"},
        )
        received: List[Tuple[List[Mapping[str, Any]], Optional[str]]] = []
        while not walk.done:
            outcome = walk.next()
            assert outcome.ok, outcome.error
            payload = outcome.payload
            assert isinstance(payload, CollectionPayload)
            assert payload.items, "a page arrived over TLS with no items"
            assert outcome.result is not None
            # ITEM 1: the cursor is read off the ENVELOPE; the payload has none.
            assert not hasattr(payload, "next_cursor")
            received.append((list(payload.items), outcome.result["next_cursor"]))

    # --- what the consumer received, by VALUE ---------------------------------
    assert [items for items, _ in received] == [
        [{"id": "m1", "subject": "one"}, {"id": "m2", "subject": "two"}],
        [{"id": "m3", "subject": "three"}],
        [{"id": "m4", "subject": "four"}],
    ]
    assert [cursor for _, cursor in received] == ["CURSOR-P2", "CURSOR-P3", None]
    assert walk.pages == 3

    # --- READBACK: against what the SERVER actually wrote ---------------------
    assert served.paths == [
        "/v1.0/me/messages",
        "/v1.0/me/messages?page=CURSOR-P2",
        "/v1.0/me/messages?page=CURSOR-P3",
    ]
    for path, (items, cursor) in zip(served.paths, received):
        body = json.loads(served.bodies[path].decode("utf-8"))
        assert items == body["value"], f"items diverged from the served body at {path}"
        assert cursor == body.get("@odata.nextLink"), f"cursor diverged at {path}"
    # The walk really RESUMED on the served cursor: the second request's path
    # carries the cursor the first response's body announced.
    first_body = json.loads(served.bodies["/v1.0/me/messages"].decode("utf-8"))
    assert served.paths[1] == f"/v1.0/me/messages?page={first_body['@odata.nextLink']}"
    # The credential travelled (it is the origin the handle authorized) and is the
    # vault's, revealed per call -- never the secret's placeholder repr.
    assert served.authorization == ["Bearer outlook-live-token"] * 3


# =============================================================================
# (2) SINGLE OBJECT -- the object's fields, over real TLS
# =============================================================================
def test_a_single_object_crosses_real_tls_and_reads_back_field_for_field(
    fresh_install: Path, trust_loopback: Tuple[Path, Path], real_vault: SecretVault
) -> None:
    certfile, keyfile = trust_loopback
    served = _Served()
    body = b'{"id":"m1","subject":"Quarterly review","isRead":false,"weight":3,"webLink":"https://x/1"}'
    script = {
        "/v1.0/me/messages/m1": (200, {"Content-Type": "application/json"}, body),
    }

    handle = _handle()
    with _https_server(_handler_for(served, script), certfile, keyfile) as port:
        outcome = execute(
            _descriptor(),
            handle,
            _transport_for(handle, real_vault, port, "/v1.0/me/messages/m1", _object_decode),
            **_kw(),
        )

    assert outcome.ok
    payload = outcome.payload
    assert isinstance(payload, ObjectPayload)
    # The FIELDS, by value -- including the two that a sloppy decode would coerce.
    assert payload.object["id"] == "m1"
    assert payload.object["subject"] == "Quarterly review"
    assert payload.object["isRead"] is False
    assert payload.object["weight"] == 3
    assert payload.object["webLink"] == "https://x/1"
    # A single object is not a paged shape: no cursor was invented for it.
    assert outcome.result is not None and outcome.result["next_cursor"] is None
    assert not isinstance(payload, CollectionPayload)

    # --- READBACK against the served bytes -----------------------------------
    reread = outcome.payload
    assert isinstance(reread, ObjectPayload)
    assert dict(reread.object) == json.loads(served.bodies["/v1.0/me/messages/m1"].decode("utf-8"))
    assert served.paths == ["/v1.0/me/messages/m1"]


# =============================================================================
# (3) OFFICE BYTES -- byte-equal over real TLS, and never text-coerced
# =============================================================================
def test_office_bytes_cross_real_tls_byte_for_byte(
    fresh_install: Path, trust_loopback: Tuple[Path, Path], real_vault: SecretVault
) -> None:
    """The binary claim, on the neutral decode, over a real socket and real TLS.

    No vendor decode is injected: this is what makes a download work on a provider
    nobody has written a decode for yet.
    """

    # The body is genuinely binary -- a text coercion cannot survive it. Proven
    # here, before anything is sent, so the byte-equality below has teeth.
    with pytest.raises(UnicodeDecodeError):
        _XLSX_BYTES.decode("utf-8")

    certfile, keyfile = trust_loopback
    served = _Served()
    script = {
        "/v1.0/me/drive/items/w1/content": (
            200,
            {
                "Content-Type": _XLSX_MEDIA_TYPE,
                "Content-Disposition": 'attachment; filename="Q3.xlsx"',
            },
            _XLSX_BYTES,
        )
    }

    handle = _handle()
    with _https_server(_handler_for(served, script), certfile, keyfile) as port:
        outcome = execute(
            _descriptor(),
            handle,
            _transport_for(
                handle, real_vault, port, "/v1.0/me/drive/items/w1/content", neutral_decode
            ),
            **_kw(),
        )

    assert outcome.ok
    payload = outcome.payload
    assert isinstance(payload, BytesPayload)
    # THE assertion: byte-equal to the constant, off a real TLS wire.
    assert payload.data == _XLSX_BYTES
    assert type(payload.data) is bytes and len(payload.data) == len(_XLSX_BYTES)
    assert b"\x00" in payload.data
    assert payload.data[:4] == b"PK\x03\x04" and payload.data.endswith(b"PK\x05\x06")
    # And what arrived is STILL not decodable -- so nothing on the path coerced,
    # replaced or normalized a byte on the way through.
    with pytest.raises(UnicodeDecodeError):
        payload.data.decode("utf-8")
    assert payload.media_type == _XLSX_MEDIA_TYPE
    assert payload.filename == "Q3.xlsx"

    # --- READBACK against exactly the bytes the server wrote -----------------
    reread = outcome.payload
    assert isinstance(reread, BytesPayload)
    on_the_wire = served.bodies["/v1.0/me/drive/items/w1/content"]
    assert reread.data == on_the_wire
    assert len(reread.data) == len(on_the_wire)
    # Byte-by-byte, not just ==, so a length-equal-but-different body cannot pass.
    assert all(a == b for a, b in zip(reread.data, on_the_wire))
    with pytest.raises(UnicodeDecodeError):
        on_the_wire.decode("utf-8")


# =============================================================================
# ITEM 2 on a real wire: header folding is http.client's, not a fake's
# =============================================================================
def test_credential_response_headers_are_absent_from_metadata_off_a_real_wire(
    fresh_install: Path, trust_loopback: Tuple[Path, Path], real_vault: SecretVault
) -> None:
    """The allowlist holds against REAL header parsing, repeated headers included.

    An injected sender hands over a dict a test wrote. Here ``http.client`` parses
    the header block the server actually emitted -- including two ``Set-Cookie``
    lines, which is the shape a fake dict cannot even represent.
    """

    certfile, keyfile = trust_loopback
    served = _Served()

    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
            served.record(self.path, {k: v for k, v in self.headers.items()}, b"{}")
            self.send_response(429)
            self.send_header("Retry-After", "42")
            self.send_header("X-RateLimit-Remaining", "0")
            self.send_header("Set-Cookie", "session=SESSION-CANARY; HttpOnly")
            self.send_header("Set-Cookie", "extra=SECOND-CANARY")
            self.send_header("WWW-Authenticate", 'Bearer realm="graph"')
            self.send_header("Authorization", "Bearer ECHOED-CANARY")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args: Any) -> None:
            return

    handle = _handle()
    with _https_server(_H, certfile, keyfile) as port:
        outcome = execute(
            _descriptor(),
            handle,
            _transport_for(handle, real_vault, port, "/v1.0/me/messages", neutral_decode),
            **_kw(),
        )

    assert outcome.error is not None and outcome.error["error_class"] == "throttle"
    # PRESENT: the rate family the caller needs to back off.
    assert outcome.metadata["retry-after"] == "42"
    assert outcome.metadata["x-ratelimit-remaining"] == "0"
    # ABSENT: every credential/session key and every canary value.
    keys = {key.lower() for key in outcome.metadata}
    for banned in ("set-cookie", "www-authenticate", "authorization"):
        assert banned not in keys
    blob = " ".join(f"{k}={v}" for k, v in outcome.metadata.items())
    for canary in ("SESSION-CANARY", "SECOND-CANARY", "ECHOED-CANARY", "realm"):
        assert canary not in blob
    assert set(outcome.metadata) == {"retry-after", "x-ratelimit-remaining"}


# =============================================================================
# the hard fresh-install proof: a CHILD interpreter, first import, cwd elsewhere
# =============================================================================
_CHILD_SCRIPT = '''
"""Run all three shapes over real TLS in a FRESH interpreter, print a verdict.

Imported for the first time in this process, from a cwd that is a temp directory
outside the source tree, with the package reachable only through PYTHONPATH.
"""
import datetime, http.server, ipaddress, json, os, ssl, sys, threading

assert os.getcwd() == sys.argv[1], (os.getcwd(), sys.argv[1])
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes
from kiro_crew.connections.control_plane.binding import binding_secret_ref, create_binding
from kiro_crew.connections.control_plane.executor import PageWalk, execute
from kiro_crew.connections.control_plane.handle import derive_handle, ensure_usable
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    BindingSecretSelector, BytesPayload, HttpRequest, build_production_transport,
    decode_json_body, neutral_decode, urllib_http_send,
)
from kiro_crew.connections.control_plane.result import (
    CollectionPayload, ObjectPayload, result_with_payload,
)
from kiro_crew.secrets import SecretVault

WORK = sys.argv[1]
XLSX = b"PK\\x03\\x04\\x14\\x00\\x08\\x08\\x00\\x00" + bytes(range(256)) + b"\\xff\\xfe\\xfd\\x00PK\\x05\\x06"
T0 = 1_000_000.0
JSON = {"Content-Type": "application/json"}
SCRIPT = {
    "/list": (200, JSON, b'{"value":[{"id":"m1"}],"@odata.nextLink":"C2"}'),
    "/list?page=C2": (200, JSON, b'{"value":[{"id":"m2"}]}'),
    "/one": (200, JSON, b'{"id":"m1","subject":"s","isRead":false}'),
    "/bytes": (200, {"Content-Type": "application/octet-stream"}, XLSX),
}


def mint(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certfile = os.path.join(directory, "c.pem")
    keyfile = os.path.join(directory, "k.pem")
    with open(certfile, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(keyfile, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
    return certfile, keyfile


SERVED = {}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        status, headers, body = SCRIPT[self.path]
        SERVED[self.path] = body
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        return


def verifier(*, claimed_subject, claimed_tenant, service_id):
    return {"subject_ref": "subject://verified/a", "tenant_ref": "tenant://verified/t"}


def collection_decode(reply):
    body = decode_json_body(reply)
    link = body.get("@odata.nextLink")
    return result_with_payload(
        CollectionPayload(items=tuple(body.get("value", []))),
        status="partial" if link else "ok",
        next_cursor=link if isinstance(link, str) else None,
    )


def object_decode(reply):
    return result_with_payload(ObjectPayload(object=decode_json_body(reply)), status="ok")


def locator_for(port, path):
    def locate(*, request_args, **_):
        cursor = request_args.get("cursor")
        url = "https://localhost:%d%s%s" % (port, path, "?page=%s" % cursor if cursor else "")
        return HttpRequest(method="GET", url=url, headers={"Accept": "*/*"})
    return locate


certfile, keyfile = mint(WORK)
os.environ["SSL_CERT_FILE"] = certfile
vault = SecretVault(os.path.join(WORK, "crewhome"))
vault.set_sync(binding_secret_ref("outlook")["name"], "outlook-live-token")

binding = create_binding(service_id="outlook", claimed_subject="alice", claimed_tenant="acme",
                         credential_mode="oauth_user", verifier=verifier, slug="outlook")
handle = derive_handle(binding, granted_scopes=("mail.read",), requested_scopes=("mail.read",),
                       now=T0, ttl_seconds=300.0)
view = ensure_usable(handle, now=T0)
selector = BindingSecretSelector(slug="outlook", binding_fingerprint=view.binding_fingerprint,
                                 service_id=view.service_id, credential_mode=view.credential_mode)
descriptor = {"operation_id": "outlook.messages.list", "service_id": "outlook",
              "operation_kind": "list", "effect": "read", "credential_modes": ("oauth_user",)}
kw = dict(now=T0, offered_mode="oauth_user", permitted=declare_permitted_modes(("oauth_user",)),
          layers=LayerCeilings(), governance_scope="tools", governance_item="messages.list")

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile, keyfile)
server.socket = context.wrap_socket(server.socket, server_side=True)
threading.Thread(target=server.serve_forever, daemon=True).start()
port = server.server_address[1]

out = {"cwd": os.getcwd(), "module": sys.modules["kiro_crew.connections.control_plane.production"].__file__}


def transport(path, decode):
    return build_production_transport(selector=selector, vault=vault,
                                      locator=locator_for(port, path),
                                      http_send=urllib_http_send, decode=decode)


walk = PageWalk(descriptor=descriptor, handle=handle, transport=transport("/list", collection_decode),
                offered_mode="oauth_user", permitted=declare_permitted_modes(("oauth_user",)),
                layers=LayerCeilings(), governance_scope="tools", governance_item="messages.list",
                clock=lambda: T0)
items, cursors = [], []
while not walk.done:
    outcome = walk.next()
    assert outcome.ok, outcome.error
    items.extend(dict(item) for item in outcome.payload.items)
    cursors.append(outcome.result["next_cursor"])
    assert not hasattr(outcome.payload, "next_cursor")
out["items"] = items
out["cursors"] = cursors
out["pages"] = walk.pages

single = execute(descriptor, handle, transport("/one", object_decode), **kw)
assert single.ok
out["object"] = dict(single.payload.object)
out["object_cursor"] = single.result["next_cursor"]

office = execute(descriptor, handle, transport("/bytes", neutral_decode), **kw)
assert office.ok and isinstance(office.payload, BytesPayload)
data = office.payload.data
out["bytes_equal_constant"] = data == XLSX
out["bytes_equal_served"] = data == SERVED["/bytes"]
out["bytes_len"] = len(data)
try:
    data.decode("utf-8")
    out["utf8_raises"] = False
except UnicodeDecodeError:
    out["utf8_raises"] = True

server.shutdown()
print("KC-VERDICT " + json.dumps(out))
'''


def test_a_fresh_interpreter_outside_the_source_tree_carries_all_three_shapes(
    tmp_path: Path,
) -> None:
    """The hard fresh-install proof: a CHILD process, first import, cwd elsewhere.

    The in-process tests chdir, which covers "nothing reads the cwd at call time".
    This covers the rest: a brand-new interpreter that has never imported the
    package, launched with ``cwd`` set to a temp directory and the package
    reachable only through an absolute ``PYTHONPATH`` entry -- i.e. the posture an
    installed wheel is imported in, not a dev checkout. It runs the whole real-TLS
    path itself and prints a verdict this test asserts on.
    """

    workdir = tmp_path / "child-cwd"
    workdir.mkdir()
    script = tmp_path / "child_e2e.py"
    script.write_text(_CHILD_SCRIPT)
    src_root = Path(production_module.__file__).resolve().parents[3]
    assert src_root.name == "src" and (src_root / "kiro_crew").is_dir()
    assert src_root not in workdir.parents and workdir != src_root

    completed = subprocess.run(
        [sys.executable, str(script), str(workdir)],
        cwd=str(workdir),
        env={
            "PYTHONPATH": str(src_root),
            "PATH": "/usr/bin:/bin",
            "HOME": str(workdir),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    line = next(row for row in completed.stdout.splitlines() if row.startswith("KC-VERDICT "))
    verdict = json.loads(line[len("KC-VERDICT ") :])

    # It really ran outside the source tree, off the PYTHONPATH copy.
    assert verdict["cwd"] == str(workdir)
    assert (
        verdict["module"] == str(Path(production_module.__file__).resolve())
        or Path(verdict["module"]).resolve() == Path(production_module.__file__).resolve()
    )
    # (1) collection: item VALUES and the envelope cursors, across a real walk.
    assert verdict["items"] == [{"id": "m1"}, {"id": "m2"}]
    assert verdict["cursors"] == ["C2", None]
    assert verdict["pages"] == 2
    # (2) single object: the fields.
    assert verdict["object"] == {"id": "m1", "subject": "s", "isRead": False}
    assert verdict["object_cursor"] is None
    # (3) Office: byte-equal to the constant AND to what the server served, and
    # still not UTF-8 decodable.
    assert verdict["bytes_equal_constant"] is True
    assert verdict["bytes_equal_served"] is True
    assert verdict["bytes_len"] == len(_XLSX_BYTES)
    assert verdict["utf8_raises"] is True
