"""W01 · L09: the four PRODUCTION boundaries, proved without an all-mock seam.

The executor's own tests inject a fake transport, and the composition tests next
to them inject a fake vault and a fake sender. That is the right shape for
proving a DECISION -- but it cannot prove a WIRE property. A fake sender that
never opens a socket cannot tell you whether ``urllib`` forwards an
``Authorization`` header across a redirect (it does), and a stub vault that
returns whatever you seeded it with cannot tell you whether the custody path
resolves the right binding's entry out of a real encrypted store.

So the four boundaries here are exercised against real things:

* a REAL :class:`kiro_crew.secrets.SecretVault` -- an AES-256-GCM store on disk in
  a per-test ``tmp_path``, isolated, created and keyed by the vault itself;
* a REAL HTTPS loopback server -- ``http.server`` behind a TLS socket with a
  self-signed certificate minted in the test, driven by the UNMODIFIED
  :func:`~kiro_crew.connections.control_plane.production.urllib_http_send` over
  real sockets, so the redirect machinery, the body read, the size cap and the
  deadline are the real ones.

Each defect these pin was reproduced first. The redirect leak in particular was
observed on the wire: with the default opener, a 302 from one loopback origin to
another delivered ``Bearer <token>`` to the second server.
"""

from __future__ import annotations

import datetime
import http.server
import socket
import ssl
import threading
import time
import urllib.error
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes
from kiro_crew.connections.control_plane.binding import (
    Binding,
    VerifiedIdentity,
    binding_secret_ref,
    create_binding,
)
from kiro_crew.connections.control_plane.executor import (
    EXECUTOR_SCHEMA_VERSION,
    TransportResponse,
    execute,
    is_non_idempotent_effect,
)
from kiro_crew.connections.control_plane.handle import (
    DerivedHandle,
    derive_handle,
    ensure_usable,
)
from kiro_crew.connections.control_plane.operation import Effect, OperationDescriptor
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_MAX_RESPONSE_BYTES,
    PRODUCTION_SCHEMA_VERSION,
    BindingIdentityMismatchError,
    BindingSecretSelector,
    HttpReply,
    HttpRequest,
    RedirectHop,
    RedirectRefusedError,
    ResponseTooLargeError,
    TransportDeadlineExceededError,
    build_production_transport,
    neutral_decode,
    neutral_decode_detail,
    urllib_http_send,
)
from kiro_crew.connections.control_plane.result import (
    DEFAULT_MEDIA_TYPE,
    RESULT_SCHEMA_VERSION,
    RESULT_STATUS_OK,
    RESULT_STATUS_PARTIAL,
    RESULT_STATUSES,
    BytesPayload,
)
from kiro_crew.connections.control_plane.writes import (
    ATTEMPT_FAILED_NOT_APPLIED,
    ATTEMPT_UNKNOWN,
    REPLAY_ALLOW,
    REPLAY_REFUSE,
    args_fingerprint,
    record_attempt,
    replay_decision,
)
from kiro_crew.secrets import SecretValue, SecretVault

_T0 = 1_000_000.0
_GRANTED = ("mail.read", "mail.send")


# =============================================================================
# shared control-plane fixtures (the decision side, kept minimal)
# =============================================================================
def _verifier(*, claimed_subject: str, claimed_tenant: str, service_id: str) -> VerifiedIdentity:
    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


def _binding(*, subject: str = "alice", tenant: str = "acme", slug: str = "outlook") -> Binding:
    return create_binding(
        service_id="outlook",
        claimed_subject=subject,
        claimed_tenant=tenant,
        credential_mode="oauth_user",
        verifier=_verifier,
        slug=slug,
    )


def _handle(binding: Binding, *, requested: Tuple[str, ...] = ("mail.read",)) -> DerivedHandle:
    return derive_handle(
        binding,
        granted_scopes=_GRANTED,
        requested_scopes=requested,
        now=_T0,
        ttl_seconds=300.0,
    )


def _selector_for(handle: DerivedHandle, *, slug: str = "outlook") -> BindingSecretSelector:
    view = ensure_usable(handle, now=_T0)
    return BindingSecretSelector(
        slug=slug,
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
        layers=LayerCeilings(),  # all None == ungoverned == permit
        governance_scope="tools",
        governance_item="messages.list",
    )
    base.update(over)
    return base


def _locator_to(url: str, *, method: str = "GET", body: Optional[bytes] = None):
    def _locate(**kwargs: Any) -> HttpRequest:
        return HttpRequest(
            method=method, url=url, headers={"Accept": "application/json"}, body=body
        )

    return _locate


# =============================================================================
# a REAL isolated SecretVault (encrypted store on disk, per test)
# =============================================================================
class RecordingVault(SecretVault):
    """The REAL vault, with reads recorded.

    A subclass rather than a stub on purpose: the store, the key file and the
    AES-256-GCM crypto are the product's own, so what this proves about custody is
    a property of the real path. The override records the name and then delegates,
    so ``asked`` is the honest answer to "was the vault consulted, and for what" --
    which is exactly what the binding-mismatch counterexample needs to assert
    NEGATIVELY.
    """

    def __init__(self, config_dir: Path) -> None:
        super().__init__(config_dir)
        self.asked: List[str] = []

    def get(self, name: str) -> Optional[SecretValue]:
        self.asked.append(name)
        return super().get(name)


@pytest.fixture
def real_vault(tmp_path: Path) -> RecordingVault:
    """A real, isolated, encrypted vault holding the outlook binding secret."""

    vault = RecordingVault(tmp_path / "crewhome")
    vault.set_sync(binding_secret_ref("outlook")["name"], "outlook-live-token")
    vault.asked.clear()
    return vault


def test_the_real_vault_under_test_is_an_encrypted_store_on_disk(
    tmp_path: Path, real_vault: RecordingVault
) -> None:
    """Guard for the guards: if this were a stub, nothing below would prove custody."""

    store = tmp_path / "crewhome" / ".vault" / "secrets.enc"
    key = tmp_path / "crewhome" / ".vault" / ".vault_key"
    assert store.is_file() and key.is_file()
    raw = store.read_bytes()
    # The plaintext is NOT on disk: an encrypted store, not a JSON file.
    assert b"outlook-live-token" not in raw
    assert isinstance(real_vault, SecretVault)
    # And it round-trips through the real crypto.
    value = real_vault.get(binding_secret_ref("outlook")["name"])
    assert value is not None and value.reveal() == "outlook-live-token"


# =============================================================================
# a REAL HTTPS loopback server (self-signed, minted per test)
# =============================================================================
def _tls_material(tmp_path: Path) -> Tuple[Path, Path]:
    """Mint a self-signed cert valid for ``localhost`` / ``127.0.0.1``.

    Self-signed means the cert is its own CA, so pointing ``SSL_CERT_FILE`` at it
    is enough to make the stdlib client trust it -- with hostname verification and
    certificate validation left ON, which is what keeps this a real TLS path
    rather than a disabled one.
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
    certfile = tmp_path / "loopback-cert.pem"
    keyfile = tmp_path / "loopback-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


class _Recorder:
    """What each loopback server actually received."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, str]] = []

    @property
    def hits(self) -> int:
        return len(self.requests)

    def authorization_seen(self) -> List[Optional[str]]:
        return [
            next((v for k, v in req.items() if k.lower() == "authorization"), None)
            for req in self.requests
        ]


def _handler_for(
    recorder: _Recorder,
    *,
    reply: Callable[[], Tuple[int, Dict[str, str], bytes]],
    pause_before_body: float = 0.0,
):
    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _respond(self) -> None:
            recorder.requests.append({k: v for k, v in self.headers.items()})
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            status, headers, body = reply()
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            if status not in (204, 304):
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if pause_before_body:
                self.wfile.flush()
                time.sleep(pause_before_body)
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


@pytest.fixture
def trust_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tuple[Path, Path]:
    """TLS material for the loopback servers, trusted by the stdlib client."""

    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))
    return certfile, keyfile


def test_the_loopback_harness_really_speaks_tls_to_the_real_sender(
    trust_loopback: Tuple[Path, Path],
) -> None:
    """Guard for the guards: the redirect tests below must not be sending over http."""

    certfile, keyfile = trust_loopback
    rec = _Recorder()
    handler = _handler_for(rec, reply=lambda: (200, {}, b'{"ok":true}'))
    with _https_server(handler, certfile, keyfile) as port:
        reply = urllib_http_send(
            HttpRequest(method="GET", url=f"https://localhost:{port}/probe", headers={}),
            timeout_seconds=10.0,
        )
    assert reply.status == 200 and reply.body == b'{"ok":true}'
    assert rec.hits == 1


# =============================================================================
# DEFECT A -- the credential must never leave its origin
# =============================================================================
def test_a_cross_origin_redirect_is_refused_by_default_and_the_target_sees_nothing(
    trust_loopback: Tuple[Path, Path],
) -> None:
    """The pre-fix behaviour, on this exact harness, delivered Bearer to hop 2."""

    certfile, keyfile = trust_loopback
    target_rec, origin_rec = _Recorder(), _Recorder()
    target_handler = _handler_for(target_rec, reply=lambda: (200, {}, b"{}"))
    with _https_server(target_handler, certfile, keyfile) as target_port:
        origin_handler = _handler_for(
            origin_rec,
            reply=lambda: (302, {"Location": f"https://localhost:{target_port}/next"}, b""),
        )
        with _https_server(origin_handler, certfile, keyfile) as origin_port:
            with pytest.raises(RedirectRefusedError) as caught:
                urllib_http_send(
                    HttpRequest(
                        method="GET",
                        url=f"https://localhost:{origin_port}/start",
                        headers={"Authorization": "Bearer LEAK-CANARY"},
                    ),
                    timeout_seconds=10.0,
                )
    # Hop 1 got the credential (it is the origin the handle authorized).
    assert origin_rec.authorization_seen() == ["Bearer LEAK-CANARY"]
    # Hop 2 was never even contacted: no request, so nothing to leak.
    assert target_rec.hits == 0
    assert "follows no redirects" in str(caught.value)


def test_an_allowlisted_cross_origin_hop_travels_with_the_credential_stripped(
    trust_loopback: Tuple[Path, Path],
) -> None:
    """Rule 4, and the one that matters: allowlisted is not the same as trusted."""

    certfile, keyfile = trust_loopback
    target_rec, origin_rec = _Recorder(), _Recorder()
    target_handler = _handler_for(target_rec, reply=lambda: (200, {}, b'{"v":1}'))
    with _https_server(target_handler, certfile, keyfile) as target_port:
        origin_handler = _handler_for(
            origin_rec,
            reply=lambda: (302, {"Location": f"https://localhost:{target_port}/next"}, b""),
        )
        with _https_server(origin_handler, certfile, keyfile) as origin_port:
            hops: List[RedirectHop] = []
            reply = urllib_http_send(
                HttpRequest(
                    method="GET",
                    url=f"https://localhost:{origin_port}/start",
                    headers={
                        "Authorization": "Bearer LEAK-CANARY",
                        "Cookie": "session=CANARY",
                        "X-Api-Key": "CANARY",
                        "Accept": "application/json",
                    },
                ),
                timeout_seconds=10.0,
                allowed_redirect_hosts=frozenset(
                    {f"localhost:{origin_port}", f"localhost:{target_port}"}
                ),
                hop_log=hops,
            )

    assert reply.status == 200 and reply.body == b'{"v":1}'
    # The hop happened, off-origin, and NO credential header rode along.
    assert [(h.same_origin, h.credential_forwarded) for h in hops] == [(False, False)]
    assert hops[0].to_url.endswith("/next")
    # Observed at the second server, not inferred from the hop record.
    received = target_rec.requests[0]
    for header in ("authorization", "cookie", "x-api-key"):
        assert not any(k.lower() == header for k in received), header
    # A non-credential header is NOT stripped -- the guard is targeted.
    assert any(k.lower() == "accept" for k in received)


def test_a_same_origin_redirect_keeps_the_credential(trust_loopback: Tuple[Path, Path]) -> None:
    """The credential may follow within the origin it was authorized for."""

    certfile, keyfile = trust_loopback
    rec = _Recorder()
    replies = iter([(302, {"Location": "/second"}, b""), (200, {}, b'{"v":2}')])
    handler = _handler_for(rec, reply=lambda: next(replies))
    with _https_server(handler, certfile, keyfile) as port:
        hops: List[RedirectHop] = []
        reply = urllib_http_send(
            HttpRequest(
                method="GET",
                url=f"https://localhost:{port}/first",
                headers={"Authorization": "Bearer SAME-ORIGIN-OK"},
            ),
            timeout_seconds=10.0,
            allowed_redirect_hosts=frozenset({f"localhost:{port}"}),
            hop_log=hops,
        )
    assert reply.status == 200 and reply.body == b'{"v":2}'
    assert [(h.same_origin, h.credential_forwarded) for h in hops] == [(True, True)]
    assert rec.authorization_seen() == ["Bearer SAME-ORIGIN-OK", "Bearer SAME-ORIGIN-OK"]


def test_an_https_to_http_downgrade_hop_is_refused_even_when_allowlisted(
    trust_loopback: Tuple[Path, Path],
) -> None:
    """Rule 2 is independent of rule 3: an allowlist entry does not license clear text."""

    certfile, keyfile = trust_loopback
    plain_rec = _Recorder()
    plain_handler = _handler_for(plain_rec, reply=lambda: (200, {}, b"{}"))
    plain = http.server.ThreadingHTTPServer(("127.0.0.1", 0), plain_handler)
    plain_port = int(plain.server_address[1])
    plain_thread = threading.Thread(target=plain.serve_forever, daemon=True)
    plain_thread.start()
    try:
        origin_rec = _Recorder()
        origin_handler = _handler_for(
            origin_rec,
            reply=lambda: (302, {"Location": f"http://localhost:{plain_port}/next"}, b""),
        )
        with _https_server(origin_handler, certfile, keyfile) as origin_port:
            with pytest.raises(RedirectRefusedError) as caught:
                urllib_http_send(
                    HttpRequest(
                        method="GET",
                        url=f"https://localhost:{origin_port}/start",
                        headers={"Authorization": "Bearer LEAK-CANARY"},
                    ),
                    timeout_seconds=10.0,
                    # Explicitly allowlisted, and STILL refused.
                    allowed_redirect_hosts=frozenset({f"localhost:{plain_port}"}),
                )
    finally:
        plain.shutdown()
        plain.server_close()
        plain_thread.join(timeout=5)
    assert plain_rec.hits == 0
    assert "would leave https" in str(caught.value)


def test_a_hop_off_the_allowlist_is_refused(trust_loopback: Tuple[Path, Path]) -> None:
    """Rule 3, default-deny: absence from the allowlist is a refusal."""

    certfile, keyfile = trust_loopback
    target_rec, origin_rec = _Recorder(), _Recorder()
    target_handler = _handler_for(target_rec, reply=lambda: (200, {}, b"{}"))
    with _https_server(target_handler, certfile, keyfile) as target_port:
        origin_handler = _handler_for(
            origin_rec,
            reply=lambda: (302, {"Location": f"https://localhost:{target_port}/next"}, b""),
        )
        with _https_server(origin_handler, certfile, keyfile) as origin_port:
            with pytest.raises(RedirectRefusedError) as caught:
                urllib_http_send(
                    HttpRequest(
                        method="GET",
                        url=f"https://localhost:{origin_port}/start",
                        headers={"Authorization": "Bearer LEAK-CANARY"},
                    ),
                    timeout_seconds=10.0,
                    allowed_redirect_hosts=frozenset({f"localhost:{origin_port}"}),
                )
    assert target_rec.hits == 0
    assert "not in this send's egress allowlist" in str(caught.value)


def test_a_refused_redirect_reaches_the_executor_as_a_typed_error(
    real_vault: RecordingVault, trust_loopback: Tuple[Path, Path]
) -> None:
    """End to end: the transport returns an envelope, it does not raise."""

    certfile, keyfile = trust_loopback
    target_rec, origin_rec = _Recorder(), _Recorder()
    target_handler = _handler_for(target_rec, reply=lambda: (200, {}, b"{}"))
    with _https_server(target_handler, certfile, keyfile) as target_port:
        origin_handler = _handler_for(
            origin_rec,
            reply=lambda: (302, {"Location": f"https://localhost:{target_port}/next"}, b""),
        )
        with _https_server(origin_handler, certfile, keyfile) as origin_port:
            handle = _handle(_binding())
            transport = build_production_transport(
                selector=_selector_for(handle),
                vault=real_vault,
                locator=_locator_to(f"https://localhost:{origin_port}/start"),
            )
            outcome = execute(_descriptor(), handle, transport, **_kw())

    assert outcome.error is not None
    assert outcome.error["error_class"] == "input"
    assert target_rec.hits == 0
    # The real vault WAS read (the credential is needed for hop 1) and the token
    # reached only the origin.
    assert real_vault.asked == ["CONNECTIONS_OUTLOOK_BINDING_SECRET"]
    assert origin_rec.authorization_seen() == ["Bearer outlook-live-token"]
    # A read has no effect to be uncertain about.
    assert outcome.write_outcome is None


# =============================================================================
# DEFECT B -- the secret is selected from the call's trusted binding
# =============================================================================
def test_the_real_vault_resolves_this_bindings_secret_for_a_matching_call(
    real_vault: RecordingVault, trust_loopback: Tuple[Path, Path]
) -> None:
    certfile, keyfile = trust_loopback
    rec = _Recorder()
    handler = _handler_for(rec, reply=lambda: (200, {}, b'{"value":[]}'))
    with _https_server(handler, certfile, keyfile) as port:
        handle = _handle(_binding())
        transport = build_production_transport(
            selector=_selector_for(handle),
            vault=real_vault,
            locator=_locator_to(f"https://localhost:{port}/v1/me/messages"),
        )
        outcome = execute(_descriptor(), handle, transport, **_kw())

    assert outcome.error is None
    # Resolved by NAME out of the real encrypted store, and it reached the wire.
    assert real_vault.asked == ["CONNECTIONS_OUTLOOK_BINDING_SECRET"]
    assert rec.authorization_seen() == ["Bearer outlook-live-token"]


def test_a_transport_refuses_a_call_from_another_binding_and_never_reads_the_vault(
    real_vault: RecordingVault,
) -> None:
    """The counterexample: composed for X, called for Y -> refuse, resolve nothing.

    Both bindings are the SAME service and the SAME credential mode -- the two
    axes the executor used to pass -- and differ only in the verified
    subject/tenant behind them. That is precisely the pair the old composition
    could not tell apart.
    """

    binding_x = _binding(subject="alice", tenant="acme")
    binding_y = _binding(subject="bob", tenant="globex")
    handle_x, handle_y = _handle(binding_x), _handle(binding_y)
    view_x, view_y = ensure_usable(handle_x, now=_T0), ensure_usable(handle_y, now=_T0)
    # Same trusted routing axes; different bindings.
    assert (view_x.service_id, view_x.credential_mode) == (
        view_y.service_id,
        view_y.credential_mode,
    )
    assert view_x.binding_fingerprint != view_y.binding_fingerprint

    sent: List[HttpRequest] = []

    def _send(request: HttpRequest, *, timeout_seconds: float) -> HttpReply:
        sent.append(request)
        return HttpReply(status=200, body=b"{}")

    transport = build_production_transport(
        selector=_selector_for(handle_x),  # custody for X
        vault=real_vault,
        locator=_locator_to("https://graph.example.invalid/v1/me"),
        http_send=_send,
    )
    outcome = execute(_descriptor(), handle_y, transport, **_kw())  # a call for Y

    assert outcome.error is not None
    assert outcome.error["error_class"] == "auth"
    # NOTHING was emitted and the vault was NEVER asked -- not for X's name, not
    # for any name -- so no plaintext existed at any point on this path.
    assert sent == []
    assert real_vault.asked == []
    assert binding_secret_ref("outlook")["name"] not in real_vault.asked


def test_the_selector_refuses_a_call_that_carries_no_trusted_identity_at_all(
    real_vault: RecordingVault,
) -> None:
    """Fail CLOSED: an absent view must not fall back to the composed binding."""

    handle = _handle(_binding())
    selector = _selector_for(handle)
    with pytest.raises(BindingIdentityMismatchError) as caught:
        selector.secret_ref_for(None)
    assert "no trusted binding identity" in str(caught.value)

    def _send(request: HttpRequest, *, timeout_seconds: float) -> HttpReply:
        raise AssertionError("must not send")

    transport = build_production_transport(
        selector=selector,
        vault=real_vault,
        locator=_locator_to("https://graph.example.invalid/v1/me"),
        http_send=_send,
    )
    # Called directly, as a legacy caller that never passes trusted_view would.
    response = transport(
        service_id="outlook",
        credential_mode="oauth_user",
        descriptor=_descriptor(),
        request_args={},
    )
    assert response.http_status == 401
    assert real_vault.asked == []


def test_the_selector_refuses_a_mismatched_service_or_credential_mode() -> None:
    """The fingerprint is not the only gate: the trusted axes must agree too."""

    handle = _handle(_binding())
    view = ensure_usable(handle, now=_T0)
    base = _selector_for(handle)

    wrong_service = BindingSecretSelector(
        slug="outlook",
        binding_fingerprint=view.binding_fingerprint,
        service_id="github",
        credential_mode="oauth_user",
    )
    with pytest.raises(BindingIdentityMismatchError):
        wrong_service.secret_ref_for(view)

    wrong_mode = BindingSecretSelector(
        slug="outlook",
        binding_fingerprint=view.binding_fingerprint,
        service_id="outlook",
        credential_mode="service_to_service",
    )
    with pytest.raises(BindingIdentityMismatchError):
        wrong_mode.secret_ref_for(view)

    # And the matching one still resolves, through L02's own naming.
    assert base.secret_ref_for(view)["name"] == "CONNECTIONS_OUTLOOK_BINDING_SECRET"
    assert base.secret_ref_for(view)["backend"] == "vault"


def test_an_empty_composed_fingerprint_matches_nothing() -> None:
    """A blank-vs-blank comparison must not become a wildcard."""

    handle = _handle(_binding())
    view = ensure_usable(handle, now=_T0)
    blank = BindingSecretSelector(
        slug="outlook",
        binding_fingerprint="",
        service_id=view.service_id,
        credential_mode=view.credential_mode,
    )
    with pytest.raises(BindingIdentityMismatchError):
        blank.secret_ref_for(view)


def test_named_gap_the_vault_entry_name_is_per_slug_not_per_binding() -> None:
    """A GAP this repair does not close, pinned so it is not mistaken for closed.

    :func:`~kiro_crew.connections.control_plane.binding.binding_secret_ref` derives
    the entry name from the provider SLUG alone, so two bindings of the SAME
    provider -- different subjects, different tenants -- reference the SAME vault
    entry. Per-binding secret SEPARATION therefore does not exist at the naming
    level, and it cannot be created here: ``binding.py`` is an integrated L02
    primitive this repair may not edit.

    What the selector does achieve is narrower and still worth having: a transport
    refuses to act for a binding it does not hold custody for, so a cross-binding
    call fails closed instead of proceeding under whatever single credential the
    slug happens to hold. Anything more requires a binding-scoped entry name in
    L02 plus the missing principal -> binding resolver.
    """

    view_a = ensure_usable(_handle(_binding(subject="alice", tenant="acme")), now=_T0)
    view_b = ensure_usable(_handle(_binding(subject="bob", tenant="globex")), now=_T0)
    sel_a = BindingSecretSelector(
        slug="outlook",
        binding_fingerprint=view_a.binding_fingerprint,
        service_id=view_a.service_id,
        credential_mode=view_a.credential_mode,
    )
    sel_b = BindingSecretSelector(
        slug="outlook",
        binding_fingerprint=view_b.binding_fingerprint,
        service_id=view_b.service_id,
        credential_mode=view_b.credential_mode,
    )
    # Different bindings, SAME entry name -- the gap, stated as a fact.
    assert sel_a.secret_ref_for(view_a)["name"] == sel_b.secret_ref_for(view_b)["name"]
    # But neither selector will serve the other's call.
    with pytest.raises(BindingIdentityMismatchError):
        sel_a.secret_ref_for(view_b)
    with pytest.raises(BindingIdentityMismatchError):
        sel_b.secret_ref_for(view_a)
    # A different SLUG does get a different entry, which is the axis L02 does model.
    assert (
        BindingSecretSelector(
            slug="github",
            binding_fingerprint=view_a.binding_fingerprint,
            service_id=view_a.service_id,
            credential_mode=view_a.credential_mode,
        ).secret_ref_for(view_a)["name"]
        == "CONNECTIONS_GITHUB_BINDING_SECRET"
    )


def test_named_gap_l04_generation_fencing_is_not_judged_here() -> None:
    """The selector matches a BINDING, not a generation. L04 owns the fencing.

    A handle derived from generation N still matches its binding after the binding
    has moved to N+1, because nothing in this module compares generations. Saying
    so out loud is the point: this must not be read as revoke enforcement.
    """

    from kiro_crew.connections.control_plane.binding import next_generation

    binding = _binding()
    handle = _handle(binding)
    view = ensure_usable(handle, now=_T0)
    selector = _selector_for(handle)

    rotated = next_generation(binding)
    assert rotated["generation"] == binding["generation"] + 1
    # The old handle's view still resolves: no generation judgment happens here.
    assert selector.secret_ref_for(view)["name"] == "CONNECTIONS_OUTLOOK_BINDING_SECRET"
    assert view.generation == binding["generation"]


def test_the_transport_binds_to_the_record_sourced_view_never_a_caller_chosen_one() -> None:
    """The fingerprint the selector matches on cannot be chosen by the caller.

    Two facts, and the second is the stronger one:

    1. On a clean call the transport receives a ``trusted_view`` whose
       ``binding_fingerprint`` is the one L08 recorded at issuance.
    2. A handle carrying a DIFFERENT fingerprint does not reach the transport at
       all -- ``ensure_usable`` refuses it as tampered before step 2 of the gate
       chain. So the identity the selector judges is never caller-supplied, and
       the selector's match is not the only thing standing between two bindings.
    """

    handle = _handle(_binding())
    view = ensure_usable(handle, now=_T0)
    seen: List[Dict[str, Any]] = []

    def _transport(**kwargs: Any) -> TransportResponse:
        seen.append(kwargs)
        return TransportResponse(
            http_status=200, result={"status": "ok", "next_cursor": None, "payload": None}
        )

    outcome = execute(_descriptor(), handle, _transport, **_kw())
    assert outcome.error is None
    assert seen[0]["trusted_view"].binding_fingerprint == view.binding_fingerprint
    # The selector built for this binding matches the view the executor passed.
    assert _selector_for(handle).secret_ref_for(seen[0]["trusted_view"])["name"] == (
        "CONNECTIONS_OUTLOOK_BINDING_SECRET"
    )

    # (2) A rewritten fingerprint never gets as far as the transport.
    tampered = dict(handle)
    tampered["binding_fingerprint"] = "0" * 64
    seen.clear()
    refused = execute(_descriptor(), tampered, _transport, **_kw())  # type: ignore[arg-type]
    assert refused.error is not None
    assert refused.error["error_class"] == "auth"
    assert seen == []


# =============================================================================
# DEFECT C -- 2xx is interpreted, not collapsed
# =============================================================================
@pytest.mark.parametrize(
    ("status", "body", "expected_status", "kind", "determined"),
    [
        (204, b"", "ok", "no_content", True),
        (200, b"", "ok", "empty_complete", True),
        (202, b"", "ok", "empty_complete", True),
        (206, b'{"value":[1]}', "partial", "partial_content", False),
        (200, b'{"value":[1,2]}', "partial", "cursor_undetermined", False),
        (201, b'{"id":"new"}', "partial", "cursor_undetermined", False),
    ],
)
def test_the_2xx_interpretation_table(
    status: int, body: bytes, expected_status: str, kind: str, determined: bool
) -> None:
    detail = neutral_decode_detail(HttpReply(status=status, body=body))
    assert detail.result["status"] == expected_status
    assert detail.content_kind == kind
    assert detail.cursor_determined is determined
    # No cursor is ever GUESSED -- that stays the vendor owner's job.
    assert detail.result["next_cursor"] is None
    assert neutral_decode(HttpReply(status=status, body=body)) == detail.result
    # Every status produced is a member of L01's closed set, and the two spellings
    # this module writes are L01's own constants -- pinned here rather than
    # trusted, since production.py writes the literals for mypy's benefit.
    assert detail.result["status"] in RESULT_STATUSES
    assert (RESULT_STATUS_OK, RESULT_STATUS_PARTIAL) == ("ok", "partial")


def test_a_204_and_a_200_with_a_body_no_longer_decode_the_same() -> None:
    """The counterexample this defect was reported with."""

    no_content = neutral_decode(HttpReply(status=204, body=b""))
    with_body = neutral_decode(HttpReply(status=200, body=b'{"value":[1,2,3]}'))
    assert no_content != with_body
    assert no_content == {"status": "ok", "next_cursor": None, "payload": None}
    # The body-bearing reply is `partial` AND carries its bytes: the two readings
    # differ on the payload channel as well as on the status.
    assert with_body["status"] == "partial" and with_body["next_cursor"] is None
    assert with_body["payload"] == BytesPayload(
        data=b'{"value":[1,2,3]}', media_type=DEFAULT_MEDIA_TYPE
    )
    assert neutral_decode(HttpReply(status=206, body=b"x"))["status"] == "partial"


def test_a_2xx_body_is_preserved_rather_than_discarded() -> None:
    """A cursor this module cannot read must still be readable by someone."""

    body = b'{"value":[1,2,3],"@odata.nextLink":"https://x/next"}'
    detail = neutral_decode_detail(HttpReply(status=200, body=body))
    assert detail.body == body
    assert detail.cursor_determined is False
    # 204 has no body by definition, so nothing is being hidden there.
    assert neutral_decode_detail(HttpReply(status=204, body=b"ignored")).body == b""


def test_a_real_204_and_a_real_206_off_the_wire_decode_correctly(
    trust_loopback: Tuple[Path, Path],
) -> None:
    """The statuses come from a real server, not a hand-built HttpReply."""

    certfile, keyfile = trust_loopback
    rec = _Recorder()
    handler = _handler_for(rec, reply=lambda: (204, {}, b""))
    with _https_server(handler, certfile, keyfile) as port:
        reply_204 = urllib_http_send(
            HttpRequest(method="GET", url=f"https://localhost:{port}/empty", headers={}),
            timeout_seconds=10.0,
        )
    assert reply_204.status == 204 and reply_204.body == b""
    assert neutral_decode_detail(reply_204).content_kind == "no_content"
    assert neutral_decode(reply_204) == {"status": "ok", "next_cursor": None, "payload": None}

    rec206 = _Recorder()
    handler206 = _handler_for(
        rec206,
        reply=lambda: (206, {"Content-Range": "items 0-0/9"}, b'{"value":[1]}'),
    )
    with _https_server(handler206, certfile, keyfile) as port:
        reply_206 = urllib_http_send(
            HttpRequest(method="GET", url=f"https://localhost:{port}/page", headers={}),
            timeout_seconds=10.0,
        )
    assert reply_206.status == 206
    detail = neutral_decode_detail(reply_206)
    assert detail.result["status"] == "partial"
    assert detail.body == b'{"value":[1]}'
    assert detail.cursor_determined is False
    # A real 206 off the wire carries its fragment's bytes to the consumer.
    payload = detail.result["payload"]
    assert isinstance(payload, BytesPayload) and payload.data == b'{"value":[1]}'


def test_the_transport_surfaces_the_partial_reading_for_a_body_bearing_2xx(
    real_vault: RecordingVault, trust_loopback: Tuple[Path, Path]
) -> None:
    certfile, keyfile = trust_loopback
    rec = _Recorder()
    handler = _handler_for(rec, reply=lambda: (200, {}, b'{"value":[1,2]}'))
    with _https_server(handler, certfile, keyfile) as port:
        handle = _handle(_binding())
        transport = build_production_transport(
            selector=_selector_for(handle),
            vault=real_vault,
            locator=_locator_to(f"https://localhost:{port}/v1/me/messages"),
        )
        outcome = execute(_descriptor(), handle, transport, **_kw())
    assert outcome.result is not None
    # `ok` would have asserted completeness nobody established.
    assert outcome.result["status"] == "partial"
    assert outcome.result["next_cursor"] is None


# =============================================================================
# DEFECT D -- an ambiguous outcome is recorded as ambiguous
# =============================================================================
def _write_descriptor() -> OperationDescriptor:
    return {
        "operation_id": "outlook.messages.send",
        "service_id": "outlook",
        "operation_kind": "mutation",
        "effect": "external_send",
        "credential_modes": ("oauth_user",),
    }


def test_a_real_connection_failure_on_a_write_records_unknown_not_not_applied(
    real_vault: RecordingVault,
) -> None:
    """A REAL refused TCP connection, on a port nothing is listening on."""

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    handle = _handle(_binding(), requested=("mail.send",))
    transport = build_production_transport(
        selector=_selector_for(handle),
        vault=real_vault,
        locator=_locator_to(f"https://localhost:{dead_port}/sendMail", method="POST", body=b"{}"),
    )
    outcome = execute(
        _write_descriptor(),
        handle,
        transport,
        request_idempotency_key="idem-1",
        **_kw(governance_item="messages.send"),
    )
    assert outcome.error is not None
    assert outcome.error["error_class"] == "temporary"
    # The point: NOT a determinate "did not apply".
    assert outcome.write_outcome == ATTEMPT_UNKNOWN
    assert outcome.write_outcome != ATTEMPT_FAILED_NOT_APPLIED


def test_feeding_that_unknown_into_l07_refuses_a_blind_replay(
    real_vault: RecordingVault,
) -> None:
    """The whole reason the field exists: L07 must see `unknown`, not a guess."""

    def _timeout_send(request: HttpRequest, *, timeout_seconds: float) -> HttpReply:
        raise urllib.error.URLError(TimeoutError("timed out"))

    descriptor = _write_descriptor()
    handle = _handle(_binding(), requested=("mail.send",))
    transport = build_production_transport(
        selector=_selector_for(handle),
        vault=real_vault,
        locator=_locator_to("https://graph.example.invalid/v1/me/sendMail", method="POST"),
        http_send=_timeout_send,
    )
    args = {"to": "someone@example.invalid"}
    outcome = execute(
        descriptor,
        handle,
        transport,
        request_args=args,
        request_idempotency_key="idem-7",
        **_kw(governance_item="messages.send"),
    )
    assert outcome.write_outcome == ATTEMPT_UNKNOWN

    # Record exactly what the transport reported, then ask L07 to replay.
    record = record_attempt(
        operation_id=descriptor["operation_id"],
        args_fingerprint=args_fingerprint(args),
        idempotency_key="idem-7",
        # The literal is what mypy needs; the assert above pins it == ATTEMPT_UNKNOWN.
        outcome="unknown",
    )
    refused = replay_decision(
        descriptor, record, request_args=args, request_idempotency_key="idem-7"
    )
    assert refused["verdict"] == REPLAY_REFUSE

    # And the counterfactual that makes the defect concrete: had the transport
    # reported the old determinate 503 as "not applied", L07 would have ALLOWED
    # the second sendMail.
    misrecorded = record_attempt(
        operation_id=descriptor["operation_id"],
        args_fingerprint=args_fingerprint(args),
        idempotency_key="idem-7",
        outcome="failed_not_applied",  # == ATTEMPT_FAILED_NOT_APPLIED, pinned below
    )
    assert ATTEMPT_FAILED_NOT_APPLIED == "failed_not_applied"
    assert ATTEMPT_UNKNOWN == "unknown"
    assert (
        replay_decision(
            descriptor, misrecorded, request_args=args, request_idempotency_key="idem-7"
        )["verdict"]
        == REPLAY_ALLOW
    )


def test_a_read_never_claims_an_unknown_write_outcome(real_vault: RecordingVault) -> None:
    def _timeout_send(request: HttpRequest, *, timeout_seconds: float) -> HttpReply:
        raise urllib.error.URLError(TimeoutError("timed out"))

    handle = _handle(_binding())
    transport = build_production_transport(
        selector=_selector_for(handle),
        vault=real_vault,
        locator=_locator_to("https://graph.example.invalid/v1/me/messages"),
        http_send=_timeout_send,
    )
    outcome = execute(_descriptor(), handle, transport, **_kw())
    assert outcome.error is not None and outcome.error["error_class"] == "temporary"
    assert outcome.write_outcome is None
    assert is_non_idempotent_effect("read") is False


@pytest.mark.parametrize("status", [502, 503, 504])
def test_a_gateway_status_on_a_write_is_also_unknown(
    real_vault: RecordingVault, status: int
) -> None:
    """A failure in transit reached no end-to-end verdict either."""

    def _send(request: HttpRequest, *, timeout_seconds: float) -> HttpReply:
        return HttpReply(status=status, body=b"")

    handle = _handle(_binding(), requested=("mail.send",))
    transport = build_production_transport(
        selector=_selector_for(handle),
        vault=real_vault,
        locator=_locator_to("https://graph.example.invalid/v1/me/sendMail", method="POST"),
        http_send=_send,
    )
    outcome = execute(
        _write_descriptor(),
        handle,
        transport,
        request_idempotency_key="idem-2",
        **_kw(governance_item="messages.send"),
    )
    assert outcome.write_outcome == ATTEMPT_UNKNOWN


def test_a_pre_send_refusal_stays_determinate(real_vault: RecordingVault) -> None:
    """Nothing left the process, so the outcome is NOT uncertain.

    Over-reporting `unknown` is safe but not free: it blocks a replay the caller
    is entitled to. A refusal raised before a socket exists is determinate and
    says so.
    """

    handle = _handle(_binding(), requested=("mail.send",))
    transport = build_production_transport(
        selector=_selector_for(handle),
        vault=real_vault,
        locator=_locator_to("http://graph.example.invalid/v1/me/sendMail", method="POST"),
    )
    outcome = execute(
        _write_descriptor(),
        handle,
        transport,
        request_idempotency_key="idem-3",
        **_kw(governance_item="messages.send"),
    )
    assert outcome.error is not None and outcome.error["error_class"] == "input"
    assert outcome.write_outcome is None


def test_a_real_response_over_the_size_cap_is_refused(trust_loopback: Tuple[Path, Path]) -> None:
    certfile, keyfile = trust_loopback
    rec = _Recorder()
    oversize = b"x" * 4096
    handler = _handler_for(rec, reply=lambda: (200, {}, oversize))
    with _https_server(handler, certfile, keyfile) as port:
        # Under the cap: fine.
        ok = urllib_http_send(
            HttpRequest(method="GET", url=f"https://localhost:{port}/big", headers={}),
            timeout_seconds=10.0,
            max_response_bytes=4096,
        )
        assert len(ok.body) == 4096
        # One byte under what the server sends: refused, not truncated.
        with pytest.raises(ResponseTooLargeError) as caught:
            urllib_http_send(
                HttpRequest(method="GET", url=f"https://localhost:{port}/big", headers={}),
                timeout_seconds=10.0,
                max_response_bytes=4095,
            )
    assert "4095-byte cap" in str(caught.value)


def test_an_oversize_response_on_a_write_is_unknown(real_vault: RecordingVault) -> None:
    def _send(request: HttpRequest, *, timeout_seconds: float) -> HttpReply:
        raise ResponseTooLargeError("too big")

    handle = _handle(_binding(), requested=("mail.send",))
    transport = build_production_transport(
        selector=_selector_for(handle),
        vault=real_vault,
        locator=_locator_to("https://graph.example.invalid/v1/me/sendMail", method="POST"),
        http_send=_send,
    )
    outcome = execute(
        _write_descriptor(),
        handle,
        transport,
        request_idempotency_key="idem-4",
        **_kw(governance_item="messages.send"),
    )
    assert outcome.write_outcome == ATTEMPT_UNKNOWN


def test_the_overall_deadline_cuts_off_a_real_read(trust_loopback: Tuple[Path, Path]) -> None:
    """The deadline is enforced against a real socket, on an injected clock.

    The clock is injected rather than slept through so the test is deterministic
    and fast; everything else -- the TLS connection, the response, the read loop
    -- is real.
    """

    certfile, keyfile = trust_loopback
    rec = _Recorder()
    handler = _handler_for(rec, reply=lambda: (200, {}, b"y" * 256))
    ticks = iter([0.0, 0.0, 10_000.0, 10_000.0, 10_000.0])

    def _clock() -> float:
        try:
            return next(ticks)
        except StopIteration:
            return 10_000.0

    with _https_server(handler, certfile, keyfile) as port:
        with pytest.raises(TransportDeadlineExceededError) as caught:
            urllib_http_send(
                HttpRequest(method="GET", url=f"https://localhost:{port}/slow", headers={}),
                timeout_seconds=10.0,
                deadline_seconds=30.0,
                monotonic=_clock,
            )
    assert "deadline elapsed while reading" in str(caught.value)


def test_the_deadline_is_checked_before_the_request_is_even_opened() -> None:
    """An already-elapsed budget must not open a connection at all."""

    ticks = iter([0.0, 100.0])

    def _clock() -> float:
        try:
            return next(ticks)
        except StopIteration:
            return 100.0

    with pytest.raises(TransportDeadlineExceededError) as caught:
        urllib_http_send(
            HttpRequest(method="GET", url="https://127.0.0.1:1/never", headers={}),
            deadline_seconds=10.0,
            monotonic=_clock,
        )
    assert "before the request was opened" in str(caught.value)


def test_a_deadline_timeout_on_a_write_is_unknown(real_vault: RecordingVault) -> None:
    def _send(request: HttpRequest, *, timeout_seconds: float) -> HttpReply:
        raise TransportDeadlineExceededError("out of budget")

    handle = _handle(_binding(), requested=("mail.send",))
    transport = build_production_transport(
        selector=_selector_for(handle),
        vault=real_vault,
        locator=_locator_to("https://graph.example.invalid/v1/me/sendMail", method="POST"),
        http_send=_send,
    )
    outcome = execute(
        _write_descriptor(),
        handle,
        transport,
        request_idempotency_key="idem-5",
        **_kw(governance_item="messages.send"),
    )
    assert outcome.write_outcome == ATTEMPT_UNKNOWN


# =============================================================================
# the numbers and the schema versions the downstreams pin
# =============================================================================
def test_the_two_bounds_have_concrete_documented_numbers() -> None:
    assert DEFAULT_DEADLINE_SECONDS == 60.0
    assert DEFAULT_MAX_RESPONSE_BYTES == 8 * 1024 * 1024
    # The deadline is the ceiling: it must exceed one socket operation's timeout,
    # or the per-op timeout could never be reached and would be decorative.
    from kiro_crew.connections.control_plane.production import DEFAULT_TIMEOUT_SECONDS

    assert DEFAULT_DEADLINE_SECONDS > DEFAULT_TIMEOUT_SECONDS


def test_both_schema_versions_were_bumped_for_these_shape_changes() -> None:
    # TransportResponse/ExecutionOutcome grew write_outcome and the Transport
    # contract grew trusted_view; the composition signature changed. Then the
    # success envelope grew a payload, which moved the executor to 3 (see
    # RESULT_SCHEMA_VERSION 2).
    #
    # All three then moved again, for two changes:
    #   * the cursor is SINGLE-SOURCED -- CollectionPayload.next_cursor is gone and
    #     result_with_payload takes an explicit next_cursor -- so RESULT went to 3,
    #     and the executor to 4 because a 3-era producer that set the cursor only on
    #     the collection now silently builds a one-page walk;
    #   * response metadata reaches a caller through an ALLOWLIST on
    #     TransportResponse.metadata / ExecutionOutcome.metadata, which is a new
    #     executor field (4) AND new behaviour in this module's transport on every
    #     reply branch, so PRODUCTION went to 3 as well. Unlike the payload -- which
    #     was a change in the L01 envelope this module merely returns -- the metadata
    #     is populated HERE, from this module's own allowlist.
    assert EXECUTOR_SCHEMA_VERSION == 4
    assert RESULT_SCHEMA_VERSION == 3
    assert PRODUCTION_SCHEMA_VERSION == 3


def test_the_production_symbols_stay_off_the_connections_top_level() -> None:
    import kiro_crew.connections as connections
    import kiro_crew.connections.control_plane as cp

    for name in (
        "BindingIdentityMismatchError",
        "BindingSecretSelector",
        "DEFAULT_DEADLINE_SECONDS",
        "DEFAULT_MAX_RESPONSE_BYTES",
        "Decoded2xx",
        "RedirectHop",
        "RedirectRefusedError",
        "ResponseTooLargeError",
        "TransportDeadlineExceededError",
        "is_non_idempotent_effect",
        "neutral_decode_detail",
    ):
        assert hasattr(cp, name), name
        assert name in cp.__all__, name
        assert name not in connections.__all__, f"{name} leaked into connections.__all__"
