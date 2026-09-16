"""W11-C: a Zoom meetings operation ACTUALLY invoked -- located, dispatched
through W01's real executor and transport, decoded, host-verified, and paged --
with no naked sender.

The load-bearing tests drive real
:func:`~kiro_crew.connections.control_plane.production.urllib_http_send` over a
self-signed HTTPS loopback server:

* :func:`test_real_create_over_tls_readback_verifies_host` -- a ``create`` whose
  controlled TLS server returns a meeting object with ``host_id`` equal to the
  requested target, driven through the UNMODIFIED transport; the host-readback
  gate then reports ``verified``. NO real Zoom account, token, or business
  meeting is touched -- the "create" hits a loopback echo.
* :func:`test_real_list_across_two_pages_over_tls` -- a real
  :class:`~kiro_crew.connections.control_plane.executor.PageWalk` of
  ``zoom.meetings.list`` where page 1 carries a body ``next_page_token`` and page
  2 does not, a genuine two-page structured fetch with the cursor threaded
  through W01's single-authoritative ``next_cursor``.

Custody in both is the REAL, isolated, encrypted
:class:`~kiro_crew.secrets.SecretVault`.

The rest prove the pieces in isolation with an injected fake sender (still going
through W01's real transport -- the fake replaces only the socket at the bottom,
never the auth/custody/decode chain): the locator shapes correctly and refuses a
shaping fault, the decoder reads the cursor list and the single object honestly,
the descriptor projection is faithful, the host-readback gate catches a
mismatch and stays unknown on absence, and an uncertain write outcome is carried
as L07 ``unknown`` (never blind-replayed).
"""

from __future__ import annotations

import datetime
import http.server
import ipaddress
import json
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes
from kiro_crew.connections.control_plane.binding import (
    Binding,
    VerifiedIdentity,
    create_binding,
)
from kiro_crew.connections.control_plane.executor import ExecutionOutcome, TransportResponse
from kiro_crew.connections.control_plane.handle import (
    DerivedHandle,
    derive_handle,
    ensure_usable,
)
from kiro_crew.connections.control_plane.lifecycle import BindingStore
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    BindingCustodyGate,
    HttpReply,
    urllib_http_send,
)
from kiro_crew.connections.control_plane.result import (
    CollectionPayload,
    ObjectPayload,
    result_with_payload,
)
from kiro_crew.connections.control_plane.writes import (
    ATTEMPT_FAILED_NOT_APPLIED,
    ATTEMPT_SUCCEEDED,
    ATTEMPT_UNKNOWN,
)
from kiro_crew.connections.vendors.zoom.decoder import (
    ZoomDecodeError,
    decode_list_page,
    decode_single,
    readback_host_id,
)
from kiro_crew.connections.vendors.zoom.dispatch import (
    ZOOM_SERVICE_ID,
    ZOOM_SLUG,
    ZoomDispatchError,
    assert_schema_versions,
    attempt_from_outcome,
    build_zoom_transport,
    control_plane_descriptor,
    decode_for,
    dispatch_operation,
    open_page_walk,
    verify_created_host,
    walk_pages,
)
from kiro_crew.connections.vendors.zoom.identity import HOST_REACHABILITY_UNKNOWN
from kiro_crew.connections.vendors.zoom.locator import (
    CURSOR_ARG,
    ZOOM_API_BASE,
    ZoomLocatorError,
    build_request,
    locate,
)
from kiro_crew.connections.vendors.zoom.meetings import (
    OP_CREATE,
    OP_GET,
    OP_LIST,
    OP_UPDATE,
)
from kiro_crew.secrets import SecretVault

_T0 = 1_000_000.0
_GRANTED: Tuple[str, ...] = ("meeting:read", "meeting:write")
_TARGET_HOST = "host_ABC123"


# =============================================================================
# control-plane fixtures (real binding / handle / gate / store, Zoom service)
# =============================================================================
def _verifier(*, claimed_subject: str, claimed_tenant: str, service_id: str) -> VerifiedIdentity:
    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


def _binding(*, subject: str = "alice", tenant: str = "acme") -> Binding:
    return create_binding(
        service_id="zoom",
        claimed_subject=subject,
        claimed_tenant=tenant,
        credential_mode="service_to_service",
        verifier=_verifier,
        slug=ZOOM_SLUG,
    )


def _handle(binding: Binding, *, requested: Tuple[str, ...] = ("meeting:write",)) -> DerivedHandle:
    return derive_handle(
        binding,
        granted_scopes=_GRANTED,
        requested_scopes=requested,
        now=_T0,
        ttl_seconds=3600.0,
    )


def _gate_for(binding: Binding, handle: DerivedHandle) -> BindingCustodyGate:
    view = ensure_usable(handle, now=_T0)
    return BindingCustodyGate(binding=binding, binding_fingerprint=view.binding_fingerprint)


def _store_for(root: Path, *bindings: Binding) -> BindingStore:
    store = BindingStore(root / "connections" / "control_plane_bindings.json")
    for index, binding in enumerate(bindings):
        store.insert(
            binding,
            deployment_id=f"deployment://test/zoom/{index}",
            kiro_principal="kiro://test/owner",
        )
    return store


def _gate_kwargs(**over: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = dict(
        offered_mode="service_to_service",
        permitted=declare_permitted_modes(("service_to_service",)),
        layers=LayerCeilings(),  # ungoverned == permit
        governance_scope="tools",
        governance_item="meetings",
    )
    base.update(over)
    return base


@pytest.fixture
def real_vault(tmp_path: Path) -> SecretVault:
    # An empty, real, encrypted vault. The secret is seeded per test under the
    # BINDING'S OWN secret_ref name (`_seed_vault`), because the executor's
    # `select_secret` reads the per-binding name off the live store record --
    # NOT the legacy slug-collapsed `binding_secret_ref` name. Seeding by slug
    # would leave the per-binding name absent and the fence would 401.
    return SecretVault(tmp_path / "crewhome")


def _seed_vault(vault: SecretVault, binding: Binding, value: str = "zoom-s2s-access-token") -> str:
    """Seed the vault under the binding's OWN secret_ref name; return that name.

    ``create_binding`` mints a per-binding secret_ref (``CONNECTIONS_ZOOM_
    BINDING_<id>_SECRET``), and ``store.select_secret`` resolves the credential
    by that trusted per-binding name off the live store, never the slug-collapsed
    one. So the vault must hold the value under exactly this name.
    """

    name = binding["secret_ref"]["name"]
    vault.set_sync(name, value)
    return name


# =============================================================================
# a REAL HTTPS loopback server (self-signed, minted per test)
# =============================================================================
def _tls_material(tmp_path: Path) -> Tuple[Path, Path]:
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
    certfile = tmp_path / "loopback-cert.pem"
    keyfile = tmp_path / "loopback-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


class _Recorder:
    def __init__(self) -> None:
        self.requests: List[Dict[str, str]] = []
        self.paths: List[str] = []
        self.bodies: List[bytes] = []


def _create_handler(recorder: _Recorder):
    """A handler that ECHOES a created meeting with a fixed ``host_id``.

    A ``POST`` returns a Zoom-shaped meeting object whose ``host_id`` equals the
    target under test, so the host-readback gate can verify. Nothing real is
    created -- this is a loopback echo, never a Zoom account.
    """

    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802 - stdlib name
            length = int(self.headers.get("Content-Length", "0"))
            recorder.bodies.append(self.rfile.read(length) if length else b"")
            recorder.requests.append({k: v for k, v in self.headers.items()})
            recorder.paths.append(self.path)
            body = json.dumps(
                {"id": 998877, "host_id": _TARGET_HOST, "topic": "Sync", "status": "waiting"}
            ).encode("utf-8")
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            return

    return _H


def _paging_handler(recorder: _Recorder):
    """A handler that pages: page 1 carries a body ``next_page_token``, page 2 none."""

    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802 - stdlib name
            recorder.requests.append({k: v for k, v in self.headers.items()})
            recorder.paths.append(self.path)
            if "next_page_token=tok2" in self.path:
                payload = {"meetings": [{"id": 2, "topic": "second"}], "next_page_token": ""}
            else:
                payload = {"meetings": [{"id": 1, "topic": "first"}], "next_page_token": "tok2"}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
# THE load-bearing tests: real create + real two-page list over real TLS
# =============================================================================
def test_real_create_over_tls_readback_verifies_host(
    tmp_path: Path, real_vault: SecretVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))

    rec = _Recorder()
    handler = _create_handler(rec)

    binding = _binding()
    handle = _handle(binding)
    gate = _gate_for(binding, handle)
    store = _store_for(tmp_path, binding)
    _seed_vault(real_vault, binding)

    with _https_server(handler, certfile, keyfile) as port:
        import kiro_crew.connections.vendors.zoom.locator as zoom_locator

        monkeypatch.setattr(zoom_locator, "ZOOM_API_BASE", f"https://localhost:{port}")

        transport = build_zoom_transport(
            operation_id=OP_CREATE,
            gate=gate,
            store=store,
            vault=real_vault,
            http_send=urllib_http_send,
        )
        outcome = dispatch_operation(
            operation_id=OP_CREATE,
            handle=handle,
            transport=transport,
            request_args={"user_id": "me", "topic": "Sync"},
            clock=lambda: _T0,
            **_gate_kwargs(),
        )

    # The write went out over real TLS through the UNMODIFIED transport.
    assert rec.paths == ["/users/me/meetings"]
    assert outcome.ok
    assert isinstance(outcome.payload, ObjectPayload)
    # Host readback verifies: the response host_id equals the requested target.
    verification = verify_created_host(outcome, _TARGET_HOST)
    assert verification.verified is True
    assert verification.reachability == "verified"
    # A DIFFERENT target is a mismatch, not silently accepted.
    assert verify_created_host(outcome, "host_OTHER").verified is False
    assert verify_created_host(outcome, "host_OTHER").reachability == "mismatch"


def test_real_list_across_two_pages_over_tls(
    tmp_path: Path, real_vault: SecretVault, monkeypatch: pytest.MonkeyPatch
) -> None:
    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))

    rec = _Recorder()
    handler = _paging_handler(rec)

    binding = _binding()
    handle = _handle(binding, requested=("meeting:read",))
    gate = _gate_for(binding, handle)
    store = _store_for(tmp_path, binding)
    _seed_vault(real_vault, binding)

    with _https_server(handler, certfile, keyfile) as port:
        import kiro_crew.connections.vendors.zoom.locator as zoom_locator

        monkeypatch.setattr(zoom_locator, "ZOOM_API_BASE", f"https://localhost:{port}")

        transport = build_zoom_transport(
            operation_id=OP_LIST,
            gate=gate,
            store=store,
            vault=real_vault,
            http_send=urllib_http_send,
        )
        walk = open_page_walk(
            operation_id=OP_LIST,
            handle=handle,
            transport=transport,
            base_args={"user_id": "me", "page_size": 30},
            clock=lambda: _T0,
            **_gate_kwargs(offered_mode="service_to_service"),
        )
        outcomes = walk_pages(walk)

    assert len(outcomes) == 2
    assert all(o.ok for o in outcomes)
    # Page 1 carried the cursor on the SINGLE authoritative next_cursor.
    assert outcomes[0].result is not None and outcomes[0].result["next_cursor"] == "tok2"
    assert outcomes[1].result is not None and outcomes[1].result["next_cursor"] is None
    # Page 2's request carried the cursor as next_page_token, plus base filters.
    assert any("next_page_token=tok2" in p for p in rec.paths)
    # Rows landed in the neutral collection channel.
    assert isinstance(outcomes[0].payload, CollectionPayload)
    assert outcomes[0].payload.items[0]["topic"] == "first"


# =============================================================================
# guard for the guards
# =============================================================================
def test_the_vault_under_test_is_the_real_encrypted_store(
    tmp_path: Path, real_vault: SecretVault
) -> None:
    binding = _binding()
    name = _seed_vault(real_vault, binding)
    store = tmp_path / "crewhome" / ".vault" / "secrets.enc"
    assert store.is_file()
    assert b"zoom-s2s-access-token" not in store.read_bytes()
    value = real_vault.get(name)
    assert value is not None and value.reveal() == "zoom-s2s-access-token"


# =============================================================================
# schema pins
# =============================================================================
def test_schema_versions_match_pins() -> None:
    # Composes only if the W01 seam is the version this dispatch was built for.
    assert_schema_versions()


# =============================================================================
# descriptor projection
# =============================================================================
class TestControlPlaneDescriptor:
    def test_projects_the_four_operations(self) -> None:
        for op, kind, effect in (
            (OP_LIST, "list", "read"),
            (OP_GET, "single_fetch", "read"),
            (OP_CREATE, "mutation", "write"),
            (OP_UPDATE, "mutation", "write"),
        ):
            d = control_plane_descriptor(op)
            assert d["operation_id"] == op
            assert d["service_id"] == ZOOM_SERVICE_ID == "zoom"
            assert d["operation_kind"] == kind
            assert d["effect"] == effect
            assert d["credential_modes"] == ("oauth_user", "service_to_service")

    def test_unknown_operation_refused(self) -> None:
        with pytest.raises(ZoomDispatchError):
            control_plane_descriptor("zoom.meetings.delete")


# =============================================================================
# decoder selection + decode
# =============================================================================
class TestDecoder:
    def test_decode_for_list_is_collection(self) -> None:
        assert decode_for(OP_LIST) is decode_list_page

    def test_decode_for_reads_and_mutations_are_single(self) -> None:
        assert decode_for(OP_GET) is decode_single
        assert decode_for(OP_CREATE) is decode_single
        assert decode_for(OP_UPDATE) is decode_single

    def test_decode_for_unknown_refused(self) -> None:
        with pytest.raises(ZoomDispatchError):
            decode_for("zoom.meetings.delete")

    def test_list_page_folds_next_page_token_to_cursor(self) -> None:
        reply = HttpReply(
            status=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"meetings": [{"id": 1}], "next_page_token": "abc"}).encode(),
        )
        result = decode_list_page(reply)
        assert result["next_cursor"] == "abc"
        assert result["status"] == "partial"
        assert isinstance(result["payload"], CollectionPayload)
        assert result["payload"].items[0]["id"] == 1

    def test_list_page_empty_token_is_terminal(self) -> None:
        reply = HttpReply(
            status=200,
            body=json.dumps({"meetings": [{"id": 2}], "next_page_token": ""}).encode(),
        )
        result = decode_list_page(reply)
        assert result["next_cursor"] is None
        assert result["status"] == "ok"

    def test_list_page_malformed_meetings_is_decode_error(self) -> None:
        reply = HttpReply(status=200, body=json.dumps({"meetings": "notalist"}).encode())
        with pytest.raises(ZoomDecodeError):
            decode_list_page(reply)

    def test_single_object_has_no_cursor(self) -> None:
        reply = HttpReply(status=200, body=json.dumps({"id": 5, "host_id": "h"}).encode())
        result = decode_single(reply)
        assert result["next_cursor"] is None
        assert isinstance(result["payload"], ObjectPayload)
        assert result["payload"].object["host_id"] == "h"

    def test_single_empty_ack_is_none_payload(self) -> None:
        # an update 204-style ack: no object, not a forced empty object.
        result = decode_single(HttpReply(status=204, body=b""))
        assert result["payload"] is None
        assert result["next_cursor"] is None

    def test_readback_host_id_reads_object_host(self) -> None:
        reply = HttpReply(status=201, body=json.dumps({"host_id": "hZ"}).encode())
        assert readback_host_id(reply) == "hZ"

    def test_readback_host_id_absent_is_none(self) -> None:
        assert readback_host_id(HttpReply(status=201, body=json.dumps({"id": 1}).encode())) is None


# =============================================================================
# locator shaping (still through pure logic; no socket)
# =============================================================================
class TestLocator:
    def test_list_builds_cursor_list_url(self) -> None:
        req = build_request(OP_LIST, {"user_id": "me", "page_size": 50})
        assert req.method == "GET"
        assert req.url == f"{ZOOM_API_BASE}/users/me/meetings?page_size=50"
        assert req.body is None

    def test_list_carries_cursor_as_next_page_token(self) -> None:
        req = build_request(OP_LIST, {"user_id": "me", CURSOR_ARG: "tokX"})
        assert "next_page_token=tokX" in req.url

    def test_get_numeric_id_in_path_no_cursor(self) -> None:
        req = build_request(OP_GET, {"meeting_id": "97763643886"})
        assert req.url == f"{ZOOM_API_BASE}/meetings/97763643886"

    def test_create_posts_json_body_no_credential_header(self) -> None:
        req = build_request(
            OP_CREATE,
            {
                "user_id": "me",
                "topic": "T",
                "start_time": "2022-03-25T07:46:00Z",
                "timezone": "UTC",
            },
        )
        assert req.method == "POST"
        assert req.body is not None
        body = json.loads(req.body.decode())
        assert body["topic"] == "T"
        assert body["timezone"] == "UTC"
        # no credential header on a locator-built request
        assert not any(k.lower() == "authorization" for k in req.headers)

    def test_update_with_occurrence_id_targets_single(self) -> None:
        req = build_request(OP_UPDATE, {"meeting_id": "1", "occurrence_id": "occ99", "topic": "x"})
        assert req.method == "PATCH"
        assert "occurrence_id=occ99" in req.url

    def test_update_missing_occurrence_id_no_query(self) -> None:
        req = build_request(OP_UPDATE, {"meeting_id": "1", "topic": "x"})
        assert "occurrence_id" not in req.url

    def test_missing_required_param_refused(self) -> None:
        with pytest.raises(ZoomLocatorError):
            build_request(OP_LIST, {})

    def test_unknown_operation_refused(self) -> None:
        with pytest.raises(ZoomLocatorError):
            build_request("zoom.meetings.delete", {"meeting_id": "1"})

    def test_bad_page_size_refused(self) -> None:
        with pytest.raises(ZoomLocatorError):
            build_request(OP_LIST, {"user_id": "me", "page_size": 0})

    def test_locate_keyword_surface_resolves_operation_from_descriptor(self) -> None:
        req = locate(
            service_id="zoom",
            credential_mode="service_to_service",
            descriptor=control_plane_descriptor(OP_GET),
            request_args={"meeting_id": "5"},
        )
        assert req.url == f"{ZOOM_API_BASE}/meetings/5"

    def test_locate_refuses_non_zoom_service(self) -> None:
        with pytest.raises(ZoomLocatorError):
            locate(
                service_id="github",
                credential_mode="service_to_service",
                descriptor=control_plane_descriptor(OP_GET),
                request_args={"meeting_id": "5"},
            )


# =============================================================================
# host readback gate over an outcome (unit, no socket)
# =============================================================================
def _object_outcome(host_id: Optional[str]) -> ExecutionOutcome:
    obj = {"id": 1}
    if host_id is not None:
        obj["host_id"] = host_id
    return ExecutionOutcome(result=result_with_payload(ObjectPayload(object=obj), status="ok"))


class TestHostReadbackGate:
    def test_matching_host_verified(self) -> None:
        v = verify_created_host(_object_outcome("hT"), "hT")
        assert v.verified is True and v.reachability == "verified"

    def test_mismatched_host_not_verified(self) -> None:
        v = verify_created_host(_object_outcome("hOther"), "hT")
        assert v.verified is False and v.reachability == "mismatch"

    def test_absent_readback_host_unknown(self) -> None:
        v = verify_created_host(_object_outcome(None), "hT")
        assert v.verified is False and v.reachability == HOST_REACHABILITY_UNKNOWN

    def test_absent_target_unknown(self) -> None:
        v = verify_created_host(_object_outcome("hT"), None)
        assert v.reachability == HOST_REACHABILITY_UNKNOWN

    def test_non_success_outcome_unknown(self) -> None:
        # a transport-error outcome carries no object -> unknown, never verified.
        from kiro_crew.connections.control_plane.errors import operation_error

        err_outcome = ExecutionOutcome(error=operation_error("temporary", "boom"))
        v = verify_created_host(err_outcome, "hT")
        assert v.verified is False and v.reachability == HOST_REACHABILITY_UNKNOWN


# =============================================================================
# write-replay: uncertain outcome carried as L07 unknown, never blind-replayed
# =============================================================================
class TestAttemptFromOutcome:
    def test_uncertain_write_is_unknown(self) -> None:
        # the transport reported write_outcome=unknown (timeout / 5xx-transit).
        outcome = ExecutionOutcome(
            error=__import__(
                "kiro_crew.connections.control_plane.errors", fromlist=["operation_error"]
            ).operation_error("temporary", "timeout"),
            write_outcome=ATTEMPT_UNKNOWN,
        )
        record = attempt_from_outcome(
            operation_id=OP_CREATE,
            request_args={"user_id": "me", "topic": "T"},
            outcome=outcome,
        )
        assert record["outcome"] == ATTEMPT_UNKNOWN
        assert record["recorded_result"] is None
        # not asserted idempotent: a plain create must NOT be blind-replayed.
        assert record["idempotent"] is False

    def test_clean_success_is_succeeded_with_result(self) -> None:
        outcome = ExecutionOutcome(
            result=result_with_payload(ObjectPayload(object={"id": 1}), status="ok")
        )
        record = attempt_from_outcome(
            operation_id=OP_CREATE,
            request_args={"user_id": "me"},
            outcome=outcome,
        )
        assert record["outcome"] == ATTEMPT_SUCCEEDED
        assert record["recorded_result"] is not None

    def test_determinate_failure_is_failed_not_applied(self) -> None:
        from kiro_crew.connections.control_plane.errors import operation_error

        outcome = ExecutionOutcome(error=operation_error("input", "bad request"))
        record = attempt_from_outcome(
            operation_id=OP_CREATE,
            request_args={"user_id": "me"},
            outcome=outcome,
        )
        assert record["outcome"] == ATTEMPT_FAILED_NOT_APPLIED


# =============================================================================
# cursor-less refusal: only list opens a page walk
# =============================================================================
class TestPageWalkRefusal:
    def test_get_cannot_open_page_walk(self) -> None:
        binding = _binding()
        handle = _handle(binding)
        with pytest.raises(ZoomDispatchError):
            open_page_walk(
                operation_id=OP_GET,
                handle=handle,
                transport=lambda **kw: TransportResponse(http_status=200),
                base_args={"meeting_id": "1"},
                **_gate_kwargs(),
            )

    def test_create_cannot_open_page_walk(self) -> None:
        binding = _binding()
        handle = _handle(binding)
        with pytest.raises(ZoomDispatchError):
            open_page_walk(
                operation_id=OP_CREATE,
                handle=handle,
                transport=lambda **kw: TransportResponse(http_status=200),
                base_args={"user_id": "me"},
                **_gate_kwargs(),
            )
