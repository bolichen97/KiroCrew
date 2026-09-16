"""W06 · Graph optimistic-concurrency version-safe write protocol.

Coverage:
1. PURE-LOGIC unit tests of the protocol pieces.
2. A REAL SEQUENCE routed THROUGH W01's ``execute`` -- composed with a real
   encrypted ``SecretVault``, a real binding/handle, the two vendor seats, the
   D9 500-unknown wrapper, and W01's UNMODIFIED ``urllib_http_send`` over a
   self-signed TLS loopback. Every hop passes custody + gates; nothing calls a
   raw sender. This is the harness SHAPE W01 uses (read, not modified).

NOT LIVE (self-signed loopback, no real Graph, no cloud write). The auth chain is
W01's and is not complete; this only wires the version-safe write onto it.
CANDIDATE-ON-PARENT-BASE (cd00f1837; not on main).
"""

from __future__ import annotations

import datetime
import http.server
import json
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes
from kiro_crew.connections.control_plane.binding import (
    VerifiedIdentity,
    binding_secret_ref,
    create_binding,
)
from kiro_crew.connections.control_plane.executor import (
    ExecutionOutcome,
    execute,
)
from kiro_crew.connections.control_plane.handle import (
    derive_handle,
    ensure_usable,
)
from kiro_crew.connections.control_plane.operation import Effect, OperationDescriptor
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    HttpReply,
    HttpRequest,
    BindingSecretSelector,
    build_production_transport,
    urllib_http_send,
)
from kiro_crew.connections.control_plane.writes import ATTEMPT_UNKNOWN
from kiro_crew.secrets import SecretValue, SecretVault

from kiro_crew.connections.vendors.microsoft.graph.concurrency import (
    ARG_METHOD,
    ARG_PATH,
    FIELD_CTAG,
    FIELD_ID,
    ODATA_ETAG,
    ColumnKind,
    ConcurrencyError,
    ConcurrencyMode,
    Conflict,
    DispatchResult,
    FieldChange,
    VersionKind,
    VersionTag,
    WriteIntent,
    accepts_validator,
    baseline_conflict,
    conditional_write_args,
    decode_page,
    extract_version,
    graph_500_unknown_transport,
    graph_request_locator,
    graph_result_decode,
    has_412_contract,
    recover_from_precondition_failed,
    run_version_safe_write,
    supports_if_match,
    verify_read_back,
)

_ETAG_V1 = '"1"'
_ETAG_V2 = '"2"'
_ETAG_V3 = '"3"'
_RID = "7"
_T0 = 1_000_000.0
_PATH = "/sites/S/lists/L/items/7/fields"


def _intent(resource_id=_RID, **changes):
    return WriteIntent(
        resource_id=resource_id,
        changes={
            n: FieldChange(baseline=b, intended=i, column_kind=k)
            for n, (b, i, k) in changes.items()
        },
    )


def _reply(status, body=None, **headers):
    raw = b"" if body is None else json.dumps(body).encode()
    return HttpReply(status=status, headers=headers, body=raw)


# =============================================================================
# PURE-LOGIC unit tests
# =============================================================================
class TestVersionModesSeats:
    def test_extract_versions(self):
        assert extract_version({ODATA_ETAG: _ETAG_V1}) == VersionTag(VersionKind.ETAG, _ETAG_V1)
        assert extract_version({FIELD_CTAG: "c"}) == VersionTag(VersionKind.CTAG, "c")

    def test_per_endpoint_validators(self):
        assert accepts_validator(ConcurrencyMode.LISTITEM_ETAG, VersionKind.ETAG)
        assert not accepts_validator(ConcurrencyMode.LISTITEM_ETAG, VersionKind.CTAG)
        assert accepts_validator(ConcurrencyMode.DRIVEITEM_ETAG_OR_CTAG, VersionKind.CTAG)

    def test_412_contracts(self):
        assert has_412_contract(ConcurrencyMode.LISTITEM_ETAG)
        assert has_412_contract(ConcurrencyMode.DRIVEITEM_ETAG_OR_CTAG)
        assert not has_412_contract(ConcurrencyMode.NONE_LAST_WRITE_WINS)
        assert not supports_if_match(ConcurrencyMode.NONE_LAST_WRITE_WINS)

    def test_locator_seat_shapes_request_from_args(self):
        req = graph_request_locator(
            service_id="sharepoint",
            credential_mode="oauth_user",
            descriptor=_descriptor(),
            request_args={ARG_METHOD: "GET", ARG_PATH: _PATH},
            endpoint_host="graph.microsoft.com",
        )
        assert req.method == "GET" and req.url == f"https://graph.microsoft.com{_PATH}"
        assert "Authorization" not in req.headers  # transport owns credentials

    def test_conditional_write_args_refuses_excel(self):
        with pytest.raises(ConcurrencyError, match="last-write-wins"):
            conditional_write_args(
                ConcurrencyMode.NONE_LAST_WRITE_WINS,
                _PATH,
                VersionTag(VersionKind.ETAG, _ETAG_V1),
                _intent(Q=(1, 2, ColumnKind.SCALAR)),
            )

    def test_conditional_write_args_refuses_missing_version(self):
        with pytest.raises(ConcurrencyError, match="blind"):
            conditional_write_args(
                ConcurrencyMode.LISTITEM_ETAG, _PATH, None, _intent(Q=(1, 2, ColumnKind.SCALAR))
            )

    def test_sharepoint_refuses_ctag(self):
        with pytest.raises(ConcurrencyError, match="per-endpoint"):
            conditional_write_args(
                ConcurrencyMode.LISTITEM_ETAG,
                _PATH,
                VersionTag(VersionKind.CTAG, "c"),
                _intent(Q=(1, 2, ColumnKind.SCALAR)),
            )


class TestDecoderKeepsRows:
    """D10: the decoder must not drop a page's rows."""

    def test_decode_page_keeps_rows_and_cursor(self):
        link = "https://graph.microsoft.com/next?$skiptoken=abc"
        page = decode_page(
            _reply(200, {"value": [{"id": "1"}, {"id": "2"}], "@odata.nextLink": link})
        )
        assert page.result == {"status": "partial", "next_cursor": link}
        assert page.rows == [{"id": "1"}, {"id": "2"}]

    def test_decode_page_ok_without_cursor_keeps_rows(self):
        page = decode_page(_reply(200, {"value": [{"id": "1"}]}))
        assert page.result == {"status": "ok", "next_cursor": None}
        assert page.rows == [{"id": "1"}]

    def test_seat_returns_only_envelope_but_rows_reachable(self):
        env = graph_result_decode(_reply(200, {"value": [{"id": "1"}]}))
        assert env == {"status": "ok", "next_cursor": None}
        assert decode_page(_reply(200, {"value": [{"id": "1"}]})).rows == [{"id": "1"}]


class TestBaselineConflictBeforeWrite:
    """D7: compare baseline against the INITIAL GET's actual values."""

    def test_field_already_moved_is_conflict(self):
        # baseline 1, but the resource already shows 9 (a concurrent writer).
        c = baseline_conflict(
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            {FIELD_ID: _RID, ODATA_ETAG: _ETAG_V2, "Quantity": 9},
        )
        assert isinstance(c, Conflict) and c.moved_fields == ("Quantity",)

    def test_unchanged_field_is_no_conflict(self):
        assert (
            baseline_conflict(
                _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
                {FIELD_ID: _RID, ODATA_ETAG: _ETAG_V1, "Quantity": 1},
            )
            is None
        )

    def test_wrong_identity_is_conflict(self):
        c = baseline_conflict(
            _intent(resource_id=_RID, Quantity=(1, 2, ColumnKind.SCALAR)),
            {FIELD_ID: "999", "Quantity": 1},
        )
        assert isinstance(c, Conflict)


class TestRecoveryAndReadBack:
    def test_recovery_retries_when_unmoved(self):
        plan = recover_from_precondition_failed(
            ConcurrencyMode.LISTITEM_ETAG,
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            {FIELD_ID: _RID, ODATA_ETAG: _ETAG_V2, "Quantity": 1},
        )
        assert plan.should_retry and plan.fresh_version.value == _ETAG_V2

    def test_recovery_conflict_when_moved(self):
        plan = recover_from_precondition_failed(
            ConcurrencyMode.LISTITEM_ETAG,
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            {FIELD_ID: _RID, ODATA_ETAG: _ETAG_V2, "Quantity": 9},
        )
        assert not plan.should_retry and plan.conflict.moved_fields == ("Quantity",)

    def test_undocumented_column_refuses(self):
        with pytest.raises(ConcurrencyError, match="lookup"):
            recover_from_precondition_failed(
                ConcurrencyMode.LISTITEM_ETAG,
                _intent(Author=({"LookupId": 1}, {"LookupId": 2}, ColumnKind.LOOKUP)),
                {FIELD_ID: _RID, ODATA_ETAG: _ETAG_V2, "Author": {"LookupId": 1}},
            )

    def test_read_back_asserts_identity(self):
        v = verify_read_back(
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            {FIELD_ID: "999", "Quantity": 2},  # right value, WRONG resource
        )
        assert v.verified is False and v.identity_ok is False

    def test_read_back_verified_on_target(self):
        v = verify_read_back(
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            {FIELD_ID: _RID, "Quantity": 2},
        )
        assert v.verified is True and "not a claim that this write produced it" in v.reason


class TestColumnKindRequired:
    def test_field_change_requires_column_kind(self):
        with pytest.raises(TypeError):
            FieldChange(baseline=1, intended=2)  # type: ignore[call-arg]


# =============================================================================
# W01 composition helpers (read from W01's harness shape; W01 tests untouched).
# =============================================================================
def _verifier(*, claimed_subject: str, claimed_tenant: str, service_id: str) -> VerifiedIdentity:
    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


def _descriptor(effect: Effect = "write") -> OperationDescriptor:
    return {
        "operation_id": "sharepoint.listitem.update",
        "service_id": "sharepoint",
        "operation_kind": "mutation",
        "effect": effect,
        "credential_modes": ("oauth_user",),
    }


class _RecordingVault(SecretVault):
    def __init__(self, config_dir: Path) -> None:
        super().__init__(config_dir)
        self.asked: List[str] = []

    def get(self, name: str) -> Optional[SecretValue]:
        self.asked.append(name)
        return super().get(name)


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


class _Scripted:
    """A tiny stateful Graph-like list item served over the loopback."""

    def __init__(
        self,
        *,
        script: Callable[
            ["_Scripted", str, Optional[str], bytes], Tuple[int, Dict[str, str], bytes]
        ],
    ):
        self.requests: List[Dict[str, Any]] = []
        self.quantity = 1
        self.etag = _ETAG_V1
        self._patched = False
        self._script = script

    def handle(self, method, if_match, body):
        self.requests.append({"method": method, "if_match": if_match, "body": body})
        return self._script(self, method, if_match, body)


def _handler_for(state: _Scripted):
    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _do(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            status, headers, out = state.handle(self.command, self.headers.get("If-Match"), body)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            if status not in (204, 304):
                self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            if status not in (204, 304) and out:
                self.wfile.write(out)

        do_GET = _do
        do_PATCH = _do
        do_POST = _do

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


def _make_execute_dispatch(*, host: str, vault, selector, handle, descriptor):
    """Bind an execute-backed Dispatch composed from the two seats + the D9 wrapper.

    A capturing http_send wraps W01's real urllib_http_send so the orchestrator
    can read the reply BODY (the L01 result envelope carries no rows), WITHOUT
    bypassing anything: the capture only records the reply W01's transport
    already produced; custody, gates and the sender are all W01's.
    """
    import functools

    captured: Dict[str, Optional[HttpReply]] = {"reply": None}

    def _capturing_send(request: HttpRequest, **kw: Any) -> HttpReply:
        reply = urllib_http_send(request, **kw)
        captured["reply"] = reply
        return reply

    locator = functools.partial(graph_request_locator, endpoint_host=host)
    inner = build_production_transport(
        selector=selector,
        vault=vault,
        locator=locator,
        http_send=_capturing_send,
        decode=graph_result_decode,
    )
    transport = graph_500_unknown_transport(inner)

    def _dispatch(request_args: Mapping[str, Any]) -> DispatchResult:
        captured["reply"] = None
        outcome: ExecutionOutcome = execute(
            descriptor,
            handle,
            transport,
            now=_T0,
            offered_mode="oauth_user",
            permitted=declare_permitted_modes(("oauth_user",)),
            layers=LayerCeilings(),
            governance_scope="tools",
            governance_item="listitem.update",
            request_args=request_args,
        )
        reply = captured["reply"]
        body = None
        if reply is not None and 200 <= reply.status < 300:
            parsed = json.loads(reply.body) if reply.body else None
            body = parsed if isinstance(parsed, dict) else None
        return DispatchResult(outcome=outcome, body=body)

    return _dispatch


def _compose(tmp_path: Path):
    vault = _RecordingVault(tmp_path / "crewhome")
    vault.set_sync(binding_secret_ref("sharepoint")["name"], "sp-live-token")
    binding = create_binding(
        service_id="sharepoint",
        claimed_subject="alice",
        claimed_tenant="acme",
        credential_mode="oauth_user",
        verifier=_verifier,
        slug="sharepoint",
    )
    handle = derive_handle(
        binding,
        granted_scopes=("sites.rw",),
        requested_scopes=("sites.rw",),
        now=_T0,
        ttl_seconds=300.0,
    )
    view = ensure_usable(handle, now=_T0)
    selector = BindingSecretSelector(
        slug="sharepoint",
        binding_fingerprint=view.binding_fingerprint,
        service_id=view.service_id,
        credential_mode=view.credential_mode,
    )
    return vault, selector, handle


# =============================================================================
# REAL SEQUENCE through execute (D6): custody + gates on every hop.
# =============================================================================
def test_full_sequence_through_executor_applies_after_safe_retry(
    trust_loopback: Tuple[Path, Path], tmp_path: Path
) -> None:
    certfile, keyfile = trust_loopback
    vault, selector, handle = _compose(tmp_path)

    def script(st, method, if_match, body):
        if method == "GET":
            return (
                200,
                {},
                json.dumps({FIELD_ID: _RID, ODATA_ETAG: st.etag, "Quantity": st.quantity}).encode(),
            )
        if method == "PATCH" and not st._patched:
            st._patched = True
            st.etag = _ETAG_V2  # concurrent writer bumped version, field untouched
            return 412, {"ETag": _ETAG_V2}, b""
        st.quantity = json.loads(body.decode())["Quantity"]
        st.etag = _ETAG_V3
        return 200, {}, json.dumps({FIELD_ID: _RID, ODATA_ETAG: st.etag}).encode()

    state = _Scripted(script=script)
    with _https_server(_handler_for(state), certfile, keyfile) as port:
        dispatch = _make_execute_dispatch(
            host=f"localhost:{port}",
            vault=vault,
            selector=selector,
            handle=handle,
            descriptor=_descriptor(effect="write"),
        )
        outcome = run_version_safe_write(
            mode=ConcurrencyMode.LISTITEM_ETAG,
            path=_PATH,
            intent=_intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            dispatch=dispatch,
        )
    assert outcome.applied is True and outcome.verified is True and outcome.attempts == 2
    # The vault WAS consulted (custody ran) and the real ordered sequence hit the server.
    assert vault.asked  # custody path exercised
    assert [(r["method"], r["if_match"]) for r in state.requests] == [
        ("GET", None),
        ("PATCH", _ETAG_V1),
        ("GET", None),
        ("PATCH", _ETAG_V2),
        ("GET", None),
    ]


def test_d7_initial_get_already_moved_conflicts_no_write(
    trust_loopback: Tuple[Path, Path], tmp_path: Path
) -> None:
    """D7: the initial GET already shows 9/v2 -> conflict BEFORE any PATCH."""
    certfile, keyfile = trust_loopback
    vault, selector, handle = _compose(tmp_path)

    def script(st, method, if_match, body):
        # The resource is ALREADY 9 at v2 the very first GET.
        if method == "GET":
            return (
                200,
                {},
                json.dumps({FIELD_ID: _RID, ODATA_ETAG: _ETAG_V2, "Quantity": 9}).encode(),
            )
        return 200, {}, json.dumps({FIELD_ID: _RID, ODATA_ETAG: _ETAG_V3}).encode()

    state = _Scripted(script=script)
    with _https_server(_handler_for(state), certfile, keyfile) as port:
        dispatch = _make_execute_dispatch(
            host=f"localhost:{port}",
            vault=vault,
            selector=selector,
            handle=handle,
            descriptor=_descriptor(effect="write"),
        )
        outcome = run_version_safe_write(
            mode=ConcurrencyMode.LISTITEM_ETAG,
            path=_PATH,
            intent=_intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            dispatch=dispatch,
        )
    # intent 1->2 but the field is already 9: without the baseline check, If-Match
    # v2 would MATCH and clobber. Baseline check catches it: conflict, NO PATCH.
    assert outcome.applied is False and outcome.conflict.moved_fields == ("Quantity",)
    assert [r["method"] for r in state.requests] == ["GET"]  # no PATCH ever sent


def test_d9_500_on_write_is_unknown_not_not_applied(
    trust_loopback: Tuple[Path, Path], tmp_path: Path
) -> None:
    """D9: a 500 on a non-idempotent PATCH -> UNKNOWN outcome, not 'did not land'."""
    certfile, keyfile = trust_loopback
    vault, selector, handle = _compose(tmp_path)

    def script(st, method, if_match, body):
        if method == "GET":
            return (
                200,
                {},
                json.dumps({FIELD_ID: _RID, ODATA_ETAG: _ETAG_V1, "Quantity": 1}).encode(),
            )
        return 500, {}, json.dumps({"error": "boom"}).encode()

    state = _Scripted(script=script)
    with _https_server(_handler_for(state), certfile, keyfile) as port:
        dispatch = _make_execute_dispatch(
            host=f"localhost:{port}",
            vault=vault,
            selector=selector,
            handle=handle,
            descriptor=_descriptor(effect="write"),  # non-idempotent
        )
        outcome = run_version_safe_write(
            mode=ConcurrencyMode.LISTITEM_ETAG,
            path=_PATH,
            intent=_intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            dispatch=dispatch,
        )
    assert outcome.applied is False
    assert outcome.write_outcome == ATTEMPT_UNKNOWN  # do NOT record 'not applied'
    assert "UNKNOWN" in outcome.reason
