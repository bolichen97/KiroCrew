"""W06 · Graph optimistic-concurrency version-safe write protocol.

Two kinds of coverage:

1. PURE-LOGIC unit tests of the protocol (version read, per-endpoint If-Match,
   conflict-first 412 recovery, per-typed-column field compare, read-back).
2. A REAL SEQUENCE against a controlled TLS loopback server, driven by the
   UNMODIFIED W01 sender ``urllib_http_send`` over real sockets -- the same
   harness shape as W01's ``test_the_loopback_harness_really_speaks_tls_to_the_real_sender``.
   The full GET -> conditional PATCH -> 412 -> fresh re-GET -> read-back walk
   runs against that server. CORRELATION is the ACTUAL SENDER CALL RELATIONSHIP:
   every decision uses the ``HttpReply`` the sender RETURNED for the
   ``HttpRequest`` this module's seat produced -- not a header echo. ``request-id``
   / ``client-request-id`` are never relied on.

NOT LIVE: the server is a self-signed loopback the test stands up; there is no
real Microsoft Graph endpoint, no credential, no cloud write. CANDIDATE-ON-
PARENT-BASE (parent W01 executor branch cd00f1837; not on main).
"""

from __future__ import annotations

import datetime
import http.server
import json
import socket  # noqa: F401  (kept parallel to W01 harness imports)
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

from kiro_crew.connections.control_plane.production import HttpReply, urllib_http_send
from kiro_crew.connections.vendors.microsoft.graph.concurrency import (
    FIELD_CTAG,
    FIELD_ID,
    ODATA_ETAG,
    PRECONDITION_FAILED,
    ColumnKind,
    ConcurrencyError,
    ConcurrencyMode,
    Conflict,
    FieldChange,
    VersionKind,
    VersionTag,
    WriteIntent,
    accepts_validator,
    conditional_write_request,
    extract_version,
    graph_request_locator,
    graph_result_decode,
    has_412_contract,
    recover_from_precondition_failed,
    supports_if_match,
    verify_read_back,
)

_ETAG_V1 = '"1"'
_ETAG_V2 = '"2"'
_ETAG_V3 = '"3"'
_CTAG_V2 = "aYzk5V2"


def _intent(**changes):
    """name=(baseline, intended, ColumnKind) -- column_kind REQUIRED."""
    return WriteIntent(
        changes={
            n: FieldChange(baseline=b, intended=i, column_kind=k)
            for n, (b, i, k) in changes.items()
        }
    )


def _reply(status: int, body: Any = None, **headers) -> HttpReply:
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    return HttpReply(status=status, headers=headers, body=raw)


# =============================================================================
# PURE-LOGIC unit tests
# =============================================================================
class TestVersionAndModes:
    def test_extract_etag(self):
        assert extract_version({ODATA_ETAG: _ETAG_V1}) == VersionTag(VersionKind.ETAG, _ETAG_V1)

    def test_extract_ctag_kept_distinct(self):
        assert extract_version({FIELD_CTAG: _CTAG_V2}) == VersionTag(VersionKind.CTAG, _CTAG_V2)

    def test_sharepoint_etag_only(self):
        assert accepts_validator(ConcurrencyMode.LISTITEM_ETAG, VersionKind.ETAG)
        assert not accepts_validator(ConcurrencyMode.LISTITEM_ETAG, VersionKind.CTAG)

    def test_onedrive_etag_or_ctag(self):
        assert accepts_validator(ConcurrencyMode.DRIVEITEM_ETAG_OR_CTAG, VersionKind.ETAG)
        assert accepts_validator(ConcurrencyMode.DRIVEITEM_ETAG_OR_CTAG, VersionKind.CTAG)

    def test_both_writers_have_412_contract(self):
        assert has_412_contract(ConcurrencyMode.LISTITEM_ETAG)
        assert has_412_contract(ConcurrencyMode.DRIVEITEM_ETAG_OR_CTAG)

    def test_excel_has_no_mechanism(self):
        assert not has_412_contract(ConcurrencyMode.NONE_LAST_WRITE_WINS)
        assert not supports_if_match(ConcurrencyMode.NONE_LAST_WRITE_WINS)


class TestSeat1RequestLocator:
    def test_shapes_https_url_and_if_match(self):
        req = graph_request_locator(
            method="get",
            endpoint_host="graph.microsoft.com",
            path="/sites/S/lists/L/items/7/fields",
            if_match=_ETAG_V1,
        )
        assert req.method == "GET"
        assert req.url == "https://graph.microsoft.com/sites/S/lists/L/items/7/fields"
        assert req.headers["If-Match"] == _ETAG_V1

    def test_locator_refuses_to_set_a_credential_header(self):
        with pytest.raises(ConcurrencyError, match="transport owns credentials"):
            graph_request_locator(
                method="GET",
                endpoint_host="graph.microsoft.com",
                path="/x",
                extra_headers={"Authorization": "Bearer nope"},
            )

    def test_conditional_write_refused_for_excel(self):
        with pytest.raises(ConcurrencyError, match="last-write-wins"):
            conditional_write_request(
                mode=ConcurrencyMode.NONE_LAST_WRITE_WINS,
                endpoint_host="graph.microsoft.com",
                path="/x",
                version=VersionTag(VersionKind.ETAG, _ETAG_V1),
                intent=_intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            )

    def test_conditional_write_refuses_missing_version(self):
        with pytest.raises(ConcurrencyError, match="silently degrade|blind"):
            conditional_write_request(
                mode=ConcurrencyMode.LISTITEM_ETAG,
                endpoint_host="graph.microsoft.com",
                path="/x",
                version=None,
                intent=_intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            )

    def test_sharepoint_refuses_ctag_validator(self):
        with pytest.raises(ConcurrencyError, match="per-endpoint"):
            conditional_write_request(
                mode=ConcurrencyMode.LISTITEM_ETAG,
                endpoint_host="graph.microsoft.com",
                path="/x",
                version=VersionTag(VersionKind.CTAG, _CTAG_V2),
                intent=_intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            )

    def test_conditional_write_carries_ifmatch_and_json_body(self):
        req = conditional_write_request(
            mode=ConcurrencyMode.LISTITEM_ETAG,
            endpoint_host="graph.microsoft.com",
            path="/sites/S/lists/L/items/7/fields",
            version=VersionTag(VersionKind.ETAG, _ETAG_V1),
            intent=_intent(Quantity=(1, 2, ColumnKind.SCALAR)),
        )
        assert req.method == "PATCH" and req.headers["If-Match"] == _ETAG_V1
        assert json.loads(req.body.decode()) == {"Quantity": 2}


class TestSeat2ResultDecode:
    def test_collection_without_nextlink_is_ok(self):
        r = graph_result_decode(_reply(200, {"value": [{"id": "1"}]}))
        assert r == {"status": "ok", "next_cursor": None}

    def test_collection_with_nextlink_is_partial_with_cursor(self):
        link = "https://graph.microsoft.com/next?$skiptoken=abc"
        r = graph_result_decode(_reply(200, {"value": [], "@odata.nextLink": link}))
        assert r == {"status": "partial", "next_cursor": link}

    def test_non_collection_defers_to_neutral_decode_204(self):
        # 204 no content -> W01 neutral decode reports ok/None.
        r = graph_result_decode(HttpReply(status=204, headers={}, body=b""))
        assert r["next_cursor"] is None


class Test412RecoveryConflictFirst:
    def test_untouched_field_retries_with_fresh_version(self):
        plan = recover_from_precondition_failed(
            ConcurrencyMode.LISTITEM_ETAG,
            _reply(PRECONDITION_FAILED),
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            _reply(200, {ODATA_ETAG: _ETAG_V2, "Quantity": 1}),
        )
        assert plan.should_retry is True and plan.fresh_version.value == _ETAG_V2

    def test_quantity_1_2_9_clobber_is_a_conflict(self):
        plan = recover_from_precondition_failed(
            ConcurrencyMode.LISTITEM_ETAG,
            _reply(PRECONDITION_FAILED),
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            _reply(200, {ODATA_ETAG: _ETAG_V2, "Quantity": 9}),
        )
        assert plan.should_retry is False
        assert isinstance(plan.conflict, Conflict) and plan.conflict.moved_fields == ("Quantity",)

    def test_undocumented_typed_column_refuses(self):
        with pytest.raises(ConcurrencyError, match="lookup"):
            recover_from_precondition_failed(
                ConcurrencyMode.LISTITEM_ETAG,
                _reply(PRECONDITION_FAILED),
                _intent(AuthorLookupId=({"LookupId": 1}, {"LookupId": 2}, ColumnKind.LOOKUP)),
                _reply(200, {ODATA_ETAG: _ETAG_V2, "AuthorLookupId": {"LookupId": 1}}),
            )

    def test_non_412_does_not_retry(self):
        plan = recover_from_precondition_failed(
            ConcurrencyMode.LISTITEM_ETAG,
            _reply(409),
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            _reply(200, {ODATA_ETAG: _ETAG_V2, "Quantity": 1}),
        )
        assert plan.should_retry is False and plan.conflict is None


class TestReadBack:
    def test_verified_when_intended_value_present(self):
        v = verify_read_back(
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            _reply(200, {FIELD_ID: "7", "Quantity": 2}),
        )
        assert v.verified is True

    def test_not_verified_when_field_differs(self):
        v = verify_read_back(
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            _reply(200, {FIELD_ID: "7", "Quantity": 9}),
        )
        assert v.verified is False and v.mismatches == ("Quantity",)

    def test_success_reason_disclaims_attribution(self):
        v = verify_read_back(
            _intent(Quantity=(1, 2, ColumnKind.SCALAR)),
            _reply(200, {FIELD_ID: "7", "Quantity": 2}),
        )
        assert "not a claim that this write produced it" in v.reason


class TestColumnKindRequired:
    def test_field_change_requires_column_kind(self):
        with pytest.raises(TypeError):
            FieldChange(baseline=1, intended=2)  # type: ignore[call-arg]


# =============================================================================
# REAL SEQUENCE against a controlled TLS loopback, driven by the W01 sender.
# =============================================================================
def _tls_material(tmp_path: Path) -> Tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
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


class _Scripted:
    """A tiny stateful Graph-like resource served over the loopback.

    It records what it received and answers the version-safe sequence:
    GET -> 200 with eTag v1; PATCH with matching If-Match -> 412 (a concurrent
    writer already moved it to v2, field UNCHANGED); GET -> 200 eTag v2; PATCH
    with If-Match v2 -> 200 (applied), state now Quantity=2 eTag v3; final GET ->
    200 with Quantity=2. Everything is keyed off the REQUEST the server actually
    receives, so the test's decisions ride the real sender call relationship.
    """

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.quantity = 1
        self.etag = _ETAG_V1
        self._patched_once = False

    def handle(
        self, method: str, if_match: Optional[str], body: bytes
    ) -> Tuple[int, Dict[str, str], bytes]:
        self.requests.append({"method": method, "if_match": if_match, "body": body})
        if method == "GET":
            payload = {FIELD_ID: "7", ODATA_ETAG: self.etag, "Quantity": self.quantity}
            return 200, {}, json.dumps(payload).encode()
        if method == "PATCH":
            if not self._patched_once:
                # A concurrent writer moved the version to v2 (field unchanged),
                # so our If-Match v1 fails: 412 with the server's current ETag.
                self._patched_once = True
                self.etag = _ETAG_V2
                return 412, {"ETag": _ETAG_V2}, b""
            # Second PATCH carries If-Match v2 -> applies.
            self.quantity = json.loads(body.decode())["Quantity"]
            self.etag = _ETAG_V3
            return 200, {}, json.dumps({FIELD_ID: "7", ODATA_ETAG: self.etag}).encode()
        return 405, {}, b""


def _handler_for(state: _Scripted):
    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _do(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            if_match = self.headers.get("If-Match")
            status, headers, out = state.handle(self.command, if_match, body)
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

        def log_message(self, *a: Any) -> None:
            return

    return _H


@contextmanager
def _https_server(handler_cls: Any, certfile: Path, keyfile: Path) -> Iterator[int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
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
    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))
    return certfile, keyfile


def test_full_version_safe_sequence_over_real_tls_sender(
    trust_loopback: Tuple[Path, Path],
) -> None:
    """GET -> conditional PATCH -> 412 -> fresh re-GET -> retry -> read-back.

    Driven by the UNMODIFIED W01 ``urllib_http_send`` over a real TLS socket.
    Correlation is the sender call relationship: each decision consumes the
    HttpReply the sender returned for the request this module's seat produced.
    """
    certfile, keyfile = trust_loopback
    state = _Scripted()
    intent = _intent(Quantity=(1, 2, ColumnKind.SCALAR))

    with _https_server(_handler_for(state), certfile, keyfile) as port:
        host = f"localhost:{port}"
        base = "/sites/S/lists/L/items/7/fields"

        # 1. GET the resource. The reply is what the sender returned for THIS get.
        get_req = graph_request_locator(method="GET", endpoint_host=host, path=base)
        get_reply = urllib_http_send(get_req, timeout_seconds=10.0)
        assert get_reply.status == 200
        v1 = extract_version(json.loads(get_reply.body))
        assert v1 == VersionTag(VersionKind.ETAG, _ETAG_V1)

        # 2. Conditional PATCH with If-Match v1 -> the server answers 412.
        patch_req = conditional_write_request(
            mode=ConcurrencyMode.LISTITEM_ETAG,
            endpoint_host=host,
            path=base,
            version=v1,
            intent=intent,
        )
        patch_reply = urllib_http_send(patch_req, timeout_seconds=10.0)
        assert patch_reply.status == PRECONDITION_FAILED

        # 3. Re-GET for the fresh state; 4. recovery decides over the REAL replies.
        refresh_req = graph_request_locator(method="GET", endpoint_host=host, path=base)
        refresh_reply = urllib_http_send(refresh_req, timeout_seconds=10.0)
        plan = recover_from_precondition_failed(
            ConcurrencyMode.LISTITEM_ETAG, patch_reply, intent, refresh_reply
        )
        # Field was untouched by the concurrent writer -> safe retry at v2.
        assert plan.should_retry is True and plan.fresh_version.value == _ETAG_V2

        # 5. Retry the conditional write with the fresh version -> applied.
        retry_req = conditional_write_request(
            mode=ConcurrencyMode.LISTITEM_ETAG,
            endpoint_host=host,
            path=base,
            version=plan.fresh_version,
            intent=intent,
        )
        retry_reply = urllib_http_send(retry_req, timeout_seconds=10.0)
        assert retry_reply.status == 200

        # 6. Independent read-back over the reply that answered the read-back GET.
        rb_req = graph_request_locator(method="GET", endpoint_host=host, path=base)
        rb_reply = urllib_http_send(rb_req, timeout_seconds=10.0)
        verdict = verify_read_back(intent, rb_reply)
        assert verdict.verified is True

    # The server saw the real sequence, in order, with the real If-Match values.
    methods = [(r["method"], r["if_match"]) for r in state.requests]
    assert methods == [
        ("GET", None),
        ("PATCH", _ETAG_V1),
        ("GET", None),
        ("PATCH", _ETAG_V2),
        ("GET", None),
    ]


def test_concurrent_field_change_surfaces_conflict_over_real_tls_sender(
    trust_loopback: Tuple[Path, Path],
) -> None:
    """Same sequence, but the concurrent writer MOVED the field -> conflict, no retry."""
    certfile, keyfile = trust_loopback

    class _MovedField(_Scripted):
        def handle(self, method, if_match, body):
            self.requests.append({"method": method, "if_match": if_match, "body": body})
            if method == "GET" and not self._patched_once:
                return (
                    200,
                    {},
                    json.dumps({FIELD_ID: "7", ODATA_ETAG: _ETAG_V1, "Quantity": 1}).encode(),
                )
            if method == "PATCH":
                self._patched_once = True
                return 412, {"ETag": _ETAG_V2}, b""
            # Re-GET after 412: a concurrent writer set Quantity=9 at v2.
            return (
                200,
                {},
                json.dumps({FIELD_ID: "7", ODATA_ETAG: _ETAG_V2, "Quantity": 9}).encode(),
            )

    state = _MovedField()
    intent = _intent(Quantity=(1, 2, ColumnKind.SCALAR))
    with _https_server(_handler_for(state), certfile, keyfile) as port:
        host = f"localhost:{port}"
        base = "/sites/S/lists/L/items/7/fields"
        get_reply = urllib_http_send(
            graph_request_locator(method="GET", endpoint_host=host, path=base), timeout_seconds=10.0
        )
        v1 = extract_version(json.loads(get_reply.body))
        patch_reply = urllib_http_send(
            conditional_write_request(
                mode=ConcurrencyMode.LISTITEM_ETAG,
                endpoint_host=host,
                path=base,
                version=v1,
                intent=intent,
            ),
            timeout_seconds=10.0,
        )
        assert patch_reply.status == PRECONDITION_FAILED
        refresh_reply = urllib_http_send(
            graph_request_locator(method="GET", endpoint_host=host, path=base), timeout_seconds=10.0
        )
        plan = recover_from_precondition_failed(
            ConcurrencyMode.LISTITEM_ETAG, patch_reply, intent, refresh_reply
        )
    # The concurrent writer moved Quantity 1->9: refuse to clobber, no retry.
    assert plan.should_retry is False
    assert plan.conflict.moved_fields == ("Quantity",)
    # And no second PATCH was ever sent to the server.
    assert [r["method"] for r in state.requests] == ["GET", "PATCH", "GET"]
