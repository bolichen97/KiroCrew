"""W02 PR-3: the GitHub structured connector's LIVE wiring, honestly bounded.

The connector drives a REAL W01 page walk (the operation is invoked, authorized
per page, and the per-page cursor followed) but the fetched row payload does not
yet come back through W01's ExecutionOutcome (root-confirmed at cd00f1837:
Decoded2xx.body is dropped, only OperationResult={status,next_cursor}
propagates). W01 owns adding a neutral payload slot. Until then the row step
FAILS CLOSED — it never fabricates rows and never presents a page count as data.

These tests assert exactly that boundary, with a real, isolated encrypted
SecretVault and a self-signed HTTPS loopback so the walk really talks TLS
through the unmodified urllib_http_send.
"""

from __future__ import annotations

import asyncio
import datetime
import http.server
import ipaddress
import json
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes
from kiro_crew.connections.control_plane.binding import binding_secret_ref, create_binding
from kiro_crew.connections.control_plane.handle import derive_handle, ensure_usable
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    BindingSecretSelector,
    urllib_http_send,
)
from kiro_crew.connections.vendors.github.dispatch import build_github_transport
from kiro_crew.knowledge.connectors.github_structured import (
    ENTITY_COMMIT,
    ENTITY_PULL_REQUEST,
    GithubStructuredConnector,
    GithubTransport,
    LiveFetchError,
)
from kiro_crew.secrets import SecretVault

_T0 = 1_000_000.0
_GRANTED: Tuple[str, ...] = ("repo",)


def _verifier(*, claimed_subject, claimed_tenant, service_id):
    return {"subject_ref": "s", "tenant_ref": "t"}


def _bundle_for(vault: SecretVault, *, clock=lambda: _T0) -> GithubTransport:
    binding = create_binding(
        service_id="github", claimed_subject="octocat", claimed_tenant="acme",
        credential_mode="oauth_user", verifier=_verifier, slug="github",
    )
    handle = derive_handle(
        binding, granted_scopes=_GRANTED, requested_scopes=("repo",),
        now=_T0, ttl_seconds=3600.0,
    )
    view = ensure_usable(handle, now=_T0)
    selector = BindingSecretSelector(
        slug="github", binding_fingerprint=view.binding_fingerprint,
        service_id=view.service_id, credential_mode=view.credential_mode,
    )
    transport = build_github_transport(
        operation_id="gh_list_pull_requests", selector=selector,
        vault=vault, http_send=urllib_http_send,
    )
    return GithubTransport(
        transport=transport, handle=handle, offered_mode="oauth_user",
        permitted=declare_permitted_modes(("oauth_user",)),
        layers=LayerCeilings(), governance_scope="tools",
        governance_item="pulls.list", clock=clock,
    )


@pytest.fixture
def real_vault(tmp_path: Path) -> SecretVault:
    vault = SecretVault(tmp_path / "crewhome")
    vault.set_sync(binding_secret_ref("github")["name"], "gh-installation-token")
    return vault


# ── self-signed HTTPS loopback that pages ───────────────────────────────────
def _tls_material(tmp_path: Path) -> Tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cf = tmp_path / "cert.pem"
    kf = tmp_path / "key.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cf, kf


class _Recorder:
    def __init__(self) -> None:
        self.requests: List[Dict[str, str]] = []
        self.paths: List[str] = []


def _paging_handler(recorder: _Recorder, port_ref: Dict[str, int]):
    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            recorder.requests.append({k: v for k, v in self.headers.items()})
            recorder.paths.append(self.path)
            port = port_ref["port"]
            if self.path.startswith("/page2"):
                body = json.dumps([{"number": 2, "title": "b"}]).encode()
                headers = {"Content-Type": "application/json"}
            else:
                body = json.dumps([{"number": 1, "title": "a"}]).encode()
                headers = {
                    "Content-Type": "application/json",
                    "Link": f'<https://localhost:{port}/page2>; rel="next"',
                }
            self.send_response(200)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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


# ── the tests ───────────────────────────────────────────────────────────────
def test_fetch_drives_real_pages_then_fails_closed_at_row_seam(
    tmp_path: Path, real_vault: SecretVault, monkeypatch: pytest.MonkeyPatch,
) -> None:
    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))
    rec = _Recorder()
    port_ref: Dict[str, int] = {"port": 0}
    with _https_server(_paging_handler(rec, port_ref), certfile, keyfile) as port:
        port_ref["port"] = port
        import kiro_crew.connections.vendors.github.locator as gh_locator
        monkeypatch.setattr(gh_locator, "GITHUB_API_BASE", f"https://localhost:{port}")
        connector = GithubStructuredConnector(
            transport_provider=lambda s, e: _bundle_for(real_vault) if e == ENTITY_PULL_REQUEST else None,
        )
        with pytest.raises(LiveFetchError) as exc:
            asyncio.run(connector.fetch({"repo_full_name": "octo/hello"}))
    # Honesty: refused at the row seam, not a fabricated dataset.
    assert "row payload" in str(exc.value)
    # But the walk really turned two pages over TLS.
    assert len(rec.paths) == 2
    assert rec.paths[0].startswith("/repos/octo/hello/pulls")
    assert rec.paths[1].startswith("/page2")
    # Custody ran: the vault-resolved credential reached the wire.
    auths = [next((v for k, v in r.items() if k.lower() == "authorization"), None) for r in rec.requests]
    assert auths == ["Bearer gh-installation-token", "Bearer gh-installation-token"]


def test_detect_changes_drives_real_pages_then_fails_closed(
    tmp_path: Path, real_vault: SecretVault, monkeypatch: pytest.MonkeyPatch,
) -> None:
    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))
    rec = _Recorder()
    port_ref: Dict[str, int] = {"port": 0}
    with _https_server(_paging_handler(rec, port_ref), certfile, keyfile) as port:
        port_ref["port"] = port
        import kiro_crew.connections.vendors.github.locator as gh_locator
        monkeypatch.setattr(gh_locator, "GITHUB_API_BASE", f"https://localhost:{port}")
        connector = GithubStructuredConnector(transport_provider=lambda s, e: _bundle_for(real_vault))
        with pytest.raises(LiveFetchError) as exc:
            asyncio.run(connector.detect_changes({"repo_full_name": "octo/hello"}))
    assert "row payload" in str(exc.value)
    assert len(rec.paths) >= 2


def test_no_transport_still_refuses_notimplemented() -> None:
    connector = GithubStructuredConnector()
    with pytest.raises(NotImplementedError):
        asyncio.run(connector.fetch({"repo_full_name": "o/r"}))
    with pytest.raises(NotImplementedError):
        asyncio.run(connector.detect_changes({"repo_full_name": "o/r"}))


def test_provider_returning_none_for_every_kind_fails_closed() -> None:
    connector = GithubStructuredConnector(transport_provider=lambda s, e: None)
    with pytest.raises(LiveFetchError):
        asyncio.run(connector.fetch({"repo_full_name": "o/r"}))


def test_missing_transport_for_detect_changes_fails_closed() -> None:
    connector = GithubStructuredConnector(transport_provider=lambda s, e: None)
    with pytest.raises(LiveFetchError):
        asyncio.run(connector.detect_changes({"repo_full_name": "o/r"}))


def test_commit_and_pr_kinds_are_wired() -> None:
    from kiro_crew.knowledge.connectors.github_structured import _OP_FOR_ENTITY
    assert _OP_FOR_ENTITY[ENTITY_PULL_REQUEST] == "gh_list_pull_requests"
    assert _OP_FOR_ENTITY[ENTITY_COMMIT] == "gh_list_commits"
