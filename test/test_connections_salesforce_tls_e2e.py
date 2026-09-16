"""Two-path factory->fetch proof over REAL controlled TLS (SOQL + Report).

This is the end-to-end proof the connector's live read crosses a real TLS wire
through the REAL W01 executor, for BOTH Salesforce read paths:

* **SOQL object path** -- describe, then a paged SELECT that walks two REAL TLS
  pages via the executor's ``PageWalk`` on the vendor's own ``nextRecordsUrl``.
* **Report / Analytics path** -- a single report-run read.

Everything is real, mirroring ``test_connections_control_plane_real_tls_e2e``:

* a REAL ``ThreadingHTTPServer`` wrapped in a real ``ssl.SSLContext`` with a
  self-signed cert minted per test, trusted through ``SSL_CERT_FILE`` with
  verification AND hostname checking left ON;
* the REAL sender ``urllib_http_send``, unmodified;
* the REAL production transport ``build_production_transport`` and the REAL
  ``SalesforceProductionRunner`` over it;
* a REAL on-disk AES-256-GCM ``SecretVault`` holding the binding secret;
* a REAL binding + issued handle; the full executor gate chain runs per call.

No real Salesforce business account: the server is a loopback fixture and the
credential is the isolated fixture vault's. The readback oracle is the server's
OWN record of what it served, so an assertion proves the channel carried it.
"""

from __future__ import annotations

import asyncio
import datetime
import http.server
import ipaddress
import json
import ssl
import threading
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kiro_crew.connections.control_plane import production as production_module
from kiro_crew.connections.control_plane.auth_modes import declare_permitted_modes
from kiro_crew.connections.control_plane.binding import binding_secret_ref, create_binding
from kiro_crew.connections.control_plane.handle import derive_handle, ensure_usable
from kiro_crew.connections.control_plane.production import (
    BindingSecretSelector,
    urllib_http_send,
)
from kiro_crew.connections.vendors.salesforce.runner import (
    SalesforceAuthContext,
    SalesforceProductionRunner,
)
from kiro_crew.knowledge.connectors.salesforce_structured import (
    PATH_ANALYTICS_REPORT,
    PATH_SOQL_OBJECT,
    SalesforceStructuredConnector,
)
from kiro_crew.secrets import SecretVault

_GRANTED = ("salesforce.read",)
ORG = "00Dxx0000001gP"

# ── the Salesforce-shaped payloads the loopback server serves ──────────────
_DESCRIBE_BODY = {
    "name": "Account",
    "label": "Account",
    "createable": True,
    "queryable": True,
    "updateable": True,
    "deletable": False,
    "fields": [
        {
            "name": "Id",
            "type": "id",
            "soapType": "tns:ID",
            "nillable": False,
            "createable": False,
            "updateable": False,
            "accessible": True,
        },
        {
            "name": "Name",
            "type": "string",
            "soapType": "xsd:string",
            "nillable": False,
            "createable": True,
            "updateable": True,
            "accessible": True,
        },
        {
            "name": "SystemModstamp",
            "type": "datetime",
            "soapType": "xsd:dateTime",
            "nillable": False,
            "createable": False,
            "updateable": False,
            "accessible": True,
        },
    ],
}
# SOQL page 1 (done=false) points at a cursor path the server also serves.
_SOQL_CURSOR_PATH = "/services/data/v60.0/query/01g0000000AAA-200"
_SOQL_PAGE1 = {
    "totalSize": 2,
    "done": False,
    "nextRecordsUrl": _SOQL_CURSOR_PATH,
    "records": [
        {
            "attributes": {"type": "Account"},
            "Id": "001A00000000001",
            "Name": "Acme",
            "SystemModstamp": "2026-02-01T00:00:00Z",
        }
    ],
}
_SOQL_PAGE2 = {
    "totalSize": 2,
    "done": True,
    "records": [
        {
            "attributes": {"type": "Account"},
            "Id": "001B00000000002",
            "Name": "Globex",
            "SystemModstamp": "2026-03-01T00:00:00Z",
        }
    ],
}
_REPORT_BODY = {
    "allData": True,
    "reportMetadata": {"detailColumns": ["ACCOUNT.ID", "ACCOUNT.NAME"]},
    "factMap": {
        "T!T": {
            "rows": [
                {
                    "dataCells": [
                        {"value": "001A00000000001", "label": "001A00000000001"},
                        {"label": "Acme"},
                    ]
                },
                {
                    "dataCells": [
                        {"value": "001B00000000002", "label": "001B00000000002"},
                        {"label": "Globex"},
                    ]
                },
            ]
        }
    },
}


def _b(obj: Any) -> bytes:
    return json.dumps(obj).encode("utf-8")


# ── real TLS material + server ─────────────────────────────────────────────
def _tls_material(directory: Path) -> Tuple[Path, Path]:
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
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
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
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.authorization: list[str | None] = []

    def record(self, path: str, headers: Mapping[str, str]) -> None:
        self.paths.append(path)
        self.authorization.append(
            next((v for k, v in headers.items() if k.lower() == "authorization"), None)
        )


def _handler_for(served: _Served, script: Mapping[str, bytes]):
    class _H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            # Match on path prefix so the query-string (?q=...) still resolves.
            key = next(
                (k for k in script if self.path.split("?", 1)[0] == k or self.path == k), None
            )
            if key is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            served.record(self.path, {k: v for k, v in self.headers.items()})
            body = script[key]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a: Any) -> None:
            pass

    return _H


@pytest.fixture()
def trust_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Tuple[Path, Path]:
    certfile, keyfile = _tls_material(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certfile))
    return certfile, keyfile


@pytest.fixture()
def real_vault(tmp_path: Path) -> SecretVault:
    vault = SecretVault(tmp_path / "crewhome")
    vault.set_sync(binding_secret_ref("salesforce")["name"], "salesforce-fixture-token")
    store = tmp_path / "crewhome" / ".vault" / "secrets.enc"
    assert store.is_file() and b"salesforce-fixture-token" not in store.read_bytes()
    return vault


def _verifier(*, claimed_subject: str, claimed_tenant: str, service_id: str) -> Dict[str, str]:
    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


def _handle():
    binding = create_binding(
        service_id="salesforce",
        claimed_subject="alice",
        claimed_tenant="acme",
        credential_mode="oauth_user",
        verifier=_verifier,
        slug="salesforce",
    )  # type: ignore[arg-type]
    return derive_binding_handle(binding)


def derive_binding_handle(binding):
    # Mint against the REAL current instant with a live ttl: the runner drives
    # execute() on the production clock (time.time), so a handle pinned to a
    # fixed past _T0 would be expired on the real wire. This keeps the whole
    # path production-faithful (real clock, no test-only now override).
    import time as _time

    return derive_handle(
        binding,
        granted_scopes=_GRANTED,
        requested_scopes=("salesforce.read",),
        now=_time.time(),
        ttl_seconds=300.0,
    )


def _runner(handle, vault, port: int) -> SalesforceProductionRunner:
    import time as _time

    view = ensure_usable(handle, now=_time.time())
    selector = BindingSecretSelector(
        slug="salesforce",
        binding_fingerprint=view.binding_fingerprint,
        service_id=view.service_id,
        credential_mode=view.credential_mode,
    )
    auth = SalesforceAuthContext(
        handle=handle,
        offered_mode="oauth_user",
        permitted=declare_permitted_modes(("oauth_user",)),
        governance_item="salesforce.read",
    )
    # Pin the real sender: this is the whole claim of the file.
    assert urllib_http_send is production_module.urllib_http_send
    return SalesforceProductionRunner(
        selector=selector, vault=vault, auth=auth, http_send=urllib_http_send
    )


def _serve(script, certfile, keyfile) -> Tuple[http.server.ThreadingHTTPServer, _Served, int]:
    served = _Served()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(served, script))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, served, server.server_address[1]


class TestTwoPathTlsFactoryToFetch:
    def test_soql_object_path_walks_two_real_tls_pages(self, trust_loopback, real_vault):
        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/sobjects/Account/describe": _b(_DESCRIBE_BODY),
            "/services/data/v60.0/query": _b(_SOQL_PAGE1),
            _SOQL_CURSOR_PATH: _b(_SOQL_PAGE2),
        }
        server, served, port = _serve(script, certfile, keyfile)
        try:
            handle = _handle()
            runner = _runner(handle, real_vault, port)
            conn = SalesforceStructuredConnector(call_runner=runner)
            source = {
                "id": "src-acct",
                "uri": "salesforce://object/Account",
                "instance_url": f"https://localhost:{port}",
                "org_id": ORG,
            }
            text, meta = asyncio.run(conn.fetch(source))
        finally:
            server.shutdown()
        # readback oracle: what the SERVER actually served, per path
        assert meta["path"] == PATH_SOQL_OBJECT
        assert meta["row_count"] == 2
        # both records crossed the wire and were converted, keyed by real Id
        assert "001A00000000001" in text and "001B00000000002" in text
        # the walk really fetched describe + page1 + the cursor page2 over TLS
        assert any("describe" in p for p in served.paths)
        assert any(p.startswith("/services/data/v60.0/query?q=") for p in served.paths)
        assert _SOQL_CURSOR_PATH in served.paths
        # the credential really rode the wire (custody worked), never in the URL
        assert all(
            a == "Bearer salesforce-fixture-token" for a in served.authorization if a is not None
        )
        # watermark advanced to the max modstamp seen across both pages
        assert meta["salesforce_structured_checkpoint"]["since"] == "2026-03-01T00:00:00Z"
        # every row carries its ProviderResourceRef for the (chat408) ACL bridge
        assert len(meta["rows"]) == 2
        assert meta["rows"][0]["resource_ref"]["locator"]["sobjectType"] == "Account"

    def test_report_path_crosses_real_tls(self, trust_loopback, real_vault):
        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/analytics/reports/00O000000000001": _b(_REPORT_BODY),
        }
        server, served, port = _serve(script, certfile, keyfile)
        try:
            handle = _handle()
            runner = _runner(handle, real_vault, port)
            conn = SalesforceStructuredConnector(call_runner=runner)
            source = {
                "id": "src-rep",
                "uri": "salesforce://report/00O000000000001",
                "instance_url": f"https://localhost:{port}",
                "org_id": ORG,
            }
            text, meta = asyncio.run(conn.fetch(source))
        finally:
            server.shutdown()
        assert meta["path"] == PATH_ANALYTICS_REPORT
        assert meta["row_count"] == 2
        assert "001A00000000001" in text and "001B00000000002" in text
        assert any("analytics/reports/00O000000000001" in p for p in served.paths)
        assert all(
            a == "Bearer salesforce-fixture-token" for a in served.authorization if a is not None
        )
        # report path carries no SOQL watermark
        assert meta["salesforce_structured_checkpoint"]["since"] is None


# ── real SyncScheduler ingest: TLS -> fetch_rows -> ingest_rows -> ACL ─────
from unittest.mock import AsyncMock, MagicMock  # noqa: E402

from kiro_crew.knowledge.acl import ProviderResourceRef  # noqa: E402
from kiro_crew.knowledge.ingestion import IngestionPipeline  # noqa: E402
from kiro_crew.knowledge.store import KnowledgeStore  # noqa: E402
from kiro_crew.knowledge.sync import SyncScheduler  # noqa: E402


def _pipeline(store: KnowledgeStore) -> IngestionPipeline:
    extractor = MagicMock()
    extractor._pool = None
    extractor.extract_batch = AsyncMock(
        side_effect=lambda chunks: [
            {"category": "document", "summary": "s", "entities": []} for _ in chunks
        ]
    )
    chunker = MagicMock()
    chunker.chunk.side_effect = lambda text, **k: [
        {"content": text, "chunk_index": 0, "section_title": None}
    ]
    return IngestionPipeline(
        store=store, extractor=extractor, chunker=chunker, reader=MagicMock(), embedder=None
    )


class TestSyncSchedulerRealIngest:
    def test_soql_rows_ingest_with_deny_acl_and_checkpoint(
        self, trust_loopback, real_vault, tmp_path
    ):
        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/sobjects/Account/describe": _b(_DESCRIBE_BODY),
            "/services/data/v60.0/query": _b(_SOQL_PAGE1),
            _SOQL_CURSOR_PATH: _b(_SOQL_PAGE2),
        }
        server, served, port = _serve(script, certfile, keyfile)
        store = KnowledgeStore(str(tmp_path / "sf.db"))
        try:
            handle = _handle()
            runner = _runner(handle, real_vault, port)
            conn = SalesforceStructuredConnector(call_runner=runner)
            assert conn.supports_rows() is True
            src = store.add_source(
                "SF Account",
                "salesforce",
                "salesforce://object/Account",
                properties={"instance_url": f"https://localhost:{port}", "org_id": ORG},
            )
            sched = SyncScheduler(store, _pipeline(store), {"salesforce": conn})
            out = asyncio.run(sched.sync_source(src))
        finally:
            server.shutdown()
            # keep store open for readback below; closed at the end
        try:
            # both rows ingested, each its OWN item group + grant
            assert out["synced"] is True
            state = store.get_connector_row_state(src)
            assert len(state) == 2
            # every grant: managed=True, empty subjects (DENY, fail-closed), the
            # row's own ProviderResourceRef -- proof ACL was really persisted.
            item_ids = [state[k]["item_ids"][0] for k in state]
            grants = store.get_item_grants(item_ids)
            for iid in item_ids:
                g = grants[iid]
                assert g["managed"] is True
                # empty subjects == explicit deny-all, NOT public
                assert json.loads(g["subjects"]) == []
                rr = ProviderResourceRef.from_json(g["resource_ref"])
                assert rr.provider == "salesforce"
                assert rr.locator["sobjectType"] == "Account"
            # props['checkpoint'] written by the SHARED sync ONLY after full
            # persistence -- its presence is the "ACL landed" signal (SOQL
            # watermark advanced to the max modstamp).
            row = store.db.execute("SELECT properties FROM sources WHERE id = ?", (src,)).fetchone()
            props = json.loads(row["properties"])
            assert props["checkpoint"]["since"] == "2026-03-01T00:00:00Z"
        finally:
            store.close()

    def test_report_rows_ingest_full_snapshot(self, trust_loopback, real_vault, tmp_path):
        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/analytics/reports/00O000000000001": _b(_REPORT_BODY),
        }
        server, served, port = _serve(script, certfile, keyfile)
        store = KnowledgeStore(str(tmp_path / "sfrep.db"))
        try:
            handle = _handle()
            runner = _runner(handle, real_vault, port)
            conn = SalesforceStructuredConnector(call_runner=runner)
            src = store.add_source(
                "SF Report",
                "salesforce",
                "salesforce://report/00O000000000001",
                properties={"instance_url": f"https://localhost:{port}", "org_id": ORG},
            )
            sched = SyncScheduler(store, _pipeline(store), {"salesforce": conn})
            out = asyncio.run(sched.sync_source(src))
        finally:
            server.shutdown()
        try:
            assert out["synced"] is True
            state = store.get_connector_row_state(src)
            assert len(state) == 2  # two report rows, each its own grant
            item_ids = [state[k]["item_ids"][0] for k in state]
            grants = store.get_item_grants(item_ids)
            for iid in item_ids:
                g = grants[iid]
                assert g["managed"] is True
                assert json.loads(g["subjects"]) == []  # deny, not public
                assert (
                    ProviderResourceRef.from_json(g["resource_ref"]).locator["reportId"]
                    == "00O000000000001"
                )
        finally:
            store.close()
