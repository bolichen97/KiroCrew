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
from kiro_crew.connections.control_plane.lifecycle import BindingStore
from kiro_crew.connections.control_plane.production import (
    BindingCustodyGate,
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
    # Return the binding alongside the handle: the new W01 custody gate fences
    # for a specific BINDING (not a slug-derived selector), so the runner needs
    # both the binding (for the gate + the live store) and the handle.
    return binding, derive_binding_handle(binding)


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


def _runner(binding, handle, vault, port: int, store_root: Path) -> SalesforceProductionRunner:
    import time as _time

    # Custody gate for THIS binding, keyed on the trusted view fingerprint the
    # handle presents (the new W01 per-binding custody model). No selector.
    view = ensure_usable(handle, now=_time.time())
    gate = BindingCustodyGate(binding=binding, binding_fingerprint=view.binding_fingerprint)
    # A REAL on-disk L04 BindingStore holding the binding -- select_secret reads
    # the secret_ref off the store's OWN record and fences the live generation.
    store = BindingStore(store_root / "connections" / "control_plane_bindings.json")
    store.insert(
        binding,
        deployment_id="deployment://test/salesforce/0",
        kiro_principal="kiro://test/owner",
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
        gate=gate, store=store, vault=vault, auth=auth, http_send=urllib_http_send
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
    def test_soql_object_path_walks_two_real_tls_pages(self, trust_loopback, real_vault, tmp_path):
        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/sobjects/Account/describe": _b(_DESCRIBE_BODY),
            "/services/data/v60.0/query": _b(_SOQL_PAGE1),
            _SOQL_CURSOR_PATH: _b(_SOQL_PAGE2),
        }
        server, served, port = _serve(script, certfile, keyfile)
        try:
            binding, handle = _handle()
            runner = _runner(binding, handle, real_vault, port, tmp_path)
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

    def test_report_path_crosses_real_tls(self, trust_loopback, real_vault, tmp_path):
        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/analytics/reports/00O000000000001": _b(_REPORT_BODY),
        }
        server, served, port = _serve(script, certfile, keyfile)
        try:
            binding, handle = _handle()
            runner = _runner(binding, handle, real_vault, port, tmp_path)
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
            binding, handle = _handle()
            runner = _runner(binding, handle, real_vault, port, tmp_path)
            conn = SalesforceStructuredConnector(call_runner=runner)
            assert conn.supports_rows() is True
            src = store.add_source(
                "SF Account",
                "salesforce",
                "salesforce://object/Account",
                properties={"instance_url": f"https://localhost:{port}", "org_id": ORG},
            )
            sched = SyncScheduler(store, _pipeline(store), {"salesforce": conn})
            # PRE-STATE: a freshly-added source carries NO checkpoint. This is
            # what lets the post-sync value prove a THIS-BATCH advance rather
            # than the reuse of some older watermark -- there is no old value.
            pre_props = json.loads(
                store.db.execute("SELECT properties FROM sources WHERE id = ?", (src,)).fetchone()[
                    "properties"
                ]
            )
            assert "checkpoint" not in pre_props
            out = asyncio.run(sched.sync_source(src))
        finally:
            server.shutdown()
            # keep store open for readback below; closed at the end
        try:
            # both rows ingested, each its OWN item group + grant
            assert out["synced"] is True
            # the shared sync advanced the watermark BECAUSE this batch fully
            # persisted -- bound to THIS batch, not "a checkpoint exists".
            assert out["checkpoint_advanced"] is True
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
            # persistence. Bound to THIS batch: pre-state had no checkpoint
            # (asserted above), and the value now equals THIS batch's max
            # SystemModstamp -- max(2026-02-01, 2026-03-01) == 2026-03-01 -- so
            # it was advanced by this batch, not carried over from an older one.
            row = store.db.execute("SELECT properties FROM sources WHERE id = ?", (src,)).fetchone()
            props = json.loads(row["properties"])
            assert props["checkpoint"]["since"] == "2026-03-01T00:00:00Z"
            batch_modstamps = ["2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z"]
            assert props["checkpoint"]["since"] == max(batch_modstamps)
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
            binding, handle = _handle()
            runner = _runner(binding, handle, real_vault, port, tmp_path)
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

    def test_soql_partial_failure_does_not_advance_checkpoint(
        self, trust_loopback, real_vault, tmp_path
    ):
        """A partial ingest MUST NOT advance the watermark.

        This is the negative half of the checkpoint contract: the presence of a
        checkpoint only means SOME batch fully persisted. Here the second row
        (the one carrying the batch-max SystemModstamp 2026-03-01) fails to
        persist, so ``fully_persisted`` is False, the shared sync leaves the
        checkpoint where it was (absent), and no "false complete" deletion runs.
        The next sync therefore re-attempts from the same watermark.
        """
        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/sobjects/Account/describe": _b(_DESCRIBE_BODY),
            "/services/data/v60.0/query": _b(_SOQL_PAGE1),
            _SOQL_CURSOR_PATH: _b(_SOQL_PAGE2),
        }
        server, served, port = _serve(script, certfile, keyfile)
        store = KnowledgeStore(str(tmp_path / "sfpartial.db"))

        class _FailSecondRowPipeline(IngestionPipeline):
            # Fail ONLY the batch-max row (Globex / 2026-03-01). The first row
            # (Acme / 2026-02-01) persists; the batch is therefore PARTIAL.
            async def ingest_text(self, text, *a, **k):  # type: ignore[override]
                if "Globex" in text:
                    raise RuntimeError("injected per-row persist failure")
                return await super().ingest_text(text, *a, **k)

        base = _pipeline(store)
        pipeline = _FailSecondRowPipeline(
            store=store,
            extractor=base.extractor,
            chunker=base.chunker,
            reader=base.reader,
            embedder=None,
        )
        try:
            binding, handle = _handle()
            runner = _runner(binding, handle, real_vault, port, tmp_path)
            conn = SalesforceStructuredConnector(call_runner=runner)
            src = store.add_source(
                "SF Account partial",
                "salesforce",
                "salesforce://object/Account",
                properties={"instance_url": f"https://localhost:{port}", "org_id": ORG},
            )
            sched = SyncScheduler(store, pipeline, {"salesforce": conn})
            out = asyncio.run(sched.sync_source(src))
        finally:
            server.shutdown()
        try:
            # Partial: not fully persisted -> checkpoint NOT advanced.
            assert out["synced"] is False
            assert out["checkpoint_advanced"] is False
            props = json.loads(
                store.db.execute("SELECT properties FROM sources WHERE id = ?", (src,)).fetchone()[
                    "properties"
                ]
            )
            # The watermark stayed where it was (absent) -- NOT advanced to the
            # batch-max modstamp, because the max-modstamp row is exactly the one
            # that failed. The next sync re-attempts from here.
            assert "checkpoint" not in props or props.get("checkpoint", {}).get("since") is None
            # Only the row that succeeded is in the ledger; the failed row is not
            # recorded active (no item without its grant, no phantom completion).
            state = store.get_connector_row_state(src)
            assert len(state) == 1
        finally:
            store.close()


def _binding_named(*, subject: str, tenant: str, secret_name: str):
    """A Salesforce binding for a DISTINCT identity with its OWN vault entry name.

    Two sources in two tenants must resolve two DIFFERENT credentials; the store
    reads secret_ref off the binding's own record, so a per-binding secret_ref
    name is exactly the axis that keeps them apart.
    """
    b = create_binding(
        service_id="salesforce",
        claimed_subject=subject,
        claimed_tenant=tenant,
        credential_mode="oauth_user",
        verifier=_verifier,
        slug="salesforce",
    )  # type: ignore[arg-type]
    b["secret_ref"] = dict(b["secret_ref"])  # type: ignore[index]
    b["secret_ref"]["name"] = secret_name  # type: ignore[index]
    return b


class TestMultiSourceIdentity:
    """Different sources resolve their OWN per-source binding/auth, no cross-talk.

    New-API (BindingCustodyGate) coverage: each source's runner is composed for
    ITS binding, and the live store hands back THAT binding's secret_ref -- so the
    wire request for source A carries A's token and B's carries B's. And a runner
    whose gate is composed for binding A, driven with a handle for binding B, is
    FENCED (BindingIdentityMismatchError -> typed refusal) with ZERO bytes sent:
    no credential of A ever reaches a call routed for B.
    """

    def test_two_sources_use_their_own_credentials_and_gate_fences_cross_binding(
        self, trust_loopback, real_vault, tmp_path
    ):
        import time as _time

        certfile, keyfile = trust_loopback
        script = {
            "/services/data/v60.0/analytics/reports/00O000000000001": _b(_REPORT_BODY),
        }
        server, served, port = _serve(script, certfile, keyfile)

        # Two DISTINCT bindings, each with its OWN vault entry + token.
        bind_a = _binding_named(subject="alice", tenant="acme", secret_name="SF_TOKEN_A")
        bind_b = _binding_named(subject="bob", tenant="globex", secret_name="SF_TOKEN_B")
        real_vault.set_sync("SF_TOKEN_A", "token-for-acme-alice")
        real_vault.set_sync("SF_TOKEN_B", "token-for-globex-bob")

        # ONE live store holding BOTH bindings (the shared L04 store).
        store = BindingStore(tmp_path / "connections" / "control_plane_bindings.json")
        store.insert(bind_a, deployment_id="dep://a", kiro_principal="kiro://owner/a")
        store.insert(bind_b, deployment_id="dep://b", kiro_principal="kiro://owner/b")

        def _mk_runner(binding):
            handle = derive_binding_handle(binding)
            view = ensure_usable(handle, now=_time.time())
            gate = BindingCustodyGate(binding=binding, binding_fingerprint=view.binding_fingerprint)
            auth = SalesforceAuthContext(
                handle=handle,
                offered_mode="oauth_user",
                permitted=declare_permitted_modes(("oauth_user",)),
                governance_item="salesforce.read",
            )
            return handle, SalesforceProductionRunner(
                gate=gate, store=store, vault=real_vault, auth=auth, http_send=urllib_http_send
            )

        try:
            _ha, runner_a = _mk_runner(bind_a)
            _hb, runner_b = _mk_runner(bind_b)

            conn_a = SalesforceStructuredConnector(call_runner=runner_a)
            conn_b = SalesforceStructuredConnector(call_runner=runner_b)
            src_a = {
                "id": "src-a",
                "uri": "salesforce://report/00O000000000001",
                "instance_url": f"https://localhost:{port}",
                "org_id": ORG,
                "report_id": "00O000000000001",
            }
            src_b = dict(src_a, id="src-b")

            rows_a, _snap_a, _cp_a = asyncio.run(conn_a.fetch_rows(src_a))
            n_after_a = len(served.authorization)
            rows_b, _snap_b, _cp_b = asyncio.run(conn_b.fetch_rows(src_b))

            # Each source really read (rows came back over the wire).
            assert rows_a and rows_b
            # Source A's request(s) carried A's token; B's carried B's -- no
            # cross-contamination. served.authorization is ordered by arrival.
            auth_a = served.authorization[:n_after_a]
            auth_b = served.authorization[n_after_a:]
            assert auth_a and all(h == "Bearer token-for-acme-alice" for h in auth_a)
            assert auth_b and all(h == "Bearer token-for-globex-bob" for h in auth_b)

            # Cross-binding: a runner whose GATE is for A, driven with B's handle,
            # is fenced -- no A credential leaks to a B-routed call, ZERO bytes.
            hb = derive_binding_handle(bind_b)
            view_a = ensure_usable(_ha, now=_time.time())
            gate_a = BindingCustodyGate(
                binding=bind_a, binding_fingerprint=view_a.binding_fingerprint
            )
            mismatched_auth = SalesforceAuthContext(
                handle=hb,  # a handle for B
                offered_mode="oauth_user",
                permitted=declare_permitted_modes(("oauth_user",)),
                governance_item="salesforce.read",
            )
            crossed = SalesforceProductionRunner(
                gate=gate_a,  # gate composed for A
                store=store,
                vault=real_vault,
                auth=mismatched_auth,
                http_send=urllib_http_send,
            )
            before = len(served.authorization)
            conn_x = SalesforceStructuredConnector(call_runner=crossed)
            with pytest.raises(Exception):
                asyncio.run(conn_x.fetch_rows(dict(src_a)))
            # The fence refused before any byte crossed the wire.
            assert len(served.authorization) == before
        finally:
            server.shutdown()
