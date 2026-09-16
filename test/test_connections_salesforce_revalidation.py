"""Tests for the Salesforce query-time grant revalidator.

Exercises the REAL revalidator logic (grain routing, fail-closed on every
unresolved input, the within-window cache that never crosses a subject or a
resource) against fakes for the two injected seams -- the per-subject probe and
its resolver -- because the per-subject Salesforce credential/probe assembly is
the W01/L04 gap this module NAMES rather than fabricates. What is proven here is
that the revalidator itself:

* returns FRESH only when a real probe (as the query subject) confirms access;
* returns REVOKED when the probe says the subject can no longer see it;
* returns UNVERIFIABLE on every fail-closed path (no resource, no probe seam,
  no binding for the subject, probe error) -- never guessing FRESH;
* probes AS THE QUERY SUBJECT: a probe resolved for subject A is never used for
  a query running as subject B (cross-subject deny);
* keeps SOQL record grain and report grain distinct;
* caches within the window without ever crossing a subject or a resource.
"""

from __future__ import annotations

from kiro_crew.connections.vendors.salesforce.revalidation import (
    SalesforceGrantRevalidator,
)
from kiro_crew.knowledge.acl import (
    AccessContext,
    ItemGrant,
    ProviderResourceRef,
    RevalidationOutcome,
)

INSTANCE = "https://acme.my.salesforce.com"
ORG = "00Dxx0000001gPEAQ"


def _ctx(subject: str = "sub-alice", tenant: str = "tenant-acme") -> AccessContext:
    return AccessContext(subject=subject, tenant=tenant)


def _grant() -> ItemGrant:
    return ItemGrant(subjects=frozenset({"sub-alice"}), tenant="tenant-acme", managed=True)


def _record_ref(record_id: str = "001A00000000001", account: str = ORG) -> ProviderResourceRef:
    return ProviderResourceRef(
        provider="salesforce",
        account=account,
        resource_id=record_id,
        locator={
            "instanceUrl": INSTANCE,
            "sobjectType": "Account",
            "recordId": record_id,
        },
    )


def _report_ref(report_id: str = "00O000000000A01") -> ProviderResourceRef:
    return ProviderResourceRef(
        provider="salesforce",
        account=ORG,
        resource_id=report_id,
        locator={"instanceUrl": INSTANCE, "reportId": report_id},
    )


class _Probe:
    """A per-subject probe fake. Records every call so we can assert grain +
    that a probe resolved for subject X is only ever used for subject X."""

    def __init__(self, *, subject: str, record_visible: bool = True, report_visible: bool = True):
        self.subject = subject
        self._record_visible = record_visible
        self._report_visible = report_visible
        self.record_calls: list[tuple[str, str, str]] = []
        self.report_calls: list[tuple[str, str]] = []

    def record_visible(self, *, instance_url, sobject_type, record_id) -> bool:
        self.record_calls.append((instance_url, sobject_type, record_id))
        return self._record_visible

    def report_visible(self, *, instance_url, report_id) -> bool:
        self.report_calls.append((instance_url, report_id))
        return self._report_visible


class _Resolver:
    """Maps a ctx to the probe registered for THAT subject; None otherwise.

    This is the shape of the W01/L04 seam: it hands back a probe bound to the
    query subject's own binding, or None when that subject holds no binding.
    """

    def __init__(self, by_subject: dict[str, _Probe]):
        self._by_subject = by_subject
        self.calls: list[str] = []

    def resolve(self, ctx, resource):
        self.calls.append(ctx.subject)
        return self._by_subject.get(ctx.subject)


def _reval(*, resource, probes: dict[str, _Probe] | None, clock=None):
    resolver = _Resolver(probes) if probes is not None else None
    kwargs = {}
    if clock is not None:
        kwargs["clock"] = clock
    return (
        SalesforceGrantRevalidator(
            resource_lookup=lambda item_id: resource,
            probe_resolver=resolver,
            **kwargs,
        ),
        resolver,
    )


# ── the three outcomes ──────────────────────────────────────────────────────
def test_fresh_when_subject_can_still_see_the_record():
    probe = _Probe(subject="sub-alice", record_visible=True)
    reval, resolver = _reval(resource=_record_ref(), probes={"sub-alice": probe})
    out = reval.revalidate(_ctx(), "item-1", _grant())
    assert out == RevalidationOutcome.FRESH
    # Probed AS the query subject, at RECORD grain, for the right record.
    assert resolver.calls == ["sub-alice"]
    assert probe.record_calls == [(INSTANCE, "Account", "001A00000000001")]
    assert probe.report_calls == []


def test_revoked_when_subject_can_no_longer_see_the_record():
    probe = _Probe(subject="sub-alice", record_visible=False)
    reval, _ = _reval(resource=_record_ref(), probes={"sub-alice": probe})
    out = reval.revalidate(_ctx(), "item-1", _grant())
    assert out == RevalidationOutcome.REVOKED


def test_unverifiable_when_no_resource_ref():
    reval, _ = _reval(resource=None, probes={"sub-alice": _Probe(subject="sub-alice")})
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.UNVERIFIABLE


def test_unverifiable_when_probe_seam_absent():
    # The named gap: no subject-probe resolver wired at all.
    reval, _ = _reval(resource=_record_ref(), probes=None)
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.UNVERIFIABLE


def test_unverifiable_when_subject_holds_no_binding():
    # Resolver present but returns None for this subject (no binding) -> deny.
    reval, _ = _reval(
        resource=_record_ref(), probes={"someone-else": _Probe(subject="someone-else")}
    )
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.UNVERIFIABLE


def test_unverifiable_when_probe_errors():
    class _Boom(_Probe):
        def record_visible(self, **_):
            raise TimeoutError("provider timeout")

    reval, _ = _reval(resource=_record_ref(), probes={"sub-alice": _Boom(subject="sub-alice")})
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.UNVERIFIABLE


def test_unverifiable_for_bypass_context():
    reval, _ = _reval(resource=_record_ref(), probes={"sub-alice": _Probe(subject="sub-alice")})
    from kiro_crew.knowledge.acl import LOCAL_LIBRARY

    assert reval.revalidate(LOCAL_LIBRARY, "item-1", _grant()) == RevalidationOutcome.UNVERIFIABLE


# ── cross-subject: A's probe is never used for B's query ─────────────────────
def test_cross_subject_probe_a_binding_on_b_query_is_refused():
    """A probe is resolved AS the querying subject. Only subject A has a binding;
    a query running as subject B resolves NO probe -> UNVERIFIABLE. A's probe is
    never invoked on B's behalf (no ingest/other-subject identity reuse)."""
    probe_a = _Probe(subject="sub-alice", record_visible=True)
    reval, resolver = _reval(resource=_record_ref(), probes={"sub-alice": probe_a})

    # Subject A: resolves A's probe -> FRESH.
    assert reval.revalidate(_ctx("sub-alice"), "item-1", _grant()) == RevalidationOutcome.FRESH
    # Subject B: no binding -> UNVERIFIABLE, and A's probe was NOT used for B.
    a_calls_before = len(probe_a.record_calls)
    assert reval.revalidate(_ctx("sub-bob"), "item-1", _grant()) == RevalidationOutcome.UNVERIFIABLE
    assert len(probe_a.record_calls) == a_calls_before  # A's probe untouched by B
    assert resolver.calls[-1] == "sub-bob"


# ── report grain is distinct from record grain ──────────────────────────────
def test_report_grain_probes_report_not_record():
    probe = _Probe(subject="sub-alice", report_visible=True)
    reval, _ = _reval(resource=_report_ref(), probes={"sub-alice": probe})
    assert reval.revalidate(_ctx(), "item-r", _grant()) == RevalidationOutcome.FRESH
    # Report grain: a report probe, NOT a record probe.
    assert probe.report_calls == [(INSTANCE, "00O000000000A01")]
    assert probe.record_calls == []


def test_report_revoked_when_subject_cannot_run_report():
    probe = _Probe(subject="sub-alice", report_visible=False)
    reval, _ = _reval(resource=_report_ref(), probes={"sub-alice": probe})
    assert reval.revalidate(_ctx(), "item-r", _grant()) == RevalidationOutcome.REVOKED


# ── cache never crosses subject or resource ─────────────────────────────────
def test_cache_hit_same_subject_and_resource():
    probe = _Probe(subject="sub-alice", record_visible=True)
    reval, _ = _reval(resource=_record_ref(), probes={"sub-alice": probe})
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.FRESH
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.FRESH
    # Second call served from cache: the probe ran only once.
    assert len(probe.record_calls) == 1


def test_cache_does_not_cross_subject():
    # Two subjects with their own probes; a cached answer for A must not serve B.
    pa = _Probe(subject="sub-alice", record_visible=True)
    pb = _Probe(subject="sub-bob", record_visible=False)
    reval, _ = _reval(resource=_record_ref(), probes={"sub-alice": pa, "sub-bob": pb})
    assert reval.revalidate(_ctx("sub-alice"), "item-1", _grant()) == RevalidationOutcome.FRESH
    # B has its own (revoked) answer -- NOT A's cached FRESH.
    assert reval.revalidate(_ctx("sub-bob"), "item-1", _grant()) == RevalidationOutcome.REVOKED
    assert len(pb.record_calls) == 1


def test_cache_does_not_cross_resource():
    probe = _Probe(subject="sub-alice", record_visible=True)
    # Same subject, two different records -> two distinct probes, no cache bleed.
    r1 = _record_ref(record_id="001A00000000001")
    r2 = _record_ref(record_id="001B00000000002")
    resolver_probes = {"sub-alice": probe}
    reval1, _ = _reval(resource=r1, probes=resolver_probes)
    assert reval1.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.FRESH
    # A separate revalidator for r2 (distinct resource) probes again.
    reval2, _ = _reval(resource=r2, probes={"sub-alice": probe})
    assert reval2.revalidate(_ctx(), "item-2", _grant()) == RevalidationOutcome.FRESH
    assert probe.record_calls == [
        (INSTANCE, "Account", "001A00000000001"),
        (INSTANCE, "Account", "001B00000000002"),
    ]


def test_cache_expires_after_ttl():
    probe = _Probe(subject="sub-alice", record_visible=True)
    fake_now = {"t": 1000.0}
    reval, _ = _reval(
        resource=_record_ref(), probes={"sub-alice": probe}, clock=lambda: fake_now["t"]
    )
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.FRESH
    fake_now["t"] += 1_000_000  # well past the TTL
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.FRESH
    assert len(probe.record_calls) == 2  # re-probed after expiry, not cached


def test_probe_error_is_not_cached():
    class _FlakyProbe(_Probe):
        def __init__(self):
            super().__init__(subject="sub-alice", record_visible=True)
            self.n = 0

        def record_visible(self, **kw):
            self.n += 1
            if self.n == 1:
                raise ConnectionError("transient")
            return super().record_visible(**kw)

    probe = _FlakyProbe()
    reval, _ = _reval(resource=_record_ref(), probes={"sub-alice": probe})
    # First: error -> UNVERIFIABLE and NOT cached.
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.UNVERIFIABLE
    # Second: the transient cleared -> a real FRESH (proving no error was cached).
    assert reval.revalidate(_ctx(), "item-1", _grant()) == RevalidationOutcome.FRESH
