"""Salesforce query-time grant revalidation -- the per-provider live check.

The shared side already defines the seam
(:class:`kiro_crew.knowledge.acl.RevalidationHook` /
:meth:`revalidate(ctx, item_id, grant) -> str`) and the three outcomes
(:class:`~kiro_crew.knowledge.acl.RevalidationOutcome`). This module is the
Salesforce PROVIDER-SIDE implementation of it: given the querying context and a
managed item, it asks Salesforce -- **as the query subject's own binding** --
whether that subject can STILL see the specific record / report the item was
ingested from, turning a static ingest-time grant into a live check.

Fail-closed by construction (never guesses ``FRESH``):

* the resource ref cannot be found / parsed for the item        -> UNVERIFIABLE
* no probe runner resolves for THIS subject on THIS resource     -> UNVERIFIABLE
  (the query subject holds no Salesforce binding on that org, or the credential
  association does not exist yet -- see the NAMED GAP below)
* the probe errors / times out                                   -> UNVERIFIABLE
* the probe confirms the subject can NO LONGER see it            -> REVOKED
* the probe confirms the subject can still see it                -> FRESH

**Never the ingest service account.** The probe is composed for the QUERY
subject's binding, resolved per (provider, account, subject) -- reusing the
ingest identity would apply ingest permissions to a query, which is exactly the
over-broad-access defect this check exists to close. The subject->binding
association is the W01/L04 side; this module NAMES it as an injected seam
(:class:`SalesforceSubjectProbeResolver`) and returns UNVERIFIABLE when it is
absent, rather than fabricating a subject/handle/credential.

Two grains, never conflated:

* **SOQL object path** -- a per-RECORD probe (``SELECT Id FROM <sobjectType>
  WHERE Id = <recordId>`` as the subject): a row means still-visible, an empty
  result means revoked at the record level.
* **Report path** -- no per-record locator exists, so the probe is at REPORT
  grain (can the subject still run this report). A report-grain result is NEVER
  presented as a record-grain conclusion.

A within-staleness cache is allowed, but it is keyed on
``(subject, tenant, provider, account, resource_id, grain)`` so a cached answer
NEVER crosses a subject or a resource.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Protocol

from kiro_crew.knowledge.acl import (
    AccessContext,
    ItemGrant,
    ProviderResourceRef,
    RevalidationOutcome,
)

#: The provider id this revalidator answers for.
PROVIDER = "salesforce"

#: Default within-window cache TTL (seconds). Kept at/under the ACL layer's
#: DEFAULT_STALENESS_SECS so a cached FRESH never outlives the staleness window.
DEFAULT_PROBE_CACHE_TTL = 300.0


class SalesforceSubjectProbe(Protocol):
    """A live Salesforce permission probe bound to ONE subject's credential.

    Resolved per (query subject, resource) by a
    :class:`SalesforceSubjectProbeResolver`, so every method here runs AS THAT
    SUBJECT -- never the ingest service account. Each method answers a single
    yes/no visibility question and MUST raise on any provider error/timeout (the
    revalidator maps a raise to UNVERIFIABLE).
    """

    def record_visible(self, *, instance_url: str, sobject_type: str, record_id: str) -> bool:
        """True iff the subject can still SELECT this record (SOQL object grain)."""
        ...

    def report_visible(self, *, instance_url: str, report_id: str) -> bool:
        """True iff the subject can still run this report (report grain)."""
        ...


class SalesforceSubjectProbeResolver(Protocol):
    """NAMED GAP seam: map (query subject, resource) -> a per-subject probe.

    This is the W01/L04 side that is still being wired: resolving WHICH
    Salesforce binding/credential belongs to the query subject on a given
    (provider, account) and composing a probe that authenticates AS that subject.
    Installed by the host on ``app['salesforce_subject_probe_resolver']``.

    Returns ``None`` when the subject holds no usable Salesforce binding for the
    resource's org -- in which case the revalidator returns UNVERIFIABLE
    (fail-closed), it does NOT fall back to the ingest identity or another
    subject's binding.
    """

    def resolve(
        self, ctx: AccessContext, resource: ProviderResourceRef
    ) -> Optional[SalesforceSubjectProbe]: ...


#: How the revalidator finds WHICH provider object an item was ingested from:
#: the ingest path persisted a ProviderResourceRef on the item's grant row
#: (item_acl.resource_ref); this looks it up by item_id. The host injects a
#: reader over the store (kept a plain callable so this module holds no store
#: handle). Returns None when the item has no/parse-failed resource ref ->
#: UNVERIFIABLE.
SalesforceResourceLookup = Callable[[str], Optional[ProviderResourceRef]]


@dataclass(frozen=True)
class _CacheKey:
    subject: str
    tenant: str
    account: str
    resource_id: str
    grain: str


class SalesforceGrantRevalidator:
    """Provider-side :class:`~kiro_crew.knowledge.acl.RevalidationHook` for Salesforce.

    Construction (all injected by the host; this module composes no identity):

    * ``resource_lookup`` -- ``item_id -> ProviderResourceRef | None`` (over the
      store's persisted ``item_acl.resource_ref``).
    * ``probe_resolver`` -- the NAMED-GAP seam mapping (subject, resource) to a
      per-subject probe; ``None`` (or its ``resolve`` returning ``None``) means
      the credential association for this subject is not available -> UNVERIFIABLE.
    * ``cache_ttl`` / ``clock`` -- the within-window cache (per subject+resource).

    :meth:`revalidate` matches the shared Protocol exactly:
    ``revalidate(ctx, item_id, grant) -> str`` (one of RevalidationOutcome).
    """

    def __init__(
        self,
        *,
        resource_lookup: SalesforceResourceLookup,
        probe_resolver: Optional[SalesforceSubjectProbeResolver],
        cache_ttl: float = DEFAULT_PROBE_CACHE_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resource_lookup = resource_lookup
        self._probe_resolver = probe_resolver
        self._cache_ttl = cache_ttl
        self._clock = clock
        self._cache: dict[_CacheKey, tuple[float, str]] = {}

    # -- the shared RevalidationHook contract --------------------------------
    def revalidate(self, ctx: AccessContext, item_id: str, grant: ItemGrant) -> str:
        """Answer FRESH / REVOKED / UNVERIFIABLE for one managed Salesforce item.

        Fail-closed on every unresolved input; only a real successful probe that
        confirms visibility yields FRESH.
        """
        # A bypass/local ctx carries no provider-mapped subject: a managed item
        # can never be verified as a specific subject, so it is UNVERIFIABLE
        # here (and the retriever already denies it upstream).
        if ctx.bypass_acl or not ctx.subject:
            return RevalidationOutcome.UNVERIFIABLE

        resource = self._resource_lookup(item_id)
        if resource is None or resource.provider != PROVIDER:
            # No resource ref (or not ours) -> cannot locate the object to probe.
            return RevalidationOutcome.UNVERIFIABLE

        loc: Mapping[str, object] = resource.locator or {}
        instance_url = str(loc.get("instanceUrl") or "").strip()
        record_id = str(loc.get("recordId") or "").strip()
        report_id = str(loc.get("reportId") or "").strip()
        sobject_type = str(loc.get("sobjectType") or "").strip()
        if not instance_url:
            return RevalidationOutcome.UNVERIFIABLE

        # Grain: a record locator is per-record (SOQL object path); otherwise a
        # report locator is report-grain. Never present a report-grain answer as
        # a record-grain one -- they are distinct cache keys and distinct probes.
        if sobject_type and record_id:
            grain = "record"
            probe_id = record_id
        elif report_id:
            grain = "report"
            probe_id = report_id
        else:
            return RevalidationOutcome.UNVERIFIABLE

        # NAMED GAP: resolve the probe AS THIS SUBJECT. Absent seam or no binding
        # for the subject -> UNVERIFIABLE (never the ingest identity).
        if self._probe_resolver is None:
            return RevalidationOutcome.UNVERIFIABLE
        probe = self._probe_resolver.resolve(ctx, resource)
        if probe is None:
            return RevalidationOutcome.UNVERIFIABLE

        key = _CacheKey(
            subject=ctx.subject,
            tenant=ctx.tenant,
            account=resource.account,
            resource_id=probe_id,
            grain=grain,
        )
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        try:
            if grain == "record":
                visible = probe.record_visible(
                    instance_url=instance_url,
                    sobject_type=sobject_type,
                    record_id=record_id,
                )
            else:
                visible = probe.report_visible(instance_url=instance_url, report_id=report_id)
        except Exception:
            # Any error/timeout: fail-closed, and do NOT cache (a transient error
            # must not pin an item unverifiable for the whole window).
            return RevalidationOutcome.UNVERIFIABLE

        outcome = RevalidationOutcome.FRESH if visible else RevalidationOutcome.REVOKED
        self._cache_put(key, outcome)
        return outcome

    # -- within-window cache (never crosses subject or resource) -------------
    def _cache_get(self, key: _CacheKey) -> Optional[str]:
        hit = self._cache.get(key)
        if hit is None:
            return None
        stored_at, outcome = hit
        if self._clock() - stored_at > self._cache_ttl:
            self._cache.pop(key, None)
            return None
        return outcome

    def _cache_put(self, key: _CacheKey, outcome: str) -> None:
        self._cache[key] = (self._clock(), outcome)


__all__ = [
    "PROVIDER",
    "DEFAULT_PROBE_CACHE_TTL",
    "SalesforceGrantRevalidator",
    "SalesforceResourceLookup",
    "SalesforceSubjectProbe",
    "SalesforceSubjectProbeResolver",
]
