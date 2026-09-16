"""W01 · L04: the host-side adapter that satisfies the knowledge ACL's
``BindingResolver`` seam, backed by the trusted binding store.

WHY THIS FILE EXISTS
--------------------
The knowledge subsystem's ACL (``kiro_crew.knowledge.acl``) gates every managed
(cloud/structured) item behind a per-candidate identity check. It does NOT know
how a principal maps to a provider account -- that is a HOST/W01 concern -- so it
declares a seam and asks the host to fill it:

    class BindingResolver(Protocol):            # acl.py, @runtime_checkable
        def resolve(self, principal, provider, account) -> AccessContext | None: ...

    # "Implemented by the host/W01 layer, not here."  -- acl.py docstring

This module is that host implementation. It maps ONE candidate's
``(principal, provider, account)`` to the provider-mapped identity the principal
holds there, reading it from L04's trusted :class:`BindingStore`.

CALL-SHAPE CONFORMANCE, AND WHY THAT IS NOT THE WHOLE CONTRACT
--------------------------------------------------------------
``BindingResolver`` is a ``@runtime_checkable`` ``Protocol``. This adapter matches
its CALL SHAPE -- ``resolve(self, principal, provider, account)`` returning a
value or ``None`` -- and it does NOT import ``kiro_crew.knowledge.acl`` (that is a
knowledge-side module on an un-merged branch; importing it here would invert the
dependency and is not reachable from a control-plane wheel).

But matching the method signature is NOT the same as producing an object the ACL
can consume. The ACL's own gate reads a field this adapter does NOT produce:
``_subject_tenant_ok`` evaluates ``grant.subjects & ctx.subject_ids``, where
``ctx.subject_ids`` is a ``@property`` on ACL's ``AccessContext``
(``frozenset({subject, *groups})``). **W01 has no ``subject_ids`` anywhere** -- so
the :class:`AccessGrant` this adapter returns CANNOT be handed to the ACL gate
as-is; doing so would raise ``AttributeError`` at ``ctx.subject_ids``. Claiming
the grant is interchangeable with, or drop-in usable by, ACL's ``AccessContext``
would be exactly the kind of "documented property that does not exist" this stack
has been bitten by before, so this module does not claim it.

THE ACTUAL BRIDGE CHAIN
-----------------------
What W01 produces and what the ACL still has to do are two different halves:

1. W01 (this module) hands the ACL an :class:`AccessGrant` carrying the
   provider-mapped, VERIFIED identity for one candidate: ``subject`` and
   ``tenant`` from the resolved binding's ``subject_ref`` / ``tenant_ref``, and
   ``groups`` empty (W01 does not produce a group dimension).
2. The ACL side consumes commit ``dd715f12a`` via ordinary git and, ON THE ACL
   SIDE, bridges an :class:`AccessGrant` into its own ``AccessContext`` --
   constructing ``AccessContext(subject=grant.subject, tenant=grant.tenant,
   groups=grant.groups)`` (or equivalent), which is where the ``subject_ids``
   property comes into existence. ``subject_ids`` is an ACL-OWNED derivation, NOT
   a field W01 emits.

So :class:`AccessGrant` is a plainly-named W01 transport record, deliberately NOT
a re-implementation of ACL's ``AccessContext`` (we do not copy the ACL class, its
``__post_init__`` invariant, or its ``subject_ids`` property). The one thing W01
does NOT cover, and the ACL side MUST supply, is stated explicitly: the
``subject_ids`` derivation the gate reads.

Because the Protocol type is not importable here, this module cannot assert
``isinstance(adapter, BindingResolver)``; the tests pin the CALL shape directly
and, separately, pin the bridge-chain contract (what fields ``AccessGrant``
carries AND that ``subject_ids`` is NOT among them, i.e. is left to the ACL).

WHAT W01 PUTS IN EACH FIELD IT DOES EMIT
----------------------------------------
* ``subject`` / ``tenant`` <- the resolved binding's ``subject_ref`` /
  ``tenant_ref``. These were produced by the ``SubjectTenantVerifier`` at INSERT
  time and stored; :meth:`BindingStore.resolve_for_acl` returns the STORED values
  and takes no caller-claimed identity -- so the tenant is a VERIFIED provider
  tenant read from the trusted store, the "trusted tenant" discipline.
* ``groups`` <- ALWAYS empty (``frozenset()``). W01 does NOT produce or invent a
  group/role dimension: a binding authorizes ONE provider identity, not a set of
  team/org roles. Group membership is a separate authority (the provider's
  directory/graph); the ACL side owns it. Fabricating groups here would be an
  unverified privilege grant.
* ``bypass_acl`` <- ALWAYS ``False``. ``bypass_acl=True`` is the ACL's LOCAL
  single-user library context; a provider binding is a managed, cross-identity
  path, so W01 never sets it true. That context is minted ACL-side.

THE ``account`` -> ``deployment_id`` AXIS (a named seam, not a silent equation)
-------------------------------------------------------------------------------
The ACL keys the resolver on ``(provider, account)``, where ``account`` is the
VENDOR-side account/tenant/org an object lives in -- per acl.py, "a Graph tenant
id, a Salesforce org id, a Drive driveId, a GitHub org/login, a Slack workspace
id". L04's uniqueness domain instead keys on ``deployment_id`` =
"the PROVIDER-SIDE deployment that hosts the account (a GitHub Enterprise host, a
Salesforce org, a Graph tenant deployment)". These are DIFFERENT axes:

* a GitHub ``account`` (org/login) is NOT a GHE host -- two orgs on one GHE host
  would collapse to one "deployment" if account were used verbatim;
* a Graph ``account`` may be a ``driveId`` (a resource), not the tenant
  deployment; using it as ``deployment_id`` would also duplicate ``tenant_ref``,
  which already carries the verified tenant.

So this adapter does NOT pass ``deployment_id=account`` (the previous round did,
and that silently mislabelled a vendor account as a hosting deployment). Instead
it takes an explicit, injected ``account_to_deployment`` seam that a host wires
to translate ``(service_id, account)`` into the ``deployment_id`` that hosts it.
When no such mapping is provided, or it returns ``None``, this adapter FAILS
CLOSED (returns ``None``) rather than guess -- and the absence of a
first-class ``(service_id, account) -> deployment_id`` registry in W01 today is a
REAL, NAMED gap (see the report / the ``test_account_to_deployment_*`` tests),
not something to paper over by equating the two axes.

FAIL-CLOSED
-----------
Per the Protocol, ``resolve`` returns ``None`` -- deny this candidate -- for every
"no usable binding" case: an unmappable ``provider`` string, an
unverified/empty/local principal, an ``account`` this host cannot map to a
deployment, and a principal that holds no (or a revoked) binding on the resolved
(deployment, service). It raises only when the trusted store itself is unreadable
(corruption is surfaced, not silently read as "no binding").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from kiro_crew.connections.control_plane.lifecycle import BindingStore
from kiro_crew.connections.control_plane.operation import SERVICE_IDS, ServiceId

#: A host-provided translation from an ACL ``(service_id, account)`` -- the
#: VENDOR-side account/org/tenant/driveId a candidate lives in -- to the L04
#: ``deployment_id`` (the provider-side deployment that HOSTS that account). It
#: returns ``None`` when the host holds no deployment for that pair, which makes
#: the resolver fail closed. This is a seam, not a default: W01 has no built-in
#: ``(service_id, account) -> deployment_id`` registry yet (a named gap), so a
#: host that has not wired one gets fail-closed denials rather than a wrong axis.
AccountToDeployment = Callable[[ServiceId, str], Optional[str]]

#: Maps the ACL's ``provider`` connector-id (a free ``str`` on the ACL side, from
#: a candidate's ``ProviderResourceRef.provider``) to W01's CLOSED
#: :data:`ServiceId` set. The ACL uses ``'excel'`` for the Graph workbook
#: provider where W01's manifest range is ``'excel_shared_engine'``; every other
#: id the ACL lists ('sharepoint','onedrive','onenote','teams','outlook',
#: 'gmail','google_drive','salesforce','github','zoom','slack','asana') is a
#: verbatim member of :data:`ServiceId` and maps 1:1. ``'office_documents'`` has
#: no ACL provider id (it is a capability set, not a per-candidate provider) and
#: is intentionally absent from the VALUES here -- it is still a valid
#: ``ServiceId``, just never a ``provider`` the ACL asks about.
_PROVIDER_ALIASES: dict[str, ServiceId] = {
    "excel": "excel_shared_engine",
}


def map_provider_to_service_id(provider: str) -> ServiceId | None:
    """Map an ACL ``provider`` string to a :data:`ServiceId`, or ``None``.

    The mapping is over a CLOSED set: an exact :data:`ServiceId` member maps to
    itself, a known alias (``'excel' -> 'excel_shared_engine'``) is translated,
    and ANY other string -- an unknown, misspelled, or free-form provider --
    returns ``None`` (REFUSE). We do not leniently accept arbitrary strings: an
    unrecognised provider is a candidate this resolver cannot vouch for, so the
    ACL must deny it, exactly as it denies an unresolvable binding.
    """

    if provider in _PROVIDER_ALIASES:
        return _PROVIDER_ALIASES[provider]
    if provider in SERVICE_IDS:
        # provider is a verbatim ServiceId member.
        return provider  # type: ignore[return-value]
    return None


@dataclass(frozen=True)
class AccessGrant:
    """A W01 transport record carrying one candidate's provider-mapped identity.

    This is NOT a re-implementation of ACL's ``AccessContext``: it deliberately
    carries only the fields W01 can VERIFY and produce, and it does NOT define
    ACL's ``subject_ids`` property or ``__post_init__`` invariant. The ACL side
    bridges this into its own ``AccessContext`` (see the module docstring's
    "bridge chain"), and that is where ``subject_ids`` is derived.

    * ``subject`` -- the verified provider subject id (the binding's
      ``subject_ref``), never a raw KiroCrew session key or a caller-asserted
      value.
    * ``tenant`` -- the verified provider tenant/org boundary (the binding's
      ``tenant_ref``), read from the trusted store.
    * ``groups`` -- always empty for W01; a separate authority owns group
      membership, and the ACL folds it into ``subject_ids`` on its side.
    * ``bypass_acl`` -- always ``False`` for W01 (a provider binding is a managed,
      cross-identity path; the local-library bypass is an ACL-side context).

    NOT COVERED HERE (the ACL side must supply it when bridging): ``subject_ids``,
    the ``frozenset({subject, *groups})`` derivation the ACL gate reads.
    """

    subject: str
    tenant: str
    groups: frozenset[str] = field(default_factory=frozenset)
    bypass_acl: bool = False


class ControlPlaneBindingResolver:
    """Host-side ``BindingResolver`` implementation, over the trusted store.

    Matches the ACL ``BindingResolver`` CALL shape --
    ``resolve(self, principal, provider, account)`` returning an
    :class:`AccessGrant` or ``None`` -- without importing the ACL module. The
    returned :class:`AccessGrant` is bridged into ACL's ``AccessContext`` on the
    ACL side (see the module docstring); the ACL gate cannot read it as-is, since
    it reads a ``subject_ids`` this adapter does not produce.

    Construct it with the :class:`BindingStore` that holds this host's admitted
    bindings and, optionally, an ``account_to_deployment`` seam that translates an
    ACL ``(service_id, account)`` into the L04 ``deployment_id`` hosting it. With
    no such seam the resolver fails closed on every candidate (it will not equate
    the vendor ``account`` with a ``deployment_id``). The resolver adds no state
    of its own and never mutates the store.
    """

    def __init__(
        self,
        store: BindingStore,
        *,
        account_to_deployment: AccountToDeployment | None = None,
    ) -> None:
        self._store = store
        self._account_to_deployment = account_to_deployment

    def resolve(self, principal: object, provider: str, account: str) -> AccessGrant | None:
        """Map one candidate's ``(principal, provider, account)`` to an identity.

        ``principal`` is the ACL's ``QueryPrincipal`` -- a structural object whose
        ``principal_id`` is the VERIFIED KiroCrew caller id (never self-reported).
        We read only ``principal.principal_id`` (duck-typed, so we do not import
        the ACL type). A principal marked ``local_library`` holds no provider
        binding by definition; if the attribute is present and true we deny
        (return ``None``) without touching the store.

        ``provider`` is the ACL connector id, mapped to a :data:`ServiceId` via
        :func:`map_provider_to_service_id`; an unmappable value REFUSES (``None``).

        ``account`` is the VENDOR-side account/org/tenant/driveId the object lives
        in -- NOT a ``deployment_id``. It is translated to the hosting
        ``deployment_id`` through the injected ``account_to_deployment`` seam; if
        no seam is wired, or it returns ``None``, we FAIL CLOSED rather than
        mislabel the account as a deployment (see the module docstring's account
        -> deployment note -- the missing built-in registry is a named gap).

        Returns the provider-mapped :class:`AccessGrant` (``subject`` / ``tenant``
        from the resolved binding's VERIFIED ``subject_ref`` / ``tenant_ref``), or
        ``None`` -- fail-closed -- for an unmappable provider, an
        unverified/empty/local principal, an unmappable account, or a principal
        that holds no (or a revoked) binding on the resolved (deployment, service).
        """

        service_id = map_provider_to_service_id(provider)
        if service_id is None:
            return None

        principal_id = getattr(principal, "principal_id", None)
        if not principal_id:
            return None
        if getattr(principal, "local_library", False):
            # A local-single-user principal has no cross-identity provider
            # binding; deny every managed candidate, do not consult the store.
            return None

        # The ACL account is a VENDOR account, not a deployment. Translate it to
        # the hosting deployment through the host seam; without one we cannot
        # resolve the deployment axis and must fail closed (never account==deploy).
        if self._account_to_deployment is None:
            return None
        deployment_id = self._account_to_deployment(service_id, account)
        if not deployment_id:
            return None

        binding = self._store.resolve_for_acl(
            kiro_principal=principal_id,
            deployment_id=deployment_id,
            service_id=service_id,
        )
        if binding is None:
            return None

        # subject/tenant come from the trusted store's VERIFIED refs, never from
        # the caller. groups empty and bypass_acl False per the module contract;
        # subject_ids is deliberately NOT produced here (ACL derives it on bridge).
        return AccessGrant(
            subject=binding["subject_ref"],
            tenant=binding["tenant_ref"],
            groups=frozenset(),
            bypass_acl=False,
        )
