"""The minimal PRODUCTION runner that drives Salesforce reads through W01.

:class:`~kiro_crew.knowledge.connectors.salesforce_structured.SalesforceCallRunner`
is a Protocol -- an interface with no concrete implementation. This module is the
concrete implementation, and it is deliberately MINIMAL: it composes the real W01
production transport
(:func:`kiro_crew.connections.control_plane.production.build_production_transport`)
with THIS vendor's request-locator and per-operation result-decoders, and drives
the REAL W01 executor
(:func:`kiro_crew.connections.control_plane.executor.execute` /
:class:`~kiro_crew.connections.control_plane.executor.PageWalk`) -- never a local
short-circuit. Every read therefore passes the full gate chain (trusted handle
view -> credential-mode permit -> governance intersection -> write-replay) before
any byte crosses the wire, and the credential is resolved per call from the real
vault by the real :class:`BindingSecretSelector`.

It builds ONE transport per operation-class, because
``build_production_transport`` takes ONE ``decode`` and the three Salesforce read
operations decode differently:

* SOQL query / query-more -> :func:`salesforce_soql_decode` (a paged collection;
  the real ``nextRecordsUrl`` becomes the envelope cursor);
* Analytics report -> :func:`salesforce_report_decode` (a bounded snapshot);
* sObject describe -> :func:`salesforce_describe_decode` (a single object).

All three share ONE locator (:func:`salesforce_request_locator`), ONE selector
and ONE vault -- no second auth, vault, pagination or transport. This is not a
bypass hook: it is the real assembly, and the final production registration
(wiring this runner into the knowledge connector factory) is a separate,
root-coordinated step; this module only provides the runner it will register.

**No real Salesforce business account.** The runner is credential-agnostic: it
authenticates as whatever binding the handle was issued for, resolved from the
isolated fixture vault in tests. Nothing here targets a live org.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from kiro_crew.connections.control_plane.auth_modes import PermittedModes
from kiro_crew.connections.control_plane.executor import (
    ExecutionOutcome,
    PageWalk,
    execute,
)
from kiro_crew.connections.control_plane.handle import DerivedHandle
from kiro_crew.connections.control_plane.operation import CredentialMode, OperationDescriptor
from kiro_crew.connections.control_plane.policy import LayerCeilings
from kiro_crew.connections.control_plane.production import (
    BindingSecretSelector,
    SecretStore,
    Transport,
    build_production_transport,
    urllib_http_send,
)
from kiro_crew.connections.vendors.salesforce.transport import (
    OP_DESCRIBE,
    OP_REPORT_RUN,
    OP_SOQL_QUERY,
    OP_SOQL_QUERY_MORE,
    salesforce_describe_decode,
    salesforce_report_decode,
    salesforce_request_locator,
    salesforce_soql_decode,
)

#: Per-operation decode routing: the ONE decode ``build_production_transport``
#: takes, chosen by the operation the transport will carry.
_DECODE_BY_OP = {
    OP_SOQL_QUERY: salesforce_soql_decode,
    OP_SOQL_QUERY_MORE: salesforce_soql_decode,
    OP_REPORT_RUN: salesforce_report_decode,
    OP_DESCRIBE: salesforce_describe_decode,
}


@dataclass(frozen=True)
class SalesforceAuthContext:
    """The per-source W01 authorization inputs the runner supplies to ``execute``.

    Assembled by the FACTORY at registration time from the resolved binding: the
    issued ``handle`` (the capability, never the binding), the single
    ``offered_mode`` this source authenticates with, the ``permitted`` modes for
    the operation, the ``layers`` governance ceilings, and the governance
    scope/item the read is gated by. The runner adds nothing to these -- it only
    passes them through to the real executor, so authorization is decided by W01,
    not here.
    """

    handle: DerivedHandle
    offered_mode: CredentialMode
    permitted: PermittedModes
    layers: LayerCeilings = field(default_factory=LayerCeilings)
    governance_scope: str = "tools"
    governance_item: str = "salesforce.read"


class SalesforceProductionRunner:
    """Concrete :class:`SalesforceCallRunner` over the real W01 executor.

    Constructed by the factory with the real ``selector`` (bound to the call's
    trusted binding identity), the real ``vault``, and the per-source
    :class:`SalesforceAuthContext`. It composes one production transport per
    operation-class and drives ``execute`` / ``PageWalk`` -- the same real
    executor path W01's own end-to-end TLS tests exercise.
    """

    def __init__(
        self,
        *,
        selector: BindingSecretSelector,
        vault: SecretStore,
        auth: SalesforceAuthContext,
        http_send: Any = urllib_http_send,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self._selector = selector
        self._vault = vault
        self._auth = auth
        self._http_send = http_send
        self._timeout_seconds = timeout_seconds
        self._transports: dict[str, Transport] = {}

    def _transport_for(self, operation_id: str) -> Transport:
        decode = _DECODE_BY_OP.get(operation_id)
        if decode is None:
            raise ValueError(f"no Salesforce decode for operation {operation_id!r}")
        cached = self._transports.get(operation_id)
        if cached is not None:
            return cached
        kwargs: dict[str, Any] = {
            "selector": self._selector,
            "vault": self._vault,
            "locator": salesforce_request_locator,
            "http_send": self._http_send,
            "decode": decode,
        }
        if self._timeout_seconds is not None:
            kwargs["timeout_seconds"] = self._timeout_seconds
        transport = build_production_transport(**kwargs)
        self._transports[operation_id] = transport
        return transport

    def _execute_kwargs(self) -> dict[str, Any]:
        # No `now`: execute() reads its clock fresh per call (and per page), so
        # handle expiry is re-judged on the real current instant, not one frozen
        # here -- the production posture the executor documents.
        return {
            "offered_mode": self._auth.offered_mode,
            "permitted": self._auth.permitted,
            "layers": self._auth.layers,
            "governance_scope": self._auth.governance_scope,
            "governance_item": self._auth.governance_item,
        }

    async def run(
        self, descriptor: OperationDescriptor, request_args: Mapping[str, Any]
    ) -> ExecutionOutcome:
        transport = self._transport_for(descriptor["operation_id"])
        return execute(
            descriptor,
            self._auth.handle,
            transport,
            request_args=dict(request_args),
            **self._execute_kwargs(),
        )

    def walk(self, descriptor: OperationDescriptor, base_args: Mapping[str, Any]) -> PageWalk:
        transport = self._transport_for(descriptor["operation_id"])
        return PageWalk(
            descriptor=descriptor,
            handle=self._auth.handle,
            transport=transport,
            base_args=dict(base_args),
            **self._execute_kwargs(),
        )


__all__ = [
    "SalesforceAuthContext",
    "SalesforceProductionRunner",
]
