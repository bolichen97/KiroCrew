"""Shared connector control plane (W01 · L01).

The one typed seam every provider stream (W02..W14) dispatches an operation
through: an :class:`~kiro_crew.connections.control_plane.operation.OperationDescriptor`
(what the operation is), an
:class:`~kiro_crew.connections.control_plane.context.OperationContext` (the
references one call is made under -- never a credential value), an
:class:`~kiro_crew.connections.control_plane.result.OperationResult` (the
success/partial envelope with an opaque pagination cursor), and the RUN-01
:class:`~kiro_crew.connections.control_plane.errors.OperationError` taxonomy.

W01 · L02 adds :class:`~kiro_crew.connections.control_plane.binding.Binding` --
AUTH-01's authorized-account record that a ``binding_ref`` points at: an
unguessable random id, a VERIFIED subject/tenant, a monotonic ``generation``
counter (for L04 revoke fencing; field + increment only here), and a
``secret_ref`` that carries the secret's location and metadata but never its
value.

Pure types, zero IO. This module is the control plane's own export face, and it
is the CANONICAL one: the wider ``kiro_crew.connections`` package does NOT
re-export these symbols, so consumers import them from
``kiro_crew.connections.control_plane`` (or its submodules), never as
``kiro_crew.connections.<name>`` aliases.
"""

from kiro_crew.connections.control_plane.binding import (
    BINDING_SCHEMA_VERSION,
    INITIAL_GENERATION,
    SECRET_BACKEND_VAULT,
    Binding,
    BindingResolutionError,
    BindingVerificationError,
    SecretRef,
    SubjectTenantVerifier,
    VerifiedIdentity,
    binding_scoped_secret_ref,
    binding_secret_ref,
    create_binding,
    next_generation,
    resolve_binding_for_principal,
)
from kiro_crew.connections.control_plane.context import (
    CONTEXT_SCHEMA_VERSION,
    OperationContext,
)
from kiro_crew.connections.control_plane.errors import (
    ERROR_CLASSES,
    ERRORS_SCHEMA_VERSION,
    MAX_ERROR_CHARS,
    ErrorClass,
    OperationError,
    operation_error,
    redacted_detail,
)
from kiro_crew.connections.control_plane.operation import (
    CREDENTIAL_MODES,
    EFFECTS,
    OPERATION_KINDS,
    OPERATION_SCHEMA_VERSION,
    SERVICE_IDS,
    CredentialMode,
    Effect,
    OperationDescriptor,
    OperationKind,
    ServiceId,
)
from kiro_crew.connections.control_plane.result import (
    RESULT_SCHEMA_VERSION,
    RESULT_STATUSES,
    OperationResult,
    ResultStatus,
)

__all__ = [
    "BINDING_SCHEMA_VERSION",
    "CONTEXT_SCHEMA_VERSION",
    "CREDENTIAL_MODES",
    "EFFECTS",
    "ERRORS_SCHEMA_VERSION",
    "ERROR_CLASSES",
    "INITIAL_GENERATION",
    "MAX_ERROR_CHARS",
    "OPERATION_KINDS",
    "OPERATION_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "RESULT_STATUSES",
    "SECRET_BACKEND_VAULT",
    "SERVICE_IDS",
    "Binding",
    "BindingResolutionError",
    "BindingVerificationError",
    "CredentialMode",
    "Effect",
    "ErrorClass",
    "OperationContext",
    "OperationDescriptor",
    "OperationError",
    "OperationKind",
    "OperationResult",
    "ResultStatus",
    "SecretRef",
    "ServiceId",
    "SubjectTenantVerifier",
    "VerifiedIdentity",
    "binding_scoped_secret_ref",
    "binding_secret_ref",
    "create_binding",
    "next_generation",
    "operation_error",
    "redacted_detail",
    "resolve_binding_for_principal",
]
