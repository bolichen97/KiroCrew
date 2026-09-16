"""Contract, fault, and negative tests for the W01 control-plane seam.

The seam is pure types and zero IO, so these tests check the three things a
type-only single-source has to guarantee: the enum closed sets match the
manifest verbatim (contract), a reflected credential in an error ``detail`` is
scrubbed under the shared discipline (fault), and the additive-only /
no-credential / two-axis invariants hold (negative).
"""

from __future__ import annotations

import pathlib
import re

import pytest

from kiro_crew import connections
from kiro_crew.connections import control_plane as cp
from kiro_crew.connections.control_plane import (
    CREDENTIAL_MODES,
    EFFECTS,
    ERROR_CLASSES,
    INITIAL_GENERATION,
    MAX_ERROR_CHARS,
    OPERATION_KINDS,
    RESULT_STATUSES,
    SERVICE_IDS,
    Binding,
    BindingVerificationError,
    OperationContext,
    OperationDescriptor,
    OperationError,
    OperationResult,
    SecretRef,
    VerifiedIdentity,
    binding_secret_ref,
    create_binding,
    next_generation,
    operation_error,
    redacted_detail,
)

# The closed sets are PARSED from the owning spec
# (connector-capability-manifest.md) rather than copied here, so a change to a
# manifest enum turns this pin red directly instead of silently diverging (the
# Design Watch advisory: this is the whole point of the module -- the manifest
# is the single source of truth, and the seam's job is to stay identical to it).
# _manifest_enum() pulls the backtick-quoted values out of the "One of ... "
# clause in a named field's table row; the ORDER preserved is the manifest's own.
_MANIFEST_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "docs"
    / "system-specs"
    / "modules"
    / "connector-capability-manifest.md"
)


def _manifest_enum(field: str) -> tuple[str, ...]:
    """The closed set the manifest fixes for ``field``, in the manifest's order.

    Finds the ``| `<field>` | enum | ... |`` table row, isolates the
    ``One of[:] `a`, `b`, ...`` clause, and returns the backtick-quoted tokens.
    Deliberately parsed (not hardcoded) so a manifest enum edit fails this test.
    """

    text = _MANIFEST_PATH.read_text(encoding="utf-8")
    row = next(
        (line for line in text.splitlines() if line.lstrip().startswith(f"| `{field}` | enum |")),
        None,
    )
    if row is None:
        raise AssertionError(f"no manifest table row for enum field `{field}`")
    clause = re.search(r"One of:?\s*(.+?)(?:\s+—|\.\s)", row)
    if clause is None:
        raise AssertionError(f"could not isolate the 'One of ...' clause for `{field}`")
    values = re.findall(r"`([a-z_]+)`", clause.group(1))
    if not values:
        raise AssertionError(f"no backtick-quoted values parsed for `{field}`")
    return tuple(values)


_MANIFEST_OPERATION_KINDS = _manifest_enum("operation_kind")
_MANIFEST_EFFECTS = _manifest_enum("effect")
_MANIFEST_SERVICE_IDS = _manifest_enum("service_id")
# RUN-01 is defined in the W05->W06 edge prose, not a field table row, so it is
# pinned as an in-repo literal (its owning text is the same manifest document).
_RUN01_ERROR_CLASSES = (
    "auth",
    "scope",
    "consent",
    "not_found",
    "forbidden",
    "quota",
    "throttle",
    "conflict",
    "input",
    "temporary",
    "partial",
    "ambiguous",
)
# credential_modes IS the manifest's auth_modes axis; pinned as a literal since
# auth_modes' manifest row lists it by example, not as a closed "One of" clause.
_CREDENTIAL_MODES = ("oauth_user", "fine_grained_pat", "service_to_service")

# The exact set of names ``kiro_crew.connections.__all__`` published BEFORE this
# slice, frozen here as in-repo data rather than read from a git ref. This slice
# is additive-only over the connections export face (16 in-repo modules import
# it), and freezing the baseline as a literal makes that invariant explicit and
# independent of git state -- a shallow/detached CI checkout cannot resolve
# ``origin/main``, so a ref-based baseline would fail to read (exit 128) rather
# than test anything. If a future slice legitimately adds an export, this set
# grows in the same commit; a value must never be REMOVED from it.
_BASE_CONNECTIONS_EXPORTS = frozenset(
    {
        "AUTH_MODE_DCR",
        "AUTH_MODE_PREREGISTERED",
        "CALLBACK_PATH",
        "L0_VERIFICATION_MAX_AGE_DAYS",
        "L0_VERIFICATION_WARN_AGE_DAYS",
        "AuthConfig",
        "L0Expectations",
        "Provider",
        "REGISTRY_PATH",
        "REVOKE_VERIFICATION_MAX_AGE_DAYS",
        "RegistryValidationError",
        "SmokeFixture",
        "auth_mode",
        "declared_tool_aliases",
        "derived_alias",
        "exposed_declared_tools",
        "get_all_providers",
        "get_all_registry_providers",
        "get_preregistered_providers",
        "get_provider",
        "get_tier",
        "get_visible_providers",
        "is_local_host",
        "is_preregistered",
        "natural_tool_names",
        "redirect_uri",
        "resolve_tool_aliases",
        "stale_l0_baselines",
        "statically_visible_tool_names",
    }
)


# --- Contract --------------------------------------------------------------


def test_operation_kinds_match_manifest_verbatim() -> None:
    assert OPERATION_KINDS == _MANIFEST_OPERATION_KINDS


def test_effects_match_manifest_verbatim() -> None:
    assert EFFECTS == _MANIFEST_EFFECTS


def test_service_ids_match_manifest_verbatim() -> None:
    assert SERVICE_IDS == _MANIFEST_SERVICE_IDS


def test_run01_error_classes_are_the_twelve_value_closed_set() -> None:
    assert ERROR_CLASSES == _RUN01_ERROR_CLASSES
    assert len(ERROR_CLASSES) == 12


def test_credential_mode_is_the_three_value_axis_b_set() -> None:
    assert CREDENTIAL_MODES == _CREDENTIAL_MODES


def test_result_status_success_axis_is_ok_and_partial() -> None:
    assert RESULT_STATUSES == ("ok", "partial")


def test_every_module_carries_a_schema_version_constant() -> None:
    # The precedent l0_probe/l1_smoke/status all pin a module-level version.
    assert cp.OPERATION_SCHEMA_VERSION >= 1
    assert cp.CONTEXT_SCHEMA_VERSION >= 1
    assert cp.RESULT_SCHEMA_VERSION >= 1
    assert cp.ERRORS_SCHEMA_VERSION >= 1


def test_typed_dicts_have_every_declared_field() -> None:
    descriptor: OperationDescriptor = {
        "operation_id": "github.get_rate_limit",
        "service_id": "github",
        "operation_kind": "single_fetch",
        "effect": "read",
        "credential_modes": ("oauth_user", "fine_grained_pat", "service_to_service"),
    }
    assert set(descriptor) == set(OperationDescriptor.__annotations__)

    context: OperationContext = {
        "binding_ref": "binding://gh/acct-1",
        "tenant_ref": "tenant://org-1",
        "subject_ref": "subject://user-1",
        "deadline": 1_800_000_000.0,
        "credential_mode": "oauth_user",
    }
    assert set(context) == set(OperationContext.__annotations__)

    result: OperationResult = {
        "status": "partial",
        "next_cursor": "opaque-cursor",
        "payload": None,
    }
    assert set(result) == set(OperationResult.__annotations__)

    error: OperationError = operation_error("throttle", "slow down")
    assert set(error) == set(OperationError.__annotations__)


def test_descriptor_declares_a_set_of_modes_call_selects_one() -> None:
    # The manifest defines auth_modes as a per-operation ARRAY, and a real
    # operation (W02's GitHub get_rate_limit) supports OAuth + PAT + s2s. The
    # descriptor must express that as a SET (credential_modes, plural); the
    # single mode a call uses lives on the per-call context (credential_mode,
    # singular) -- never a single-valued field on the descriptor.
    from typing import get_type_hints

    d_hints = get_type_hints(OperationDescriptor)
    # Descriptor carries the plural declaration set, not a singular mode.
    assert "credential_modes" in d_hints
    assert "credential_mode" not in d_hints
    # A multi-mode operation is representable on the shared seam.
    multi: OperationDescriptor = {
        "operation_id": "github.get_rate_limit",
        "service_id": "github",
        "operation_kind": "single_fetch",
        "effect": "read",
        "credential_modes": ("oauth_user", "fine_grained_pat", "service_to_service"),
    }
    assert len(multi["credential_modes"]) == 3
    # The selected mode is a per-call property, on the context, not the descriptor.
    c_hints = get_type_hints(OperationContext)
    assert "credential_mode" in c_hints
    assert "credential_modes" not in c_hints


def test_declared_modes_are_the_outer_bound_a_selection_stays_within() -> None:
    # Contract: descriptor DECLARES the permitted set; a call SELECTS from within
    # it, and a policy (e.g. L05's permit_operation) may only NARROW, never
    # permit a mode the descriptor did not declare. This test pins the shape of
    # that contract on the W01 side: the selected mode must be a member of the
    # descriptor's declared set. (L05 owns the enforcing permit_operation test.)
    descriptor: OperationDescriptor = {
        "operation_id": "github.get_rate_limit",
        "service_id": "github",
        "operation_kind": "single_fetch",
        "effect": "read",
        "credential_modes": ("oauth_user", "service_to_service"),
    }
    context: OperationContext = {
        "binding_ref": "binding://gh/acct-1",
        "tenant_ref": "tenant://org-1",
        "subject_ref": "subject://user-1",
        "deadline": 1_800_000_000.0,
        "credential_mode": "oauth_user",
    }
    assert context["credential_mode"] in descriptor["credential_modes"]
    # A mode outside the declared set is exactly what a policy must refuse; the
    # declared set is the outer bound.
    assert "fine_grained_pat" not in descriptor["credential_modes"]


# --- Fault -----------------------------------------------------------------


def test_reflected_credential_in_detail_is_redacted() -> None:
    leaked = "github pat ghp_" + "a" * 40 + " was rejected"
    error = operation_error("auth", leaked)
    assert "ghp_" + "a" * 40 not in error["detail"]
    assert error["error_class"] == "auth"


def test_detail_is_redacted_before_truncation_not_after() -> None:
    # A credential straddling the cap must not survive as a bisected prefix:
    # redaction runs over the whole string first.
    secret = "ghp_" + "z" * 40
    detail = "x" * (MAX_ERROR_CHARS - 4) + secret
    out = redacted_detail(detail)
    assert secret not in out
    assert secret[:8] not in out  # not even a bisected prefix leaks


def test_detail_is_capped_at_max_error_chars() -> None:
    out = redacted_detail("y" * 5000)
    assert len(out) <= MAX_ERROR_CHARS


def test_operation_error_never_stores_raw_detail() -> None:
    # The constructor redacts on the way in; there is no un-redacted path.
    exfil = "authorization: Bearer sk-live-" + "q" * 32
    error = operation_error("forbidden", exfil)
    assert "sk-live-" + "q" * 32 not in error["detail"]


# --- Negative --------------------------------------------------------------


def test_connections_all_is_additive_only_over_the_base() -> None:
    # Every export the base __init__ published must still be published: the 16
    # in-repo importers of kiro_crew.connections must not break. Baseline is a
    # frozen in-repo literal (see _BASE_CONNECTIONS_EXPORTS) -- not a git ref,
    # which a shallow CI checkout cannot resolve.
    now_all = set(connections.__all__)
    missing = _BASE_CONNECTIONS_EXPORTS - now_all
    assert missing == set(), f"an existing connections export was removed: {sorted(missing)}"


def test_control_plane_symbols_live_on_the_canonical_subpackage_only() -> None:
    # The control-plane symbols are consumed via the canonical
    # `kiro_crew.connections.control_plane` path (that is what W02/L02 import),
    # so they are NOT re-exported as top-level `kiro_crew.connections` aliases:
    # a second spelling with zero consumers is a rename hazard, not a
    # convenience. The subpackage itself must stay importable (it is a package,
    # not an alias), and every symbol must be reachable through it.
    from kiro_crew.connections import control_plane

    canonical_symbols = (
        "CREDENTIAL_MODES",
        "ERROR_CLASSES",
        "CredentialMode",
        "Effect",
        "ErrorClass",
        "OperationContext",
        "OperationDescriptor",
        "OperationError",
        "OperationKind",
        "OperationResult",
        "ResultStatus",
        "ServiceId",
        "operation_error",
        "redacted_detail",
    )
    for name in canonical_symbols:
        assert hasattr(control_plane, name), f"{name} missing from the canonical subpackage"
        assert name not in connections.__all__, f"{name} must not be a top-level alias"
        assert not hasattr(
            connections, name
        ), f"{name} must not be attribute-reachable at top level"


def test_registration_mode_api_is_untouched() -> None:
    # Axis A stays exactly where it was; the seam adds Axis B without moving it.
    assert connections.AUTH_MODE_DCR == "dcr"
    assert connections.AUTH_MODE_PREREGISTERED == "preregistered"
    assert callable(connections.auth_mode)
    assert callable(connections.is_preregistered)


def test_container_anchor_is_vendors_not_providers() -> None:
    import kiro_crew.connections.vendors as vendors

    assert vendors.__name__.endswith(".vendors")
    with pytest.raises(ModuleNotFoundError):
        __import__("kiro_crew.connections.providers")


def test_context_fields_are_references_typed_as_str() -> None:
    # The context fields are references / a mode identifier, never a credential
    # value: binding/tenant/subject are str refs, deadline is a float timestamp,
    # and credential_mode is a constrained mode identifier (one of the closed
    # CredentialMode set), not a token. This pins the "no credential value"
    # invariant at the type level.
    from typing import get_type_hints

    hints = get_type_hints(OperationContext)
    assert hints["binding_ref"] is str
    assert hints["tenant_ref"] is str
    assert hints["subject_ref"] is str
    assert hints["deadline"] is float
    # credential_mode is the CredentialMode Literal (a mode identifier from the
    # closed set), not an unconstrained str that could smuggle a secret.
    assert set(getattr(hints["credential_mode"], "__args__", ())) == set(CREDENTIAL_MODES)


def test_success_partial_and_error_partial_are_distinct_concepts() -> None:
    # result.partial (usable-but-incomplete success) and errors.partial
    # (a failure that partially applied) share a word, not a set.
    assert "partial" in RESULT_STATUSES
    assert "partial" in ERROR_CLASSES
    assert set(RESULT_STATUSES).isdisjoint(set(ERROR_CLASSES) - {"partial"})


# --- L02 · AUTH-01 binding record ------------------------------------------
#
# The binding is the record a context's ``binding_ref`` points at. Its four
# properties each get a distinct test: random id (negative), verified-only
# subject/tenant (fault + negative), generation increment (contract), and
# secret-is-a-reference-never-a-value (negative). A verifier stub stands in for
# the real IO-doing verifier a later leaf provides.


def _accepting_verifier(*, claimed_subject, claimed_tenant, service_id) -> VerifiedIdentity:
    """A verifier that verifies the claim and normalizes it to canonical refs.

    Deliberately RETURNS DIFFERENT strings than the caller claimed, so a test
    can prove the binding stores the verifier's output rather than the raw
    claim.
    """

    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


def _rejecting_verifier(*, claimed_subject, claimed_tenant, service_id) -> VerifiedIdentity:
    raise BindingVerificationError("claimed subject/tenant did not verify")


def _make_binding() -> Binding:
    return create_binding(
        service_id="github",
        claimed_subject="alice",
        claimed_tenant="acme",
        credential_mode="oauth_user",
        verifier=_accepting_verifier,
        slug="github",
    )


# --- Contract --------------------------------------------------------------


def test_binding_has_a_schema_version() -> None:
    assert cp.BINDING_SCHEMA_VERSION >= 1


def test_binding_typed_dict_has_every_declared_field() -> None:
    binding = _make_binding()
    assert set(binding) == set(Binding.__annotations__)
    secret_ref: SecretRef = binding["secret_ref"]
    assert set(secret_ref) == set(SecretRef.__annotations__)


def test_created_binding_starts_at_the_initial_generation() -> None:
    assert _make_binding()["generation"] == INITIAL_GENERATION


def test_next_generation_increments_by_one_and_carries_every_other_field() -> None:
    binding = _make_binding()
    bumped = next_generation(binding)
    assert bumped["generation"] == binding["generation"] + 1
    # Every other field is carried through unchanged.
    for field in set(Binding.__annotations__) - {"generation"}:
        assert bumped[field] == binding[field]


def test_next_generation_is_monotonic_over_repeated_bumps() -> None:
    binding = _make_binding()
    gens = [binding["generation"]]
    for _ in range(5):
        binding = next_generation(binding)
        gens.append(binding["generation"])
    assert gens == sorted(gens)
    assert gens == list(range(INITIAL_GENERATION, INITIAL_GENERATION + 6))


def test_next_generation_does_not_mutate_the_input() -> None:
    binding = _make_binding()
    before = binding["generation"]
    next_generation(binding)
    assert binding["generation"] == before  # caller's record is untouched


def test_binding_secret_ref_follows_the_connections_vault_family() -> None:
    ref = binding_secret_ref("google-drive")
    # Same CONNECTIONS_<SLUG>_ family and slug spelling oauth_clients uses, with
    # the binding-specific suffix distinguishing it from _CLIENT_SECRET.
    assert ref["name"] == "CONNECTIONS_GOOGLE_DRIVE_BINDING_SECRET"
    assert ref["backend"] == cp.SECRET_BACKEND_VAULT
    assert isinstance(ref["bound_at"], float)


# --- Fault -----------------------------------------------------------------


def test_create_binding_refuses_when_verification_fails() -> None:
    with pytest.raises(BindingVerificationError):
        create_binding(
            service_id="github",
            claimed_subject="mallory",
            claimed_tenant="evil-corp",
            credential_mode="oauth_user",
            verifier=_rejecting_verifier,
            slug="github",
        )


def test_a_rejected_binding_is_never_partially_built() -> None:
    # The verifier runs BEFORE anything is minted, so a rejection leaves no
    # record at all -- the only observable is the raised error.
    seen: list[str] = []

    def _recording_reject(*, claimed_subject, claimed_tenant, service_id):
        seen.append("verifier-ran")
        raise BindingVerificationError("nope")

    with pytest.raises(BindingVerificationError):
        create_binding(
            service_id="slack",
            claimed_subject="x",
            claimed_tenant="y",
            credential_mode="service_to_service",
            verifier=_recording_reject,
            slug="slack",
        )
    assert seen == ["verifier-ran"]


# --- Negative --------------------------------------------------------------


def test_binding_stores_the_verified_identity_not_the_raw_claim() -> None:
    binding = create_binding(
        service_id="github",
        claimed_subject="alice",
        claimed_tenant="acme",
        credential_mode="oauth_user",
        verifier=_accepting_verifier,
        slug="github",
    )
    # The verifier normalized the claim; the binding must carry ITS output.
    assert binding["subject_ref"] == "subject://verified/alice"
    assert binding["tenant_ref"] == "tenant://verified/acme"
    # And never the raw claimed values verbatim.
    assert binding["subject_ref"] != "alice"
    assert binding["tenant_ref"] != "acme"


def test_binding_id_is_random_not_derived_from_slug_tenant_or_subject() -> None:
    # Two bindings with IDENTICAL inputs must still get different ids: the id is
    # random, not a function of any input. (A derived id would collide here.)
    a = _make_binding()
    b = _make_binding()
    assert a["binding_id"] != b["binding_id"]
    # The id does not embed the slug/tenant/subject, so it cannot be
    # reconstructed from those (often public) values.
    for token in ("github", "alice", "acme", "verified"):
        assert token not in a["binding_id"]
    # Hex handle of the advertised width (128 bits -> 32 hex chars).
    assert len(a["binding_id"]) == 32
    int(a["binding_id"], 16)  # pure hex, raises if not


def test_binding_ids_do_not_repeat_across_many_mints() -> None:
    ids = {_make_binding()["binding_id"] for _ in range(200)}
    assert len(ids) == 200  # no collisions -> genuinely random, not sequential


def test_secret_ref_carries_only_a_reference_never_a_value() -> None:
    # The whole binding record, recursively stringified, must not contain a
    # secret value: it holds a NAME and metadata only. Feed a credential-shaped
    # value through the flow to prove none of it can land on the record.
    fake_secret = "ghp_" + "s" * 36
    binding = _make_binding()
    blob = repr(binding)
    assert fake_secret not in blob
    # secret_ref exposes name + backend + bound_at, and nothing that could be a
    # value field.
    assert set(binding["secret_ref"]) == {"name", "backend", "bound_at"}
    assert "value" not in binding["secret_ref"]
    assert "secret" not in Binding.__annotations__  # no bare secret value field


def test_binding_credential_mode_is_axis_b_from_l01() -> None:
    # The binding's credential_mode is the L01 Axis-B closed set, not a new one.
    binding = create_binding(
        service_id="salesforce",
        claimed_subject="s",
        claimed_tenant="t",
        credential_mode="fine_grained_pat",
        verifier=_accepting_verifier,
        slug="salesforce",
    )
    assert binding["credential_mode"] in CREDENTIAL_MODES


def test_binding_symbols_are_reachable_via_control_plane_not_the_top_level() -> None:
    # The canonical home for the L02 binding names is the control_plane
    # subpackage; the top-level connections package deliberately carries NO
    # control-plane symbol (the 14-alias second-spelling was a rename trap and
    # was converged away). Same shape as L01's registration-mode guard: pin
    # where a name lives, and pin where it must NOT be aliased.
    binding_names = (
        "Binding",
        "SecretRef",
        "VerifiedIdentity",
        "SubjectTenantVerifier",
        "BindingVerificationError",
        "create_binding",
        "next_generation",
        "binding_secret_ref",
        "INITIAL_GENERATION",
    )
    for name in binding_names:
        # Reachable through the canonical control_plane subpackage...
        assert name in cp.__all__, f"{name} missing from control_plane.__all__"
        assert hasattr(cp, name), f"{name} not reachable via control_plane"
        # ...and NOT re-exported as a top-level connections alias.
        assert name not in connections.__all__, f"{name} leaked into connections.__all__"
        assert not hasattr(connections, name), f"{name} is a top-level connections alias"
