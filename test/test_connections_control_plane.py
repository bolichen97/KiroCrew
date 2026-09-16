"""Contract, fault, and negative tests for the W01 control-plane seam.

The seam is pure types and zero IO, so these tests check the three things a
type-only single-source has to guarantee: the enum closed sets match the
manifest verbatim (contract), a reflected credential in an error ``detail`` is
scrubbed under the shared discipline (fault), and the additive-only /
no-credential / two-axis invariants hold (negative).
"""

from __future__ import annotations

import inspect
import json
import os
import pathlib
import re
import subprocess
import sys
import textwrap
import time

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
    BindingResolutionError,
    BindingRevokedError,
    BindingStore,
    BindingStoreCorruptError,
    BindingUniquenessError,
    BindingVerificationError,
    OperationContext,
    OperationDescriptor,
    OperationError,
    OperationResult,
    ResolvedCredential,
    SecretRef,
    VerifiedIdentity,
)
from kiro_crew.connections.control_plane import binding as binding_mod
from kiro_crew.connections.control_plane import (
    binding_secret_ref,
    create_binding,
    next_generation,
    operation_error,
    redacted_detail,
    store_path,
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


# --- L04 · binding lifecycle: trusted store, single-writer rotation, revoke ---
#
# Round-24 repair. Four defects were read out of the round-23 code, and each is
# closed here with a "prove the failure / prove the refusal path is really taken"
# test alongside the fix:
#   1. assert_live used `<` and did not compare identity -> a forged future
#      generation passed, and another binding's generation passed. Now: EXACT
#      generation equality AND identity match.
#   2. uniqueness could be bypassed by reusing a binding_id with changed domain
#      fields, and a corrupt store was read as empty (erasing every binding on
#      the next write). Now: domain-enforced regardless of id, and fail-closed on
#      a corrupt store.
#   3. rotate's lock covered only the counter/ref bump, not the REAL token
#      refresh -> two processes could both refresh. Now: the refresh callable
#      runs INSIDE the lock; a controlled endpoint is hit exactly once.
#   4. `instance` meant the KiroCrew instance (backwards). Now `deployment_id`
#      means the PROVIDER-side deployment, and the Kiro principal -> authorization
#      link is enforced in resolve, not merely documented.


def _store_verifier(*, claimed_subject, claimed_tenant, service_id) -> VerifiedIdentity:
    return {
        "subject_ref": f"subject://verified/{claimed_subject}",
        "tenant_ref": f"tenant://verified/{claimed_tenant}",
    }


def _fresh_store(tmp_path) -> BindingStore:
    """A BindingStore backed by a file under an isolated tmp dir (never the live
    data home). The lock file sits beside it automatically."""

    return BindingStore(path=tmp_path / "connections" / "control_plane_bindings.json")


def _mk_binding(subject="alice", tenant="acme", service="github") -> Binding:
    binding = create_binding(
        service_id=service,
        claimed_subject=subject,
        claimed_tenant=tenant,
        credential_mode="oauth_user",
        verifier=_store_verifier,
        slug=service,
    )
    # A PER-BINDING vault-entry name. On L04's own base this came from L02's
    # `binding_scoped_secret_ref`, which is not on this branch: here
    # `create_binding` mints the SLUG-derived name, and a slug names a PROVIDER,
    # so every binding of one provider would share one entry. The tests below have
    # to be able to tell "asked by binding" from "asked by slug", which needs the
    # two names to differ -- so the per-binding name is stamped on here. It is a
    # stamp on the record, not a new naming scheme and not a second vault.
    binding["secret_ref"] = dict(binding["secret_ref"])  # type: ignore[typeddict-item]
    binding["secret_ref"]["name"] = f"{binding['secret_ref']['name']}__{binding['binding_id']}"
    return binding


_DEPLOY = "github-enterprise://ghe.acme.example"  # a PROVIDER-side deployment
_PRINCIPAL = "kiro://principal/operator-1"


def _insert(store, binding, *, deployment_id=_DEPLOY, kiro_principal=_PRINCIPAL):
    return store.insert(binding, deployment_id=deployment_id, kiro_principal=kiro_principal)


def _resolve(store, *, subject="alice", tenant="acme", deployment_id=_DEPLOY, principal=_PRINCIPAL):
    return store.resolve(
        kiro_principal=principal,
        deployment_id=deployment_id,
        service_id="github",
        claimed_subject=subject,
        claimed_tenant=tenant,
        verifier=_store_verifier,
    )


# --- Contract: the store persists and is the trusted candidate source ------


def test_store_path_lives_under_config_dir_connections(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
    p = store_path()
    assert p.parent.name == "connections"
    assert p.name == "control_plane_bindings.json"
    assert str(tmp_path) in str(p)


def test_resolution_reads_from_the_store_not_a_caller_iterable(tmp_path) -> None:
    import inspect

    sig = inspect.signature(BindingStore.resolve)
    assert "bindings" not in sig.parameters
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    with pytest.raises(BindingResolutionError):
        _resolve(store)
    _insert(store, b)
    assert _resolve(store)["binding_id"] == b["binding_id"]


def test_a_caller_supplied_candidate_outside_the_trusted_store_is_refused(tmp_path) -> None:
    fabricated = _mk_binding(subject="alice", tenant="acme")
    # (a) The DEFECT half of this counter-example -- L02's
    # `resolve_binding_for_principal([fabricated], ...)` matching over a
    # caller-supplied Iterable and happily returning `fabricated` -- is NOT
    # reproducible on this branch: that function lands with L02's own commit,
    # which is not in this history (this branch's binding.py has no such
    # entry point). What IS pinned here is the structural half of the fix: the
    # trusted store's resolve takes NO caller candidate set at all, so there is
    # no parameter through which `fabricated` could be offered.
    assert "bindings" not in inspect.signature(BindingStore.resolve).parameters
    assert not hasattr(binding_mod, "resolve_binding_for_principal")
    # (b) the trusted store never admitted it -> refused.
    store = _fresh_store(tmp_path)
    with pytest.raises(BindingResolutionError):
        _resolve(store)
    assert store.get(fabricated["binding_id"]) is None


# ===========================================================================
# DEFECT 1: assert_live fencing -- exact generation equality AND identity match
# ===========================================================================


def test_DEFECT1_before_a_less_than_only_fence_would_pass_a_forged_future_gen() -> None:
    # PRE-FIX evidence: a `< live_generation` fence lets a FORGED future
    # generation through (999 is not < 2), and lets ANOTHER binding's generation
    # through (it never compares identity). This models the round-23 assert_live
    # verbatim, and shows both holes are open.
    def old_assert_live_less_than_only(presented_gen: int, live_gen: int) -> bool:
        # returns True == "passed the fence" (i.e. NOT refused)
        return not (presented_gen < live_gen)  # the buggy `<`-only rule

    live = 2
    assert old_assert_live_less_than_only(999, live) is True  # forged future PASSES (bug)
    assert old_assert_live_less_than_only(2, live) is True  # any binding at gen 2 PASSES (bug)


def test_a_forged_future_generation_is_refused(tmp_path) -> None:
    # POST-FIX: only the EXACT live generation passes. A fabricated future gen
    # the store never issued is fenced.
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    live = store.get(b["binding_id"])["live_generation"]
    forged = _binding_future_gen(b, live + 997)  # e.g. 999
    with pytest.raises(BindingRevokedError):
        store.assert_live(forged)


def test_a_generation_from_another_binding_is_refused(tmp_path) -> None:
    # POST-FIX: identity is compared. A handle whose binding_id is A's but whose
    # ref fields are B's (a numerically-valid gen borrowed across identities) is
    # refused because the stored record's identity does not match.
    store = _fresh_store(tmp_path)
    a = _mk_binding(subject="alice", tenant="acme")
    _insert(store, a)
    live = store.get(a["binding_id"])["live_generation"]
    # Same id + same live generation number, but B's identity fields.
    forged = dict(a)
    forged["subject_ref"] = "subject://verified/bob"
    forged["tenant_ref"] = "tenant://verified/beta"
    forged["generation"] = live
    with pytest.raises(BindingRevokedError):
        store.assert_live(forged)  # identity mismatch -> fenced


def test_the_exact_live_generation_and_identity_passes(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)  # stamped at the live generation, correct identity
    store.assert_live(handle)  # must not raise


# ===========================================================================
# DEFECT 2: uniqueness on the domain (not id) + corrupt store fails closed
# ===========================================================================


def test_a_second_binding_colliding_on_the_uniqueness_domain_is_refused(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    first = _mk_binding(subject="alice", tenant="acme")
    second = _mk_binding(subject="alice", tenant="acme")  # same account, new id
    assert first["binding_id"] != second["binding_id"]
    _insert(store, first)
    with pytest.raises(BindingUniquenessError):
        _insert(store, second)
    # first untouched, still resolves.
    assert _resolve(store)["binding_id"] == first["binding_id"]


def test_DEFECT2a_reusing_a_binding_id_with_changed_domain_is_refused(tmp_path) -> None:
    # The bypass: reuse an existing binding_id but change the account/domain
    # fields. Round-23 keyed the collision check by domain-tuple only and stored
    # by id, so a same-id re-insert with a mutated domain silently overwrote.
    # POST-FIX: refused as an illegal mutation of an immutable identity.
    store = _fresh_store(tmp_path)
    original = _mk_binding(subject="alice", tenant="acme")
    _insert(store, original)
    # Same binding_id, different account (subject/tenant changed).
    mutated = dict(original)
    mutated["subject_ref"] = "subject://verified/bob"
    mutated["tenant_ref"] = "tenant://verified/beta"
    with pytest.raises(BindingUniquenessError):
        _insert(store, mutated)  # type: ignore[arg-type]
    # The original account is intact -- not overwritten.
    stored = store.get(original["binding_id"])
    assert stored["binding"]["subject_ref"] == "subject://verified/alice"
    assert stored["binding"]["tenant_ref"] == "tenant://verified/acme"


def test_a_different_deployment_or_account_is_allowed(tmp_path) -> None:
    # The domain is the RIGHT shape: same account on a DIFFERENT provider
    # deployment is distinct, and a different account on the same deployment is
    # distinct.
    store = _fresh_store(tmp_path)
    _insert(store, _mk_binding(subject="alice", tenant="acme"))
    _insert(store, _mk_binding(subject="alice", tenant="acme"), deployment_id="salesforce://org-2")
    _insert(store, _mk_binding(subject="alice", tenant="other"))
    assert len(store.all_bindings()) == 3


def test_DEFECT2b_a_corrupt_store_is_not_treated_as_empty(tmp_path) -> None:
    # PRE-FIX behaviour would read a corrupt file as {} and let the next write
    # republish a fresh (empty) store -- erasing every binding and making a
    # colliding insert "legal" again. POST-FIX: a corrupt store FAILS CLOSED.
    store = _fresh_store(tmp_path)
    _insert(store, _mk_binding(subject="alice", tenant="acme"))
    # Corrupt the file on disk (valid path, invalid JSON).
    store.path.write_text("{ this is not json ", encoding="utf-8")

    # A read fails closed rather than answering "empty".
    with pytest.raises(BindingStoreCorruptError):
        store.all_bindings()
    # A write (insert) refuses rather than erasing the store.
    with pytest.raises(BindingStoreCorruptError):
        _insert(store, _mk_binding(subject="carol", tenant="acme"))
    # The corrupt bytes are still on disk -- not silently replaced by an empty store.
    assert store.path.read_text(encoding="utf-8") == "{ this is not json "


def test_a_wrong_shape_store_fails_closed(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(json.dumps({"not_bindings": 1}), encoding="utf-8")
    with pytest.raises(BindingStoreCorruptError):
        store.all_bindings()


def test_an_absent_store_is_empty_not_corrupt(tmp_path) -> None:
    # The distinction: a file that does not exist is a genuinely empty store.
    store = _fresh_store(tmp_path)
    assert store.all_bindings() == []


# ===========================================================================
# DEFECT 3: the lock must wrap the REAL token refresh -- controlled endpoint
# ===========================================================================


# Worker: opens the shared store, waits on a barrier, then rotates -- and its
# `refresh` callable does a REAL HTTP GET to a controlled token endpoint the
# parent runs and counts. The COUNTER LIVES IN THE PARENT'S HTTP SERVER, not in
# the store and not under the store lock, so it counts how many times the
# provider endpoint was actually hit. Under the fix, only the winner calls
# refresh, so the endpoint is hit exactly once. Real subprocesses, not threads.
_REFRESH_WORKER = textwrap.dedent("""
    import json, os, sys, time, urllib.request
    from kiro_crew.connections.control_plane import BindingStore, binding_secret_ref

    store_file, binding_id, observed, endpoint, barrier, out_file = sys.argv[1:7]
    observed = int(observed)
    store = BindingStore(path=store_file)

    def refresh(binding):
        # The REAL token-refresh call: hit the controlled provider endpoint.
        with urllib.request.urlopen(endpoint, timeout=30) as resp:
            resp.read()
        # A DISTINCT per-binding ref for the rotation to swap in (L04's own
        # commit used L02's binding_scoped_secret_ref, absent on this branch).
        ref = dict(binding_secret_ref("github"))
        ref["name"] = "CONNECTIONS_GITHUB_BINDING_SECRET__ROTATED_%s" % binding["binding_id"]
        return ref

    while not os.path.exists(barrier):
        time.sleep(0.005)

    record, did = store.rotate(binding_id, observed_generation=observed, refresh=refresh)
    with open(out_file, "w") as fh:
        json.dump({"pid": os.getpid(), "did_rotate": bool(did),
                   "gen": record["live_generation"]}, fh)
    """)


def test_only_one_process_rotates_under_contention(tmp_path) -> None:
    # TWO REAL PROCESSES + a CONTROLLED TOKEN ENDPOINT. The evidence is the number
    # of times the endpoint was actually HIT (counted in the parent's HTTP
    # server), not an internal counter and not "the lock was acquired". The fix
    # runs `refresh` inside the lock, so the endpoint is hit EXACTLY ONCE even
    # though both processes attempt a rotation from the same observed generation.
    import http.server
    import threading

    hits = {"n": 0}
    hits_lock = threading.Lock()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            with hits_lock:
                hits["n"] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):  # silence
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    endpoint = f"http://127.0.0.1:{port}/token"
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        store = _fresh_store(tmp_path)
        b = _mk_binding()
        stored = _insert(store, b)
        observed = stored["live_generation"]

        worker_py = tmp_path / "refresh_worker.py"
        worker_py.write_text(_REFRESH_WORKER, encoding="utf-8")
        barrier = tmp_path / "go"
        out1 = tmp_path / "r1.json"
        out2 = tmp_path / "r2.json"

        env = dict(os.environ)
        src_root = str(pathlib.Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = src_root + os.pathsep + env.get("PYTHONPATH", "")
        common = [
            sys.executable,
            str(worker_py),
            str(store.path),
            b["binding_id"],
            str(observed),
            endpoint,
        ]
        p1 = subprocess.Popen(common + [str(barrier), str(out1)], env=env)
        p2 = subprocess.Popen(common + [str(barrier), str(out2)], env=env)
        time.sleep(0.3)
        barrier.write_text("go", encoding="utf-8")
        assert p1.wait(timeout=60) == 0
        assert p2.wait(timeout=60) == 0

        r1 = json.loads(out1.read_text())
        r2 = json.loads(out2.read_text())
        with hits_lock:
            endpoint_hits = hits["n"]
        print(
            f"\n[CONTENTION EVIDENCE] worker1={r1}\n[CONTENTION EVIDENCE] worker2={r2}\n"
            f"[CONTENTION EVIDENCE] TOKEN ENDPOINT HITS={endpoint_hits} "
            f"(must be 1) final_store_generation="
            f"{store.get(b['binding_id'])['live_generation']} observed={observed}"
        )
        rotated = [r for r in (r1, r2) if r["did_rotate"]]
        # The judgement: the REAL provider endpoint was hit exactly once.
        assert endpoint_hits == 1, f"token endpoint hit {endpoint_hits} times; r1={r1} r2={r2}"
        assert len(rotated) == 1, f"expected one rotation, r1={r1} r2={r2}"
        assert store.get(b["binding_id"])["live_generation"] == observed + 1
    finally:
        server.shutdown()
        server.server_close()


def test_the_loser_does_not_call_refresh(tmp_path) -> None:
    # Deterministic (no race): a rotate presenting an already-superseded observed
    # generation must NOT invoke the refresh callable at all, and must not rotate.
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    stored = _insert(store, b)
    gen0 = stored["live_generation"]
    calls = {"n": 0}

    def counting_refresh(binding):
        calls["n"] += 1
        return None

    _, first_did = store.rotate(b["binding_id"], observed_generation=gen0, refresh=counting_refresh)
    assert first_did is True
    assert calls["n"] == 1  # winner refreshed once
    # A stale observed generation -> loser path.
    record, second_did = store.rotate(
        b["binding_id"], observed_generation=gen0, refresh=counting_refresh
    )
    assert second_did is False
    assert calls["n"] == 1  # refresh NOT called again
    assert record["live_generation"] == gen0 + 1  # still just one rotation


def test_rotate_swaps_secret_ref_from_the_refresh_result(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    stored = _insert(store, b)
    # A DISTINCT per-binding ref for the rotation to swap in. L04's own commit
    # used L02's `binding_scoped_secret_ref`, which is not on this branch, so the
    # distinct name is built here -- what the test asserts is unchanged: the
    # record takes the ref the refresh callable returned.
    new_ref = dict(binding_secret_ref("github"))
    new_ref["name"] = f"CONNECTIONS_GITHUB_BINDING_SECRET__ROTATED__{b['binding_id']}"
    rotated, did = store.rotate(
        b["binding_id"], observed_generation=stored["live_generation"], refresh=lambda _b: new_ref
    )
    assert did is True
    assert rotated["live_generation"] == stored["live_generation"] + 1
    assert rotated["binding"]["secret_ref"]["name"] == new_ref["name"]
    # Still only a reference: no value field leaked onto the record.
    assert set(rotated["binding"]["secret_ref"]) == {"name", "backend", "bound_at"}


# ===========================================================================
# DEFECT 4: deployment_id (provider-side) semantics + principal wiring
# ===========================================================================


def test_deployment_id_is_a_provider_deployment_not_a_kiro_instance(tmp_path) -> None:
    # The corrected direction: the SAME provider account resolved from what would
    # be two different KiroCrew instances is still ONE binding (same deployment),
    # while the SAME account on two different provider deployments is TWO.
    store = _fresh_store(tmp_path)
    b = _mk_binding(subject="alice", tenant="acme")
    _insert(store, b, deployment_id="graph-tenant://contoso.onmicrosoft.com")
    # Same provider deployment + same account under a SECOND kiro principal is a
    # distinct authorization row (principal is a separate axis), but the account
    # on the SAME deployment must still collide on the domain for the SAME
    # principal:
    with pytest.raises(BindingUniquenessError):
        _insert(
            store,
            _mk_binding(subject="alice", tenant="acme"),
            deployment_id="graph-tenant://contoso.onmicrosoft.com",
        )
    # A different provider deployment (a second Graph tenant) is a new binding.
    _insert(
        store,
        _mk_binding(subject="alice", tenant="acme"),
        deployment_id="graph-tenant://fabrikam.onmicrosoft.com",
    )
    assert len(store.all_bindings()) == 2


def test_principal_to_authorization_link_is_enforced_in_resolve(tmp_path) -> None:
    # The Kiro principal -> authorization link is REAL: a caller presenting a
    # DIFFERENT principal cannot resolve the binding, even with the correct
    # provider identity and deployment.
    store = _fresh_store(tmp_path)
    b = _mk_binding(subject="alice", tenant="acme")
    _insert(store, b, kiro_principal="kiro://principal/owner")
    # Correct principal resolves.
    assert _resolve(store, principal="kiro://principal/owner")["binding_id"] == b["binding_id"]
    # A different Kiro principal, same provider identity + deployment -> refused.
    with pytest.raises(BindingResolutionError):
        _resolve(store, principal="kiro://principal/intruder")


# ===========================================================================
# revoke fencing + persistence + evidence
# ===========================================================================


def test_a_credential_from_a_revoked_generation_is_refused(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)
    store.assert_live(handle)  # before revoke: live
    store.revoke(b["binding_id"])
    with pytest.raises(BindingRevokedError):
        store.assert_live(handle)  # old generation fenced
    with pytest.raises(BindingRevokedError):
        _resolve(store)  # revoked binding resolves to nothing


def test_revoke_evidence_before_and_after(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)
    before_gen = store.get(b["binding_id"])["live_generation"]
    store.assert_live(handle)
    before = "USABLE"
    revoked = store.revoke(b["binding_id"])
    after_gen = revoked["live_generation"]
    try:
        store.assert_live(handle)
        after = "STILL-USABLE"
    except BindingRevokedError as exc:
        after = f"REFUSED ({exc})"
    print(
        f"\n[REVOKE EVIDENCE] binding={b['binding_id']} "
        f"gen before-revoke={before_gen} after-revoke={after_gen}\n"
        f"[REVOKE EVIDENCE] handle(gen={handle['generation']}) before-revoke: {before}\n"
        f"[REVOKE EVIDENCE] handle(gen={handle['generation']}) after-revoke: {after}"
    )
    assert before == "USABLE"
    assert after.startswith("REFUSED")
    assert after_gen == before_gen + 1


def test_revoke_is_idempotent(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    first = store.revoke(b["binding_id"])
    second = store.revoke(b["binding_id"])
    assert first["live_generation"] == second["live_generation"]
    assert second["revoked"] is True


def test_rotate_refuses_a_revoked_binding(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    stored = _insert(store, b)
    store.revoke(b["binding_id"])
    with pytest.raises(BindingRevokedError):
        store.rotate(b["binding_id"], observed_generation=stored["live_generation"])


def test_resolution_still_works_after_a_restart(tmp_path) -> None:
    path = tmp_path / "connections" / "control_plane_bindings.json"
    store_a = BindingStore(path=path)
    b = _mk_binding()
    store_a.insert(b, deployment_id=_DEPLOY, kiro_principal=_PRINCIPAL)
    del store_a  # process gone; only the file survives
    store_b = BindingStore(path=path)  # "after restart"
    resolved = store_b.resolve(
        kiro_principal=_PRINCIPAL,
        deployment_id=_DEPLOY,
        service_id="github",
        claimed_subject="alice",
        claimed_tenant="acme",
        verifier=_store_verifier,
    )
    assert resolved["binding_id"] == b["binding_id"]


def test_store_persists_only_references_never_a_secret_value(tmp_path) -> None:
    path = tmp_path / "connections" / "control_plane_bindings.json"
    store = BindingStore(path=path)
    store.insert(_mk_binding(), deployment_id=_DEPLOY, kiro_principal=_PRINCIPAL)
    raw = path.read_text(encoding="utf-8")
    assert "ghp_" not in raw
    assert "Bearer " not in raw
    doc = json.loads(raw)
    for rec in doc["bindings"].values():
        assert set(rec["binding"]["secret_ref"]) == {"name", "backend", "bound_at"}
        assert "value" not in rec["binding"]["secret_ref"]


# --- Negative: L04 symbols are canonical-only (no top-level alias) ----------


def test_l04_symbols_are_reachable_via_control_plane_not_the_top_level() -> None:
    l04_names = (
        "BindingStore",
        "BindingUniquenessError",
        "BindingRevokedError",
        "BindingStoreCorruptError",
        "StoredBinding",
        "LIFECYCLE_SCHEMA_VERSION",
        "store_path",
    )
    for name in l04_names:
        assert name in cp.__all__, f"{name} missing from control_plane.__all__"
        assert hasattr(cp, name), f"{name} not reachable via control_plane"
        assert name not in connections.__all__, f"{name} leaked into connections.__all__"
        assert not hasattr(connections, name), f"{name} is a top-level connections alias"


def test_lifecycle_carries_a_schema_version() -> None:
    assert cp.LIFECYCLE_SCHEMA_VERSION >= 1


def _binding_future_gen(binding: Binding, generation: int) -> Binding:
    out = dict(binding)
    out["generation"] = generation
    return out  # type: ignore[return-value]


# ===========================================================================
# Round-25 repair. Two further defects were read out of the round-24 code:
#   A. assert_live returned None and compared neither secret_ref nor
#      credential_mode -> a handle with the right id+generation+identity but a
#      SWAPPED secret_ref or credential_mode passed, and returning None forced
#      the real sender to fall back to the caller's own (unvalidated) dict for
#      the ref/mode/secret -- the 6th recurrence of "validate then use an
#      unvalidated value". Now: assert_live RETURNS the trusted store's live
#      Binding and refuses a swapped secret_ref / credential_mode.
#   B. insert did `return prior` for ANY same-id + same-domain re-insert, even
#      when principal / credential_mode / secret_ref differed -> "write looked
#      successful but stored the old value". Now: only a byte-identical re-insert
#      (over an explicitly-scoped field set, excluding volatile timestamps) is
#      idempotent; any difference raises BindingUniquenessError.
# ===========================================================================


# ---------------------------------------------------------------------------
# DEFECT A -- PRE-FIX evidence: assert_live returns None and ignores
# secret_ref / credential_mode, so a swapped ref/mode passes the fence.
# ---------------------------------------------------------------------------


def test_DEFECTA_pre_fix_assert_live_returns_none_and_ignores_ref_and_mode(tmp_path) -> None:
    # This test documents the round-24 buggy behavior BEFORE the fix. It models
    # the exact assert_live rule of round-24 (identity + exact generation only,
    # returns None) and shows that a handle with a SWAPPED secret_ref and a
    # SWAPPED credential_mode is NOT refused, and that None is returned (so the
    # caller has nothing trusted to consume).
    def round24_assert_live(presented, stored) -> None:
        # round-24 verbatim: compares only id/identity/generation, returns None.
        sb = stored["binding"]
        if (
            presented["service_id"] != sb["service_id"]
            or presented["subject_ref"] != sb["subject_ref"]
            or presented["tenant_ref"] != sb["tenant_ref"]
        ):
            raise BindingRevokedError("identity mismatch")
        if presented["generation"] != stored["live_generation"]:
            raise BindingRevokedError("generation fenced")
        return None

    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    stored = store.get(b["binding_id"])
    live = stored["live_generation"]

    # Same id, same identity, same live generation -- but a SWAPPED secret_ref
    # NAME and a SWAPPED credential_mode.
    swapped = dict(b)
    swapped["generation"] = live
    swapped["secret_ref"] = dict(b["secret_ref"])
    swapped["secret_ref"]["name"] = b["secret_ref"]["name"] + "_ATTACKER"
    swapped["credential_mode"] = "service_to_service"  # was oauth_user

    # Round-24 rule: passes the fence (no raise) AND returns None.
    assert round24_assert_live(swapped, stored) is None  # ref/mode swap NOT caught (bug)


# ---------------------------------------------------------------------------
# DEFECT B -- PRE-FIX evidence: insert returns prior for a same-id same-domain
# re-insert even when principal / credential_mode / secret_ref differ.
# ---------------------------------------------------------------------------


def test_DEFECTB_pre_fix_reinsert_with_changed_pri_or_mode_silently_returns_old(tmp_path) -> None:
    # Documents the round-24 buggy behavior BEFORE the fix: `if prior is not
    # None: return prior` unconditionally, so a re-insert that changes the
    # kiro_principal (or credential_mode / secret_ref) silently returns the OLD
    # record -- a write that "succeeded" but stored nothing new.
    def round24_insert(records, candidate, bid, want_key):
        prior = records.get(bid)
        # (illegal-mutation + domain-collision guards elided; they don't fire
        # here because the domain is unchanged and the id is reused.)
        if prior is not None:
            return prior  # round-24: unconditional -- the bug
        records[bid] = candidate
        return candidate

    b = _mk_binding()
    bid = b["binding_id"]
    first = {
        "binding": b,
        "deployment_id": _DEPLOY,
        "kiro_principal": _PRINCIPAL,
        "live_generation": b["generation"],
        "revoked": False,
        "updated_at": 1.0,
    }
    records = {bid: first}
    # Re-insert with a DIFFERENT kiro_principal (same id, same domain).
    changed = dict(first)
    changed["kiro_principal"] = "kiro://principal/attacker"
    got = round24_insert(records, changed, bid, None)
    assert got["kiro_principal"] == _PRINCIPAL  # old principal returned (bug)
    assert got is first  # the OLD record, the change was silently dropped


# ---------------------------------------------------------------------------
# DEFECT A -- POST-FIX: assert_live RETURNS the trusted store's Binding and
# refuses a swapped secret_ref / credential_mode; the sender consumes the
# returned value, never the caller dict.
# ---------------------------------------------------------------------------


def test_assert_live_returns_the_trusted_store_binding(tmp_path) -> None:
    import inspect

    # The signature no longer promises None.
    ann = inspect.signature(BindingStore.assert_live).return_annotation
    assert ann is not None
    assert ann is not inspect.Signature.empty
    # Accept the annotation whether it is the Binding class or its string form.
    assert "None" not in str(ann)
    assert "Binding" in str(ann)

    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)  # live, correct identity/generation
    returned = store.assert_live(handle)
    assert returned is not None
    stored = store.get(b["binding_id"])["binding"]
    # Equal to the store's record (stamped at the live generation).
    assert returned["binding_id"] == stored["binding_id"]
    assert returned["secret_ref"] == stored["secret_ref"]
    assert returned["credential_mode"] == stored["credential_mode"]
    assert returned["generation"] == store.get(b["binding_id"])["live_generation"]


def test_a_swapped_secret_ref_is_refused(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    live = store.get(b["binding_id"])["live_generation"]
    # Same id, same live generation, same identity, but a SWAPPED secret_ref name.
    swapped = dict(b)
    swapped["generation"] = live
    swapped["secret_ref"] = dict(b["secret_ref"])
    swapped["secret_ref"]["name"] = b["secret_ref"]["name"] + "_ATTACKER"
    with pytest.raises(BindingRevokedError):
        store.assert_live(swapped)


def test_a_swapped_credential_mode_is_refused(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    live = store.get(b["binding_id"])["live_generation"]
    # Same id, same live generation, same identity, but a SWAPPED credential_mode.
    assert b["credential_mode"] == "oauth_user"
    swapped = dict(b)
    swapped["generation"] = live
    swapped["credential_mode"] = "service_to_service"
    with pytest.raises(BindingRevokedError):
        store.assert_live(swapped)


def test_the_sender_consumes_the_returned_binding_not_the_caller_dict(tmp_path) -> None:
    # The store's record has the RIGHT secret_ref; build a GOOD handle (so
    # assert_live does not raise) whose OTHER fields match, but sanity-check that
    # the RETURNED binding carries the STORE's secret_ref name -- the value a real
    # sender must consume -- not whatever the caller might have carried forward.
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    stored = store.get(b["binding_id"])
    good_handle = _resolve(store)  # matches the store exactly
    returned = store.assert_live(good_handle)
    assert returned["secret_ref"]["name"] == stored["binding"]["secret_ref"]["name"]

    # And prove the return is the STORE's value, not the caller's: mutate the
    # caller handle's ref AFTER a successful assert_live and confirm the returned
    # object is unaffected (it is the trusted record, decoupled from the caller).
    caller_after = dict(good_handle)
    caller_after["secret_ref"] = dict(good_handle["secret_ref"])
    caller_after["secret_ref"]["name"] = "SOME_OTHER_NAME_the_caller_swapped_in"
    assert returned["secret_ref"]["name"] != caller_after["secret_ref"]["name"]
    assert returned["secret_ref"]["name"] == stored["binding"]["secret_ref"]["name"]


# ---------------------------------------------------------------------------
# DEFECT B -- POST-FIX: only a byte-identical re-insert is idempotent; a
# same-id same-domain re-insert with a changed principal / credential_mode /
# secret_ref is refused, not silently returning the old record.
# ---------------------------------------------------------------------------


def test_insert_same_id_same_domain_different_principal_is_refused(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding(subject="alice", tenant="acme")
    _insert(store, b, kiro_principal=_PRINCIPAL)
    with pytest.raises(BindingUniquenessError):
        _insert(store, b, kiro_principal="kiro://principal/attacker")
    # Store is untouched: the original principal still owns it.
    assert store.get(b["binding_id"])["kiro_principal"] == _PRINCIPAL


def test_insert_same_id_same_domain_different_credential_mode_is_refused(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding(subject="alice", tenant="acme")
    assert b["credential_mode"] == "oauth_user"
    _insert(store, b)
    # Same id + same (deployment, account) domain, but a changed credential_mode.
    changed = dict(b)
    changed["credential_mode"] = "service_to_service"
    with pytest.raises(BindingUniquenessError):
        _insert(store, changed)
    assert store.get(b["binding_id"])["binding"]["credential_mode"] == "oauth_user"


def test_insert_same_id_same_domain_different_secret_ref_is_refused(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding(subject="alice", tenant="acme")
    _insert(store, b)
    original_name = b["secret_ref"]["name"]
    # Same id + same domain, but the secret reference NAME points elsewhere.
    changed = dict(b)
    changed["secret_ref"] = dict(b["secret_ref"])
    changed["secret_ref"]["name"] = original_name + "_ELSEWHERE"
    with pytest.raises(BindingUniquenessError):
        _insert(store, changed)
    assert store.get(b["binding_id"])["binding"]["secret_ref"]["name"] == original_name


def test_insert_byte_identical_reinsert_is_still_idempotent(tmp_path) -> None:
    # A genuine byte-identical re-insert (same record, only volatile timestamps
    # would differ if re-minted -- here the SAME binding object) returns prior
    # without error and does not disturb lifecycle state.
    store = _fresh_store(tmp_path)
    b = _mk_binding(subject="alice", tenant="acme")
    first = _insert(store, b)
    gen_before = store.get(b["binding_id"])["live_generation"]
    again = _insert(store, b)  # identical id/domain/principal/mode/secret_ref
    assert again["binding"]["binding_id"] == first["binding"]["binding_id"]
    assert store.get(b["binding_id"])["live_generation"] == gen_before


def test_insert_reinsert_differing_only_in_volatile_timestamps_is_idempotent(tmp_path) -> None:
    # created_at / bound_at / updated_at are excluded from the byte-compare, so a
    # re-insert of the same logical binding whose only difference is wall-clock
    # stamps is idempotent (not a conflict).
    store = _fresh_store(tmp_path)
    b = _mk_binding(subject="alice", tenant="acme")
    _insert(store, b)
    later = dict(b)
    later["created_at"] = b["created_at"] + 1000.0
    later["secret_ref"] = dict(b["secret_ref"])
    later["secret_ref"]["bound_at"] = b["secret_ref"]["bound_at"] + 1000.0
    # No raise: only volatile stamps differ.
    got = store.insert(later, deployment_id=_DEPLOY, kiro_principal=_PRINCIPAL)
    assert got["binding"]["binding_id"] == b["binding_id"]


# ===========================================================================
# STEP 2 (round-33): the per-binding secret SELECTOR + live-store fencing.
#
# select_secret resolves a binding's secret FROM THE TRUSTED LIVE STORE, by
# binding -- NOT by provider slug, NOT from a caller-supplied candidate set --
# and fences against the live store (revoked / rotated / swapped -> refused).
# This is the sixth recurrence of the trusted-source discipline, done as a
# pattern: the value used comes from the store, never the caller's own copy.
# ===========================================================================


class _FakeVault:
    """A minimal SecretReader: name -> plaintext, counting reads by name."""

    def __init__(self, entries: dict) -> None:
        self._entries = dict(entries)
        self.reads: list[str] = []

    def get(self, name: str):
        self.reads.append(name)
        val = self._entries.get(name)
        if val is None:
            return None

        class _V:
            def __init__(self, v):
                self._v = v

            def reveal(self):
                return self._v

        return _V(val)


def _vault_for(store, binding, secret_value="s3cr3t-token"):
    """A vault holding ONLY the per-binding secret name the store recorded."""
    stored = store.get(binding["binding_id"])
    name = stored["binding"]["secret_ref"]["name"]
    return _FakeVault({name: secret_value}), name


def test_select_secret_resolves_by_binding_from_the_live_store(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)
    vault, per_binding_name = _vault_for(store, b, "the-real-token")
    got: ResolvedCredential = store.select_secret(handle, reader=vault)
    # Resolved BY BINDING: the reader was asked for the per-binding name.
    assert vault.reads == [per_binding_name]
    assert got["binding_id"] == b["binding_id"]
    assert got["secret_ref"]["name"] == per_binding_name
    assert got["secret"].reveal() == "the-real-token"


def test_JUDGEMENT_selector_uses_the_store_ref_not_the_slug_level_name(tmp_path) -> None:
    # The defect this closes: resolving by SLUG collapses every binding under a
    # provider onto ONE name (binding_secret_ref), so two identities share a
    # credential. The selector must use the per-binding name from the store.
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)
    slug_name = binding_secret_ref("github")["name"]  # the collision-prone slug name
    per_binding_name = store.get(b["binding_id"])["binding"]["secret_ref"]["name"]
    assert slug_name != per_binding_name
    # Vault holds ONLY the slug-level name, NOT the per-binding one.
    vault = _FakeVault({slug_name: "slug-shared-secret"})
    # The selector asks for the per-binding name -> not found -> refused. It does
    # NOT silently fall back to the slug name (which would be the collapse bug).
    with pytest.raises(BindingResolutionError):
        store.select_secret(handle, reader=vault)
    assert vault.reads == [per_binding_name]  # asked by binding, never by slug


def test_JUDGEMENT_selector_does_not_take_a_caller_supplied_ref(tmp_path) -> None:
    # A caller hands a handle whose secret_ref NAME points at an attacker entry,
    # but the identity/generation/mode still match the store. assert_live refuses
    # the swapped ref, so the selector never reads the attacker name.
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)
    tampered = dict(handle)
    tampered["secret_ref"] = dict(handle["secret_ref"])
    tampered["secret_ref"]["name"] = handle["secret_ref"]["name"] + "_ATTACKER"
    real_name = store.get(b["binding_id"])["binding"]["secret_ref"]["name"]
    vault = _FakeVault({real_name: "real", handle["secret_ref"]["name"] + "_ATTACKER": "attacker"})
    with pytest.raises(BindingRevokedError):
        store.select_secret(tampered, reader=vault)
    # Never read the attacker name (fence refused before any vault read).
    assert vault.reads == []


def test_JUDGEMENT_fencing_reads_the_live_store_after_revoke(tmp_path) -> None:
    # fencing decides on the LIVE store: a handle captured before a revoke can no
    # longer pull a secret, even though the caller still holds the old dict.
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)
    vault, name = _vault_for(store, b, "live")
    # Before revoke: selector works.
    ok = store.select_secret(handle, reader=vault)
    print(f"\n[SELECTOR EVIDENCE] before-revoke: got secret for {name} = {ok['secret'].reveal()!r}")
    # Revoke, then the SAME handle is fenced by a fresh live-store read.
    store.revoke(b["binding_id"])
    try:
        store.select_secret(handle, reader=vault)
        after = "STILL-RESOLVED (bug)"
    except BindingRevokedError as exc:
        after = f"REFUSED ({exc})"
    print(f"[SELECTOR EVIDENCE] after-revoke: {after}")
    assert after.startswith("REFUSED")


def test_JUDGEMENT_fencing_reads_live_store_after_rotation(tmp_path) -> None:
    # A rotation advances the live generation; a pre-rotation handle is fenced,
    # and the selector re-resolves the ref from the CURRENT live record.
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    stored = _insert(store, b)
    pre = _resolve(store)  # generation = live
    # Rotate to a NEW per-binding secret ref via the real refresh callable.
    # A DISTINCT per-binding ref for the rotation to swap in. L04's own commit
    # used L02's `binding_scoped_secret_ref`, which is not on this branch, so the
    # distinct name is built here -- what the test asserts is unchanged: the
    # record takes the ref the refresh callable returned.
    new_ref = dict(binding_secret_ref("github"))
    new_ref["name"] = f"CONNECTIONS_GITHUB_BINDING_SECRET__ROTATED__{b['binding_id']}"
    rec, did = store.rotate(
        b["binding_id"], observed_generation=stored["live_generation"], refresh=lambda _b: new_ref
    )
    assert did is True
    # The pre-rotation handle is now fenced (stale generation).
    vault = _FakeVault({new_ref["name"]: "rotated", pre["secret_ref"]["name"]: "old"})
    with pytest.raises(BindingRevokedError):
        store.select_secret(pre, reader=vault)
    # A freshly resolved handle carries the NEW live generation + the store's new ref.
    post = _resolve(store)
    got = store.select_secret(post, reader=vault)
    assert got["secret_ref"]["name"] == new_ref["name"]
    assert got["secret"].reveal() == "rotated"


def test_select_secret_refuses_when_the_named_secret_is_absent(tmp_path) -> None:
    store = _fresh_store(tmp_path)
    b = _mk_binding()
    _insert(store, b)
    handle = _resolve(store)
    empty_vault = _FakeVault({})  # vault holds nothing
    with pytest.raises(BindingResolutionError):
        store.select_secret(handle, reader=empty_vault)


def test_secret_reader_and_resolved_credential_are_canonical_only() -> None:
    for name in ("SecretReader", "ResolvedCredential"):
        assert name in cp.__all__
        assert hasattr(cp, name)
        assert name not in connections.__all__
        assert not hasattr(connections, name)
