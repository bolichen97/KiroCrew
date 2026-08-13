"""Contract tests for Connections tool-name collision resolution.

Two exposed MCP providers that ship the same tool name leave one of the two
unreachable, because kiro-cli addresses a tool by bare name. Every reachable row
of the resolver's governing decision table (EXPOSURE x IDENTITY x DECLARATION
LIFECYCLE, see :mod:`kiro_crew.connections.tool_aliases`) has a named test here,
followed by the emission pass's own three invariants.

Ownership of an already-written alias is decided by the persisted record in
:mod:`kiro_crew.connections.alias_record`, never by the shape of the name, so
that module's invariants are covered too -- including the write ORDERING, which
is what keeps the record from authorizing the deletion of a pair the spec never
carried. The mutation checks at the end reinstate each rejected shape rule and
show it failing on the case that killed it: the happy path passes under all of
them, which is why three rounds of shape-based fixes each looked correct.
"""

import json
from unittest.mock import patch

import pytest

from kiro_crew.connections import RegistryValidationError, get_all_registry_providers
from kiro_crew.connections.alias_record import (
    emitted_from_alias_map,
    is_recorded_emission,
    load_emitted_aliases,
    record_path,
    split_tool_ref,
    store_emitted_aliases,
)
from kiro_crew.connections.registry import _load_registry
from kiro_crew.connections.tool_aliases import (
    declared_tool_aliases,
    derived_alias,
    exposed_declared_tools,
    exposed_server_keys,
    natural_tool_names,
    normalized_endpoint,
    resolve_tool_aliases,
    statically_visible_tool_names,
)

URLS = {
    "github": "https://api.githubcopilot.com/mcp/",
    "linear": "https://mcp.linear.app/mcp/readonly",
    "vercel": "https://mcp.vercel.com",
    "gitlab": "https://gitlab.com/api/v4/mcp",
}


def _servers(*slugs: str) -> dict:
    return {slug: {"url": URLS[slug]} for slug in slugs}


def _aliases(servers: dict, tools: list) -> dict:
    return resolve_tool_aliases(exposed_declared_tools(servers, tools))


# ── the declarations themselves ──


def test_linear_and_vercel_both_declare_the_tools_they_share():
    """The launch-set collision this slice exists for: without declarations on
    BOTH sides, whichever mounts second wins and the other is unreachable."""
    declared = declared_tool_aliases()
    shared = set(declared["linear"]) & set(declared["vercel"])
    assert shared == {"list_projects", "get_project", "list_teams"}


def test_issue_tools_are_declared_across_every_issue_tracker():
    declared = declared_tool_aliases()
    for slug in ("linear", "github", "gitlab"):
        assert {"list_issues", "get_issue"} <= set(declared[slug]), slug


def test_every_declared_alias_is_globally_unique():
    aliases = [alias for tools in declared_tool_aliases().values() for alias in tools.values()]
    assert len(aliases) == len(set(aliases))


def test_no_declared_alias_lands_on_a_declared_natural_tool_name():
    declared = declared_tool_aliases()
    naturals = {tool for tools in declared.values() for tool in tools}
    destinations = {alias for tools in declared.values() for alias in tools.values()}
    assert not naturals & destinations


def test_every_declared_alias_equals_its_derivation():
    """The emission pass recognises its own prior output by re-deriving this name;
    an alias that is not its own derivation would never be recognised."""
    for slug, tools in declared_tool_aliases().items():
        for tool, alias in tools.items():
            assert alias == f"{slug}_{tool}", f"{slug}/{tool} -> {alias}"


def test_providers_without_collisions_declare_nothing():
    assert not {"notion", "stripe", "atlassian"} & set(declared_tool_aliases())


# ── table rows 1-3: whole-server exposure, identity matched ──


def test_row1_whole_server_both_sides_aliases_the_shared_tools():
    aliases = _aliases(_servers("linear", "vercel"), ["@linear", "@vercel"])
    assert aliases["@linear/list_projects"] == "linear_list_projects"
    assert aliases["@vercel/list_projects"] == "vercel_list_projects"
    assert set(aliases) == {
        "@linear/get_project",
        "@linear/list_projects",
        "@linear/list_teams",
        "@vercel/get_project",
        "@vercel/list_projects",
        "@vercel/list_teams",
    }


def test_row1_whole_server_alone_keeps_natural_names():
    assert _aliases(_servers("linear"), ["@linear"]) == {}
    assert _aliases(_servers("vercel"), ["@vercel"]) == {}


def test_row1_whole_server_pair_with_no_shared_declaration_aliases_nothing():
    """Linear declares issue tools, Vercel declares none, so mounting the pair
    must not rename Linear's issue tools."""
    aliases = _aliases(_servers("linear", "vercel"), ["@linear", "@vercel"])
    assert "@linear/list_issues" not in aliases


def test_row2_a_renamed_declaration_replaces_the_old_alias():
    from kiro_crew.connections import tool_aliases as ta

    renamed = {
        "linear": {"list_projects": "linear_projects"},
        "vercel": {"list_projects": "vercel_projects"},
    }
    with patch.object(ta, "declared_tool_aliases", return_value=renamed):
        aliases = _aliases(_servers("linear", "vercel"), ["@linear", "@vercel"])

    assert aliases == {
        "@linear/list_projects": "linear_projects",
        "@vercel/list_projects": "vercel_projects",
    }


def test_row3_a_withdrawn_declaration_yields_no_alias():
    from kiro_crew.connections import tool_aliases as ta

    with patch.object(ta, "declared_tool_aliases", return_value={"vercel": {"x": "vercel_x"}}):
        assert _aliases(_servers("linear", "vercel"), ["@linear", "@vercel"]) == {}


# ── table rows 4-6: per-tool exposure ──


def test_row4_per_tool_refs_on_disjoint_tools_alias_nothing():
    """Provider-level eligibility renamed both sides here even though the EXPOSED
    tools cannot collide -- mounting one tool is not mounting the server."""
    aliases = _aliases(
        _servers("linear", "github"), ["@linear/list_issues", "@github/get_issue"]
    )
    assert aliases == {}


def test_row4_per_tool_refs_on_the_same_tool_alias_both():
    aliases = _aliases(
        _servers("linear", "github"), ["@linear/list_issues", "@github/list_issues"]
    )
    assert aliases == {
        "@github/list_issues": "github_list_issues",
        "@linear/list_issues": "linear_list_issues",
    }


def test_row4_whole_server_against_per_tool_aliases_only_the_overlap():
    aliases = _aliases(_servers("linear", "vercel"), ["@linear", "@vercel/list_projects"])
    assert set(aliases) == {"@linear/list_projects", "@vercel/list_projects"}


def test_row4_whole_server_against_a_non_overlapping_per_tool_aliases_nothing():
    assert _aliases(_servers("linear", "vercel"), ["@linear", "@vercel/get_deployment"]) == {}


def test_row5_a_renamed_declaration_applies_to_the_exposed_tool_only():
    from kiro_crew.connections import tool_aliases as ta

    renamed = {
        "linear": {"list_issues": "linear_issues", "get_issue": "linear_issue"},
        "github": {"list_issues": "github_issues", "get_issue": "github_issue"},
    }
    with patch.object(ta, "declared_tool_aliases", return_value=renamed):
        aliases = _aliases(
            _servers("linear", "github"), ["@linear/list_issues", "@github/list_issues"]
        )

    assert aliases == {
        "@github/list_issues": "github_issues",
        "@linear/list_issues": "linear_issues",
    }


def test_row6_a_ref_naming_an_undeclared_tool_exposes_nothing():
    exposed = exposed_declared_tools(_servers("linear", "vercel"), ["@linear/nope", "@vercel"])
    assert "linear" not in exposed
    assert _aliases(_servers("linear", "vercel"), ["@linear/nope", "@vercel"]) == {}


# ── table rows 7-12: wildcards ──


def test_row7_the_global_wildcard_exposes_every_declared_source():
    wildcard = _aliases(_servers("linear", "vercel"), ["*"])
    whole = _aliases(_servers("linear", "vercel"), ["@linear", "@vercel"])
    assert wildcard == whole


def test_row10_a_per_server_wildcard_reads_as_whole_server():
    """Over-reading renames an unmounted tool, which is inert; under-reading
    leaves a real collision shadowed."""
    starred = _aliases(_servers("linear", "vercel"), ["@linear/*", "@vercel/*"])
    whole = _aliases(_servers("linear", "vercel"), ["@linear", "@vercel"])
    assert starred == whole


def test_a_whole_server_ref_wins_over_a_sibling_per_tool_ref():
    exposed = exposed_declared_tools(
        _servers("linear"), ["@linear/list_issues", "@linear", "@linear/get_issue"]
    )
    assert exposed["linear"] == frozenset(declared_tool_aliases()["linear"])


# ── table rows 13-18: not mounted ──


def test_row13_an_allowed_tools_only_ref_exposes_nothing():
    """``allowedTools`` auto-approves; ``tools`` is the closed allowlist that
    MOUNTS, so a ref absent from it cannot collide with anything."""
    servers = _servers("linear", "vercel")
    assert exposed_declared_tools(servers, []) == {}
    assert _aliases(servers, []) == {}


def test_row16_an_absent_provider_exposes_nothing():
    assert _aliases(_servers("linear", "vercel"), ["@linear"]) == {}


def test_builtin_entries_are_not_server_refs():
    assert exposed_server_keys(["fs_read", "code", "@linear"]) == {"linear"}
    assert exposed_server_keys(["*", "@linear"]) is None


# ── table rows 19-54: identity ──


def test_a_url_mismatched_server_gets_no_aliases():
    """Rows 19-36 collapse: identity gates before exposure, so a server that is
    not the provider has no claim on its declarations whatever ``tools`` says."""
    servers = {"linear": {"url": "https://evil.example.com/mcp"}, "vercel": {"url": URLS["vercel"]}}
    assert set(exposed_declared_tools(servers, ["@linear", "@vercel"])) == {"vercel"}
    assert _aliases(servers, ["@linear", "@vercel"]) == {}


def test_a_custom_server_carrying_a_registry_name_gets_no_aliases():
    """Rows 37-54. A registry slug is not proof of identity -- anyone can add a
    server named ``linear``."""
    servers = {"linear": {"command": "npx", "args": ["x"]}, "vercel": {"url": URLS["vercel"]}}
    assert set(exposed_declared_tools(servers, ["@linear", "@vercel"])) == {"vercel"}


def test_endpoint_matching_tolerates_a_trailing_slash_and_case():
    servers = {
        "github": {"url": "https://API.GithubCopilot.com/mcp"},
        "gitlab": {"url": URLS["gitlab"]},
    }
    assert set(exposed_declared_tools(servers, ["@github", "@gitlab"])) == {"github", "gitlab"}


def test_endpoint_matching_rejects_a_different_path_on_the_right_host():
    """Linear ships a read-only endpoint AND a read-write one; only the pinned one
    carries the tool set the declarations describe."""
    servers = {"linear": {"url": "https://mcp.linear.app/mcp"}, "vercel": {"url": URLS["vercel"]}}
    assert set(exposed_declared_tools(servers, ["@linear", "@vercel"])) == {"vercel"}


@pytest.mark.parametrize("bad", [None, "", "   ", 42, "not-a-url", "://broken", ["u"]])
def test_unusable_endpoints_normalize_to_none(bad):
    assert normalized_endpoint(bad) is None


def test_a_non_dict_server_entry_is_not_eligible():
    servers = {"linear": "nope", "vercel": {"url": URLS["vercel"]}}
    assert set(exposed_declared_tools(servers, ["*"])) == {"vercel"}


# ── determinism ──


def test_resolution_is_independent_of_order_and_is_sorted():
    forward = _aliases(_servers("linear", "vercel", "github"), ["@linear", "@vercel", "@github"])
    reverse = _aliases(_servers("github", "vercel", "linear"), ["@github", "@vercel", "@linear"])
    assert forward == reverse
    assert list(forward) == sorted(forward)


def test_three_way_collision_aliases_every_claimant():
    aliases = _aliases(
        _servers("linear", "github", "gitlab"), ["@linear", "@github", "@gitlab"]
    )
    assert {aliases[f"@{slug}/list_issues"] for slug in ("linear", "github", "gitlab")} == {
        "linear_list_issues",
        "github_list_issues",
        "gitlab_list_issues",
    }


def test_a_duplicated_slug_is_one_provider_not_a_collision():
    assert resolve_tool_aliases({"linear": ["list_projects", "list_projects"]}) == {}


def test_natural_tool_names_are_the_exposed_pre_alias_names():
    assert natural_tool_names({"vercel": {"list_projects"}}) == {"list_projects"}
    assert natural_tool_names({}) == set()


# ── the persisted ownership record ──


@pytest.mark.parametrize(
    "ref,alias,expected",
    [
        # Claimed: the whole triple is in the record.
        ("@linear/list_projects", "linear_list_projects", True),
        # NOT claimed: the record does not hold it, whatever it looks like. The
        # second row is the finding a re-derivation rule could not survive --
        # ``notion`` declares nothing and this pass never emitted for it, yet
        # ``notion_search`` is exactly the name it WOULD derive.
        ("@linear/list_issues", "linear_issues", False),
        ("@notion/search", "notion_search", False),
        ("@vercel/list_projects", "vercel_list_projects", False),
        # NOT claimed: right ref, but the value no longer matches the recorded
        # form. Membership of the whole triple IS the byte-equality test.
        ("@linear/list_projects", "linear_list_projects ", False),
        ("@linear/list_projects", "Linear_List_Projects", False),
        ("@linear/list_projects", "my_projects", False),
        # NOT claimed: malformed or non-per-tool refs name no single tool.
        ("@linear", "linear_list_projects", False),
        ("linear/list_projects", "linear_list_projects", False),
        ("@/list_projects", "linear_list_projects", False),
        ("@linear/", "linear_list_projects", False),
        ("@linear/list_projects", 42, False),
        (42, "linear_list_projects", False),
        (None, None, False),
    ],
)
def test_ownership_is_decided_by_the_record_not_by_the_name(ref, alias, expected):
    """Shape asks about the present; ownership is a fact about the past. Only a
    recorded emission may be stripped, so a hand-written name that merely looks
    generated is never claimed."""
    record = {("linear", "list_projects", "linear_list_projects")}
    assert is_recorded_emission(record, ref, alias) is expected


def test_an_empty_record_claims_nothing():
    for ref, alias in [
        ("@linear/list_projects", "linear_list_projects"),
        ("@notion/search", "notion_search"),
    ]:
        assert is_recorded_emission(frozenset(), ref, alias) is False


@pytest.mark.parametrize(
    "ref,expected",
    [
        ("@linear/list_projects", ("linear", "list_projects")),
        ("@linear/a/b", ("linear", "a/b")),
        ("@linear", None),
        ("@linear/", None),
        ("@/tool", None),
        ("linear/tool", None),
        ("", None),
        (42, None),
    ],
)
def test_a_tool_ref_splits_only_when_it_names_one_tool(ref, expected):
    assert split_tool_ref(ref) == expected


def test_an_alias_map_converts_to_record_triples():
    assert emitted_from_alias_map(
        {"@linear/list_projects": "linear_list_projects", "@vercel": "ignored"}
    ) == frozenset({("linear", "list_projects", "linear_list_projects")})


def test_the_record_round_trips_through_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    triples = frozenset(
        {
            ("linear", "list_projects", "linear_list_projects"),
            ("vercel", "list_projects", "vercel_list_projects"),
        }
    )
    store_emitted_aliases(triples)
    assert load_emitted_aliases() == triples


def test_an_absent_record_reads_as_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    assert not record_path().exists()
    assert load_emitted_aliases() == frozenset()


@pytest.mark.parametrize(
    "payload",
    [
        "{ not json",
        "",
        "null",
        "[]",
        '"a string"',
        "{}",
        '{"emitted": []}',  # no version
        '{"version": 99, "emitted": [{"slug": "l", "tool": "t", "alias": "a"}]}',
        '{"version": 1, "emitted": {}}',
        '{"version": 1}',
    ],
)
def test_a_corrupt_or_unknown_record_reads_as_empty(payload, tmp_path, monkeypatch):
    """Invariant 4: losing the record must degrade to "every pair is the user's",
    never to deleting entries on a bad parse."""
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    path = record_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    assert load_emitted_aliases() == frozenset()


def test_a_record_entry_that_is_not_three_strings_is_dropped(tmp_path, monkeypatch):
    """Dropping a malformed entry UNDERSTATES, which is the safe direction."""
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    path = record_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "emitted": [
                    {"slug": "linear", "tool": "list_projects", "alias": "linear_list_projects"},
                    {"slug": "vercel", "tool": "list_projects"},
                    {"slug": "vercel", "tool": 7, "alias": "x"},
                    "not a dict",
                ],
            }
        ),
        encoding="utf-8",
    )
    assert load_emitted_aliases() == frozenset(
        {("linear", "list_projects", "linear_list_projects")}
    )


def test_an_unwritable_record_never_raises(tmp_path, monkeypatch):
    """Invariant 5: the record is bookkeeping for the next pass, so a failure to
    persist it must not fail the rebuild that carries it."""
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    with patch(
        "kiro_crew.connections.alias_record.atomic_write", side_effect=OSError("read-only")
    ):
        store_emitted_aliases({("linear", "list_projects", "linear_list_projects")})
    assert load_emitted_aliases() == frozenset()


def test_storing_an_empty_set_relinquishes_every_earlier_claim(tmp_path, monkeypatch):
    """The empty write is not a no-op: it is how the pass gives up pairs it no
    longer emits. Skipping it would leave a superseded triple claimable forever."""
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    store_emitted_aliases({("linear", "list_projects", "linear_list_projects")})
    store_emitted_aliases(frozenset())
    assert load_emitted_aliases() == frozenset()
    assert record_path().exists()


# ── the generated-shape domain (name generation only) ──


@pytest.mark.parametrize(
    "slug,tool,expected",
    [
        ("linear", "list_projects", "linear_list_projects"),
        ("vercel", "get_project", "vercel_get_project"),
    ],
)
def test_the_derived_name_pins_slug_and_tool(slug, tool, expected):
    assert derived_alias(slug, tool) == expected


def test_the_derived_name_is_the_one_the_registry_declares():
    """``derived_alias`` is the NAME GENERATOR: the validator pins every
    declaration to it, so a reader sees the exact name that will be emitted. It is
    not an ownership test -- see the record tests below."""
    for slug, tools in declared_tool_aliases().items():
        for tool, alias in tools.items():
            assert alias == derived_alias(slug, tool)


# ── statically visible names (destination reservation input) ──


def test_per_tool_refs_of_any_server_are_statically_visible():
    visible = statically_visible_tool_names(
        ["fs_read", "@mycustom/linear_list_projects", "@linear", "@vercel/list_projects"]
    )
    assert visible == {"linear_list_projects", "list_projects"}


def test_a_whole_server_mount_publishes_no_statically_visible_names():
    """The OUT OF SCOPE row: a custom server mounted whole names its tools only
    at runtime, so nothing static can see them."""
    assert statically_visible_tool_names(["@mycustom", "@mycustom/*", "*"]) == set()


def test_a_per_tool_ref_survives_a_whole_server_ref_on_the_same_server():
    """Reservation is precedence-INDEPENDENT. Exposure lets ``@mycustom``
    supersede ``@mycustom/x`` because the wider ref already mounts it, but the
    explicit name is still occupied and a generated alias must not land on it."""
    visible = statically_visible_tool_names(
        ["@linear", "@vercel", "@mycustom", "@mycustom/vercel_list_projects"]
    )
    assert "vercel_list_projects" in visible


def test_reservation_does_not_change_exposure_precedence():
    """The companion half: exposure keeps whole-server-wins, so the narrower ref
    does not shrink what a provider exposes."""
    exposed = exposed_declared_tools(
        _servers("linear"), ["@linear", "@linear/list_issues"]
    )
    assert exposed["linear"] == frozenset(declared_tool_aliases()["linear"])


# ── registry validation ──


def _registry(tmp_path, mutate):
    payload = get_all_registry_providers()
    mutate(payload)
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"list_issues": ""},
        {"list_issues": "has space"},
        {"list_issues": "has/slash"},
        {"list_issues": "@server"},
        {"list_issues": 42},
        {"": "alias_name"},
        {" list_issues": "alias_name"},
        {"has space": "alias_name"},
        {"has/slash": "alias_name"},
        {"@server/tool": "alias_name"},
        ["list_issues"],
        "list_issues",
    ],
)
def test_malformed_tool_aliases_are_rejected_at_load(tmp_path, bad):
    """A bad alias reaches the emitted agent spec, where kiro-cli rejects the
    WHOLE spec and the agent loses every tool. A malformed KEY is worse than
    loud: it silently never matches a real tool."""
    path = _registry(tmp_path, lambda p: p[0].update(tool_aliases=bad))
    with pytest.raises(RegistryValidationError, match="tool_aliases"):
        _load_registry(path)


@pytest.mark.parametrize(
    "alias",
    ["list_issues", "shared_name", "linearlist", "linea_list", "linear_issues", "linear_"],
)
def test_an_alias_that_is_not_its_own_derivation_is_rejected(tmp_path, alias):
    """Ownership is decided by re-deriving ``<slug>_<tool>`` from the ref, so an
    alias that is not that name would be emitted and then never recognised as
    ours -- it would outlive its own declaration. ``linear_issues`` is in the list
    because it is exactly the prefix-shaped name a user might hand-write, and the
    registry must not be able to mint one that collides with that space."""

    def mutate(payload):
        linear = next(p for p in payload if p["slug"] == "linear")
        linear["tool_aliases"] = {"list_issues": alias}

    with pytest.raises(RegistryValidationError, match="must be exactly"):
        _load_registry(_registry(tmp_path, mutate))


def test_the_derived_alias_is_accepted(tmp_path):
    def mutate(payload):
        linear = next(p for p in payload if p["slug"] == "linear")
        linear["tool_aliases"] = {"list_issues": "linear_list_issues"}

    loaded = {p["slug"]: p for p in _load_registry(_registry(tmp_path, mutate))}
    assert loaded["linear"]["tool_aliases"] == {"list_issues": "linear_list_issues"}


def test_two_tools_cannot_share_one_alias(tmp_path):
    """Derivation subsumes the uniqueness check: an alias shared by two tools is
    not its own derivation for at least one of them, so it is rejected."""

    def mutate(payload):
        linear = next(p for p in payload if p["slug"] == "linear")
        linear["tool_aliases"] = {"list_issues": "linear_same", "get_issue": "linear_same"}

    with pytest.raises(RegistryValidationError, match="must be exactly"):
        _load_registry(_registry(tmp_path, mutate))


def test_tool_aliases_does_not_widen_the_schema(tmp_path):
    path = _registry(tmp_path, lambda p: p[0].update(tool_nicknames={"list_issues": "x"}))
    with pytest.raises(RegistryValidationError, match="unknown fields: tool_nicknames"):
        _load_registry(path)


def test_a_malformed_slug_is_still_rejected(tmp_path):
    """The slug check moved ahead of the alias block that depends on it."""
    path = _registry(tmp_path, lambda p: p[0].update(slug="Bad_Slug"))
    with pytest.raises(RegistryValidationError, match="slug must contain"):
        _load_registry(path)


# ── the emission pass ──


@pytest.fixture(autouse=True)
def _isolated_alias_record(tmp_path, monkeypatch):
    """Point the emitted-alias record at a per-test data home.

    Autouse because the pass READS the record on every run: without this a test
    would consult (and :func:`_apply` would write) the developer's real
    ``~/.kiro/crew``, and the record would leak between tests. Function-scoped, so
    each test starts with no record at all -- the missing-record case -- and the
    two ``_apply`` calls inside one test share the record the way two rebuilds do.
    """
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))


def _spec(*slugs: str, tools: list | None = None) -> dict:
    return {
        "mcpServers": {slug: {"url": URLS[slug]} for slug in slugs},
        "tools": [f"@{slug}" for slug in slugs] if tools is None else tools,
        "allowedTools": ["@linear"],
    }


def _apply(config: dict, *, enabled: bool = True, persist: bool = True) -> dict:
    """Run the pass the way ``rebuild_agent_config`` does, record write included.

    The ordering is the point and is reproduced here rather than assumed: the pass
    returns what it emitted and the CALLER records it, only after the spec is
    durable. ``persist=False`` models a crash in that window -- the spec is written
    but the record never is.
    """
    from kiro_crew import agent

    with patch.object(agent, "_connection_tool_aliases_enabled", return_value=enabled):
        emitted = agent._apply_connection_tool_aliases(config)
    if persist and emitted is not None:
        store_emitted_aliases(emitted)
    return config


# gate-off inertness


def test_flag_off_leaves_a_colliding_spec_byte_identical():
    baseline = json.dumps(_spec("linear", "vercel"), sort_keys=True)
    after = _apply(_spec("linear", "vercel"), enabled=False)
    assert json.dumps(after, sort_keys=True) == baseline
    assert "toolAliases" not in after


def test_flag_off_does_not_clear_an_existing_key():
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@linear/list_projects": "mine"}
    assert _apply(config, enabled=False)["toolAliases"] == {"@linear/list_projects": "mine"}


def test_flag_on_writes_the_resolved_map():
    after = _apply(_spec("linear", "vercel"))
    assert after["toolAliases"]["@vercel/list_projects"] == "vercel_list_projects"
    assert after["toolAliases"]["@linear/list_projects"] == "linear_list_projects"


def test_flag_on_without_a_collision_writes_no_key():
    assert "toolAliases" not in _apply(_spec("linear"))


def test_flag_on_never_touches_tools_or_allowed_tools():
    after = _apply(_spec("linear", "vercel"))
    assert after["tools"] == ["@linear", "@vercel"]
    assert after["allowedTools"] == ["@linear"]


def test_a_spec_without_mcp_servers_is_left_alone():
    assert _apply({"tools": []}) == {"tools": []}


def test_the_pass_is_idempotent():
    first = _apply(_spec("linear", "vercel"))
    assert _apply(dict(first)) == first


def test_per_tool_exposure_reaches_the_emission_layer():
    """The V1 row end to end: disjoint per-tool mounts emit no key at all."""
    spec = _spec("linear", "github", tools=["@linear/list_issues", "@github/get_issue"])
    assert "toolAliases" not in _apply(spec)


def test_disabling_one_provider_leaves_the_other_natural():
    assert "toolAliases" not in _apply(_spec("linear", "vercel", tools=["@linear"]))


# staleness, including registry drift


def test_disconnecting_a_provider_restores_natural_names():
    aliased = _apply(_spec("linear", "vercel"))
    assert aliased["toolAliases"]
    rebuilt = _apply({**_spec("linear"), "toolAliases": dict(aliased["toolAliases"])})
    assert "toolAliases" not in rebuilt


def test_a_renamed_registry_declaration_replaces_the_stranded_alias():
    """A tool-key rename is the reachable form of registry drift -- an alias-value
    rename is unreachable, because the validator pins each alias to its own
    derivation. Either way the superseded pair must not outlive its declaration."""
    from kiro_crew.connections import tool_aliases as ta

    first = _apply(_spec("linear", "vercel"))
    assert first["toolAliases"]["@linear/list_projects"] == "linear_list_projects"

    renamed = {
        "linear": {"list_all_projects": "linear_list_all_projects"},
        "vercel": {"list_all_projects": "vercel_list_all_projects"},
    }
    with patch.object(ta, "declared_tool_aliases", return_value=renamed):
        second = _apply({**_spec("linear", "vercel"), "toolAliases": dict(first["toolAliases"])})

    assert second["toolAliases"] == {
        "@linear/list_all_projects": "linear_list_all_projects",
        "@vercel/list_all_projects": "vercel_list_all_projects",
    }


def test_a_withdrawn_registry_declaration_drops_its_alias():
    from kiro_crew.connections import tool_aliases as ta

    first = _apply(_spec("linear", "vercel"))
    with patch.object(ta, "declared_tool_aliases", return_value={"vercel": {"x": "vercel_x"}}):
        second = _apply({**_spec("linear", "vercel"), "toolAliases": dict(first["toolAliases"])})

    assert "toolAliases" not in second


def test_a_user_alias_with_a_generated_looking_name_survives_a_rebuild():
    """B1: a prefix-shaped ownership test claims ``linear_issues`` -- it starts with
    ``linear_`` -- and a rebuild deletes or overwrites a deliberate user edit.
    Ownership must be proven by derivation, and ``linear_issues`` is not the name
    this pass would emit for ``@linear/list_issues`` (that is
    ``linear_list_issues``), so it is preserved with the flag ON."""
    config = _spec("linear", "vercel")
    config["toolAliases"] = {
        "@linear/list_issues": "linear_issues",
        "@vercel/get_project": "vercel_proj",
    }

    first = _apply(config)
    assert first["toolAliases"]["@linear/list_issues"] == "linear_issues"
    assert first["toolAliases"]["@vercel/get_project"] == "vercel_proj"

    second = _apply(dict(first))
    assert second["toolAliases"]["@linear/list_issues"] == "linear_issues"
    assert second["toolAliases"]["@vercel/get_project"] == "vercel_proj"


def test_a_user_alias_on_an_undeclared_tool_of_a_registry_provider_survives():
    """The same class one step out: the ref names a real provider but a tool the
    registry never declared, so nothing about it is this pass's output."""
    config = _spec("linear")
    config["toolAliases"] = {"@linear/create_comment": "linear_comment"}

    assert _apply(config)["toolAliases"] == {"@linear/create_comment": "linear_comment"}


def test_a_user_alias_survives_even_when_it_shadows_a_generated_destination():
    """A user alias is preserved AND reserved: the generated pair that would have
    landed on the same name is skipped rather than overwriting it."""
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@mine/thing": "vercel_list_projects"}

    after = _apply(config)

    assert after["toolAliases"]["@mine/thing"] == "vercel_list_projects"
    assert "@vercel/list_projects" not in after["toolAliases"]


def test_a_user_authored_alias_survives_registry_drift():
    from kiro_crew.connections import tool_aliases as ta

    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@linear/list_projects": "issues_from_linear"}
    first = _apply(config)
    assert first["toolAliases"]["@linear/list_projects"] == "issues_from_linear"

    renamed = {"linear": {"list_projects": "linear_projects"}}
    with patch.object(ta, "declared_tool_aliases", return_value=renamed):
        second = _apply({**_spec("linear"), "toolAliases": dict(first["toolAliases"])})

    assert second["toolAliases"] == {"@linear/list_projects": "issues_from_linear"}


# the record as the ownership oracle, end to end


def test_a_hand_written_notion_search_survives_a_rebuild():
    """The round-2 blocking finding, as an end-to-end test. ``notion`` has no
    registry declaration, so this pass can never have emitted for it -- yet
    ``notion_search`` is EXACTLY what re-derivation would generate for
    ``@notion/search``. The record holds no such triple, so the entry stands."""
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@notion/search": "notion_search"}

    first = _apply(config)
    assert first["toolAliases"]["@notion/search"] == "notion_search"

    second = _apply(dict(first))
    assert second["toolAliases"]["@notion/search"] == "notion_search"

    third = _apply(dict(second))
    assert third["toolAliases"]["@notion/search"] == "notion_search"


def test_a_user_edited_generated_alias_survives():
    """Once the user changes the VALUE, the spec's triple stops matching the
    recorded one, so the pair is no longer claimed. Invariant 3 in the field."""
    first = _apply(_spec("linear", "vercel"))
    assert first["toolAliases"]["@linear/list_projects"] == "linear_list_projects"

    edited = dict(first["toolAliases"])
    edited["@linear/list_projects"] = "my_linear_projects"
    second = _apply({**_spec("linear", "vercel"), "toolAliases": edited})

    assert second["toolAliases"]["@linear/list_projects"] == "my_linear_projects"
    # The generated destination is skipped rather than overwriting the edit, and
    # the other provider's own pair still resolves.
    assert second["toolAliases"]["@vercel/list_projects"] == "vercel_list_projects"

    third = _apply(dict(second))
    assert third["toolAliases"]["@linear/list_projects"] == "my_linear_projects"


def test_the_record_equals_exactly_what_the_pass_emitted():
    after = _apply(_spec("linear", "vercel"))

    assert load_emitted_aliases() == frozenset(
        (ref[1:].split("/", 1)[0], ref[1:].split("/", 1)[1], alias)
        for ref, alias in after["toolAliases"].items()
    )


def test_a_retained_user_alias_is_not_recorded_as_emitted():
    """The record must hold ONLY this pass's own output: recording a user's pair
    would authorize deleting it on the next run."""
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@notion/search": "notion_search"}

    _apply(config)

    assert ("notion", "search", "notion_search") not in load_emitted_aliases()


def test_a_skipped_alias_is_not_recorded():
    """A generated pair rejected by the destination guard was never written, so
    recording it would claim a name the spec does not carry."""
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@mine/thing": "vercel_list_projects"}

    after = _apply(config)

    assert "@vercel/list_projects" not in after["toolAliases"]
    assert ("vercel", "list_projects", "vercel_list_projects") not in load_emitted_aliases()


def test_an_emitted_but_unrecorded_alias_is_never_claimed():
    """A crash between the durable spec write and the record write leaves an alias
    that no record claims. It must LINGER (shadowing, the safe direction) rather
    than be strippable -- the reverse ordering would instead record a pair the spec
    never carried, and a user later hand-writing that name would lose it."""
    crashed = _apply(_spec("linear", "vercel"), persist=False)
    assert crashed["toolAliases"]["@linear/list_projects"] == "linear_list_projects"
    assert load_emitted_aliases() == frozenset()
    stranded = dict(crashed["toolAliases"])

    rebuilt = _apply({**_spec("linear"), "toolAliases": dict(stranded)})

    assert rebuilt["toolAliases"] == stranded


def test_a_missing_record_claims_nothing_on_the_next_pass():
    """Deleting the record must not delete aliases -- it must forget ownership."""
    first = _apply(_spec("linear", "vercel"))
    record_path().unlink()

    second = _apply({**_spec("linear"), "toolAliases": dict(first["toolAliases"])})

    assert second["toolAliases"] == first["toolAliases"]


def test_a_corrupt_record_claims_nothing_on_the_next_pass():
    first = _apply(_spec("linear", "vercel"))
    record_path().write_text("{ not json", encoding="utf-8")

    second = _apply({**_spec("linear"), "toolAliases": dict(first["toolAliases"])})

    assert second["toolAliases"] == first["toolAliases"]


def test_an_unreadable_registry_leaves_the_record_untouched():
    """The pass returns None on a registry failure, and the caller must NOT then
    write an empty record: forgetting a real emission strands those aliases for
    good, which is the "permanently unclearable" failure narrowing produced."""
    from kiro_crew.connections import tool_aliases as ta

    first = _apply(_spec("linear", "vercel"))
    before = load_emitted_aliases()
    assert before

    with patch.object(ta, "declared_tool_aliases", side_effect=RuntimeError("bad registry")):
        assert _apply(dict(first), persist=True)["toolAliases"] == first["toolAliases"]

    assert load_emitted_aliases() == before

    # And with the registry readable again the stale pairs are still clearable.
    assert "toolAliases" not in _apply(
        {**_spec("linear"), "toolAliases": dict(first["toolAliases"])}
    )


def test_the_gate_off_pass_writes_no_record():
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@linear/list_projects": "linear_list_projects"}

    from kiro_crew import agent

    with patch.object(agent, "_connection_tool_aliases_enabled", return_value=False):
        assert agent._apply_connection_tool_aliases(config) is None
    assert not record_path().exists()


def test_a_spec_without_servers_leaves_the_record_alone():
    _apply(_spec("linear", "vercel"))
    before = load_emitted_aliases()

    from kiro_crew import agent

    with patch.object(agent, "_connection_tool_aliases_enabled", return_value=True):
        assert agent._apply_connection_tool_aliases({"tools": []}) is None
    assert load_emitted_aliases() == before


def test_the_record_empties_when_the_collision_goes_away():
    """Relinquishing is observable: after a rebuild with no collision the record
    must be EMPTY, not stale, or a user who later hand-writes the old generated
    name would have it deleted."""
    _apply(_spec("linear", "vercel"))
    assert load_emitted_aliases()

    _apply(_spec("linear"))

    assert load_emitted_aliases() == frozenset()

    # Proof of the consequence: that same name is now safe to hand-write.
    config = _spec("linear")
    config["toolAliases"] = {"@linear/list_projects": "linear_list_projects"}
    assert _apply(config)["toolAliases"] == {"@linear/list_projects": "linear_list_projects"}


def test_a_stale_generated_ref_for_a_gone_provider_is_removed():
    """The pair must be RECORDED to be strippable, so the stale state is reached by
    really emitting it and then unmounting the provider -- not by planting it."""
    emitted = _apply(_spec("linear", "vercel"))
    assert emitted["toolAliases"]["@vercel/list_projects"] == "vercel_list_projects"

    rebuilt = _apply({**_spec("linear"), "toolAliases": dict(emitted["toolAliases"])})

    assert "toolAliases" not in rebuilt


def test_a_hand_planted_generated_looking_ref_is_never_claimed():
    """Same bytes, no record: with nothing proving this pass wrote them, the pairs
    are the user's and survive. This is the shape-based rule's failure mode
    inverted -- ``notion_search`` below is the name re-derivation would have
    claimed even though ``notion`` declares nothing at all."""
    config = _spec("linear")
    config["toolAliases"] = {
        "@vercel/list_projects": "vercel_list_projects",
        "@linear/list_projects": "linear_list_projects",
        "@notion/search": "notion_search",
    }

    after = _apply(config)

    assert after["toolAliases"] == {
        "@vercel/list_projects": "vercel_list_projects",
        "@linear/list_projects": "linear_list_projects",
        "@notion/search": "notion_search",
    }


# ── mutation checks ──
#
# Each rejected ownership rule is reinstated here and shown FAILING on the exact
# case that killed it. Without these the record looks like unnecessary machinery:
# the happy-path tests pass under a shape rule too, which is how three rounds of
# shape-based fixes each looked correct until the next case arrived.


def _prefix_ownership(record, ref, alias):
    """Rejected rule 1: ``alias.startswith(f"{slug}_")``."""
    parts = split_tool_ref(ref)
    return parts is not None and isinstance(alias, str) and alias.startswith(f"{parts[0]}_")


def _derivational_ownership(record, ref, alias):
    """Rejected rule 2: ``alias == f"{slug}_{tool}"`` (the round-2 blocker)."""
    parts = split_tool_ref(ref)
    return parts is not None and alias == derived_alias(parts[0], parts[1])


def _declared_only_derivational_ownership(record, ref, alias):
    """Rejected rule 3: rule 2, narrowed to providers that currently declare."""
    from kiro_crew.connections import tool_aliases as ta

    parts = split_tool_ref(ref)
    if parts is None or alias != derived_alias(parts[0], parts[1]):
        return False
    return parts[1] in ta.declared_tool_aliases().get(parts[0], {})


def _alias_blind_ownership(record, ref, alias):
    """Rejected rule 4: record the ref but not the VALUE (drops invariant 3)."""
    parts = split_tool_ref(ref)
    if parts is None:
        return False
    return any(slug == parts[0] and tool == parts[1] for slug, tool, _ in record)


def _with_ownership_rule(rule):
    return patch("kiro_crew.connections.alias_record.is_recorded_emission", new=rule)


def test_reverting_to_prefix_ownership_deletes_a_hand_written_alias():
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@linear/list_issues": "linear_issues"}

    with _with_ownership_rule(_prefix_ownership):
        broken = _apply(config)
    assert "@linear/list_issues" not in broken["toolAliases"]

    # The shipped rule keeps it.
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@linear/list_issues": "linear_issues"}
    assert _apply(config)["toolAliases"]["@linear/list_issues"] == "linear_issues"


def test_reverting_to_derivational_ownership_deletes_a_hand_written_notion_search():
    """The round-2 BLOCKING finding, pinned. ``notion`` carries no declaration, so
    no emission for it can exist -- but its hand-written alias is byte-identical to
    the name re-derivation would produce, and re-derivation deletes it."""
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@notion/search": "notion_search"}

    with _with_ownership_rule(_derivational_ownership):
        broken = _apply(config)
    assert "@notion/search" not in broken["toolAliases"]

    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@notion/search": "notion_search"}
    assert _apply(config)["toolAliases"]["@notion/search"] == "notion_search"


def test_narrowing_ownership_to_declared_providers_strands_the_pair_forever():
    """The fix attempted in round 3 and reverted: withdrawing a declaration takes
    its slug out of the test, so the pair that declaration stranded can never be
    recognised again -- permanently unclearable, on every future rebuild."""
    from kiro_crew.connections import tool_aliases as ta

    stale = dict(_apply(_spec("linear", "vercel"))["toolAliases"])

    # The record clears it, because the record remembers the emission the
    # withdrawn declaration no longer describes.
    with patch.object(ta, "declared_tool_aliases", return_value={}):
        fixed = _apply({**_spec("linear", "vercel"), "toolAliases": dict(stale)})
    assert "toolAliases" not in fixed

    # Same state, narrowed shape rule: the pair survives every rebuild.
    assert dict(_apply(_spec("linear", "vercel"))["toolAliases"]) == stale
    with _with_ownership_rule(_declared_only_derivational_ownership):
        with patch.object(ta, "declared_tool_aliases", return_value={}):
            broken = _apply({**_spec("linear", "vercel"), "toolAliases": dict(stale)})
            still_broken = _apply(dict(broken))
    assert still_broken["toolAliases"] == stale


def test_dropping_the_alias_from_the_record_key_deletes_a_user_edit():
    """Invariant 3 is load-bearing: keying on ``(slug, tool)`` alone claims the ref
    whatever its current value, so a user's edit of a generated alias is deleted."""
    first = _apply(_spec("linear", "vercel"))
    edited = dict(first["toolAliases"])
    edited["@linear/list_projects"] = "my_linear_projects"

    with _with_ownership_rule(_alias_blind_ownership):
        broken = _apply({**_spec("linear"), "toolAliases": dict(edited)})
    assert "@linear/list_projects" not in broken.get("toolAliases", {})


def test_recording_before_the_spec_write_deletes_a_later_hand_written_name():
    """The ordering mutation, and the reason the record is written LAST. Recorded
    first, then a crash before the spec reaches disk: the record now claims a pair
    the spec never carried, so a user who hand-writes that exact name later has it
    deleted -- finding B, resurrected through a crash boundary."""
    from kiro_crew import agent

    reversed_order = _spec("linear", "vercel")
    with patch.object(agent, "_connection_tool_aliases_enabled", return_value=True):
        emitted = agent._apply_connection_tool_aliases(reversed_order)
    store_emitted_aliases(emitted)  # <- BEFORE the spec write; then "crash".

    # The user, on a spec that never got those aliases, writes one of the names
    # themselves. The stale claim eats it.
    hand_written = _spec("linear")
    hand_written["toolAliases"] = {"@linear/list_projects": "linear_list_projects"}
    assert "toolAliases" not in _apply(hand_written)


def test_skipping_the_empty_record_write_leaves_a_stale_claim():
    """``store_emitted_aliases`` must write an EMPTY set rather than skip it. Here
    the empty write is skipped, so the previous pass's claim survives and eats a
    name the user is now entitled to write."""
    _apply(_spec("linear", "vercel"))
    stale_claim = load_emitted_aliases()
    assert stale_claim

    _apply(_spec("linear"), persist=False)  # <- the skipped empty write
    assert load_emitted_aliases() == stale_claim

    config = _spec("linear")
    config["toolAliases"] = {"@linear/list_projects": "linear_list_projects"}
    assert "toolAliases" not in _apply(config)


# destination safety


def test_a_generated_alias_colliding_with_a_user_alias_target_is_skipped():
    config = _spec("linear", "vercel")
    config["toolAliases"] = {"@custom/thing": "vercel_list_projects"}
    after = _apply(config)
    assert after["toolAliases"]["@custom/thing"] == "vercel_list_projects"
    assert "@vercel/list_projects" not in after["toolAliases"]
    assert after["toolAliases"]["@linear/list_projects"] == "linear_list_projects"


def test_a_generated_alias_colliding_with_a_custom_servers_visible_tool_is_skipped():
    """V3: a custom mount's per-tool ref names a real tool, and a name it occupies
    is occupied whoever owns the server."""
    spec = _spec(
        "linear",
        "vercel",
        tools=["@linear", "@vercel", "@mycustom/vercel_list_projects"],
    )
    after = _apply(spec)
    assert "@vercel/list_projects" not in after["toolAliases"]
    assert after["toolAliases"]["@linear/list_projects"] == "linear_list_projects"


def test_a_whole_server_custom_mount_cannot_block_a_destination():
    """The OUT OF SCOPE row, asserted as a boundary rather than left implicit: a
    whole custom mount publishes no static names, so it degrades to shadowing."""
    spec = _spec("linear", "vercel", tools=["@linear", "@vercel", "@mycustom"])
    after = _apply(spec)
    assert after["toolAliases"]["@vercel/list_projects"] == "vercel_list_projects"


def test_a_custom_per_tool_ref_beside_a_whole_server_ref_still_reserves():
    """Exposure precedence must not leak into reservation: the custom server is
    mounted whole AND names one tool explicitly, and that name is occupied."""
    spec = _spec(
        "linear",
        "vercel",
        tools=["@linear", "@vercel", "@mycustom", "@mycustom/vercel_list_projects"],
    )
    after = _apply(spec)

    assert "@vercel/list_projects" not in after["toolAliases"]
    assert after["toolAliases"]["@linear/list_projects"] == "linear_list_projects"


def test_a_generated_alias_colliding_with_a_natural_tool_name_is_skipped():
    """A destination equal to a real tool name on an exposed provider would
    recreate the shadowing. Reachable because a natural name may itself carry the
    slug prefix that destinations use."""
    from kiro_crew.connections import tool_aliases as ta

    declarations = {
        "linear": {"list_projects": "linear_teams", "linear_teams": "linear_teams_alt"},
        "vercel": {"list_projects": "vercel_list_projects"},
    }
    with patch.object(ta, "declared_tool_aliases", return_value=declarations):
        after = _apply(_spec("linear", "vercel"))

    assert "@linear/list_projects" not in after.get("toolAliases", {})
    assert after["toolAliases"]["@vercel/list_projects"] == "vercel_list_projects"


def test_a_generated_alias_colliding_with_a_builtin_is_skipped():
    from kiro_crew.connections import tool_aliases as ta

    declarations = {
        "linear": {"list_projects": "linear_fs_read"},
        "vercel": {"list_projects": "vercel_list_projects"},
    }
    spec = _spec("linear", "vercel", tools=["linear_fs_read", "@linear", "@vercel"])
    with patch.object(ta, "declared_tool_aliases", return_value=declarations):
        after = _apply(spec)

    assert "@linear/list_projects" not in after.get("toolAliases", {})
    assert after["toolAliases"]["@vercel/list_projects"] == "vercel_list_projects"


# endpoint-upgrade continuity (the adjudicated row)


def test_a_registry_endpoint_change_degrades_to_shadowing_not_worse():
    """A retired ``mcp_url`` makes an existing install's entry stop matching, so
    its tools keep their natural names -- the pre-feature behaviour, and the
    fail-safe direction. The old generated refs go with it, so no dead ref is
    left pointing at a rename that is no longer applied."""
    aliased = _apply(_spec("linear", "vercel"))
    assert aliased["toolAliases"]

    moved = {**_spec("linear", "vercel"), "toolAliases": dict(aliased["toolAliases"])}
    moved["mcpServers"]["linear"] = {"url": "https://mcp.linear.app/mcp/v2"}
    after = _apply(moved)

    assert "toolAliases" not in after


def test_reconnecting_after_an_endpoint_change_restores_the_aliases():
    """Self-heal: Connect rewrites the entry from the registry, so the URL matches
    again and the aliases come back without any historical-URL bookkeeping."""
    moved = _spec("linear", "vercel")
    moved["mcpServers"]["linear"] = {"url": "https://mcp.linear.app/mcp/v2"}
    stripped = _apply(moved)
    assert "toolAliases" not in stripped

    reconnected = _apply(_spec("linear", "vercel"))
    assert reconnected["toolAliases"]["@linear/list_projects"] == "linear_list_projects"


# self-heal + failure containment


def test_a_non_dict_tool_aliases_value_is_replaced():
    config = _spec("linear", "vercel")
    config["toolAliases"] = ["not", "a", "map"]
    assert _apply(config)["toolAliases"]["@linear/list_projects"] == "linear_list_projects"


def test_a_non_string_alias_value_is_dropped():
    config = _spec("linear")
    config["toolAliases"] = {"@custom/thing": 42}
    assert "toolAliases" not in _apply(config)


def test_a_broken_registry_does_not_fail_the_rebuild():
    from kiro_crew import agent
    from kiro_crew.connections import tool_aliases as ta

    config = _spec("linear", "vercel")
    with patch.object(agent, "_connection_tool_aliases_enabled", return_value=True), patch.object(
        ta, "exposed_declared_tools", side_effect=RegistryValidationError("boom")
    ):
        agent._apply_connection_tool_aliases(config)
    assert "toolAliases" not in config


def test_a_broken_registry_does_not_clear_existing_aliases():
    """Failure must not be indistinguishable from 'no collisions', which clears."""
    from kiro_crew import agent
    from kiro_crew.connections import tool_aliases as ta

    config = _spec("linear")
    config["toolAliases"] = {"@custom/thing": "mine"}
    with patch.object(agent, "_connection_tool_aliases_enabled", return_value=True), patch.object(
        ta, "exposed_declared_tools", side_effect=OSError("no registry")
    ):
        agent._apply_connection_tool_aliases(config)
    assert config["toolAliases"] == {"@custom/thing": "mine"}


# ── the gate ──


@pytest.mark.parametrize(
    "raw,expected",
    [
        ({}, False),
        ({"connections": {}}, False),
        ({"connections": {"tool_aliases": False}}, False),
        ({"connections": {"tool_aliases": "yes"}}, False),
        ({"connections": {"tool_aliases": 1}}, False),
        ({"connections": True}, False),
        ({"connections": {"tool_aliases": True}}, True),
    ],
)
def test_the_gate_is_off_unless_explicitly_true(raw, expected):
    from kiro_crew import agent

    with patch.object(agent, "_load_json", return_value=raw):
        assert agent._connection_tool_aliases_enabled() is expected


# ── the boot invariant ──


def test_importing_agent_does_not_eagerly_load_the_registry():
    """The registry validates at MODULE level, so an eager import would make a
    malformed registry.json break `import kiro_crew.agent` -- the module that
    installs and repairs the agent spec -- before any guard runs.

    Checked in a SUBPROCESS against real sys.modules, not by reading agent.py's
    import block: the module could be pulled in transitively by anything agent.py
    imports, which source inspection of one file cannot see."""
    import subprocess
    import sys

    probe = (
        "import sys, kiro_crew.agent; "
        "assert 'kiro_crew.connections.registry' not in sys.modules, "
        "sorted(m for m in sys.modules if m.startswith('kiro_crew.connections'))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
