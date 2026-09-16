"""Tests for the Zoom meetings actions (W11-C).

Covers the four operations' descriptors folding into the W01 control plane,
request construction (cursor list, cursor-less get/create/update, the UUID
double-encoding route, the recurrence occurrence_id targeting rule, and the
no-local-time-inference body), response mapping (next_page_token -> opaque
next_cursor; cursor-less single result), the error path (3001 stays ambiguous;
a leaked token/signed URL never survives), the two credential modes declared
per operation, the host-readback verification gate, and the per-operation
license/role scope declarations.
"""

import pytest

from kiro_crew.connections.control_plane import (
    CREDENTIAL_MODES,
    EFFECTS,
    OPERATION_KINDS,
    SERVICE_IDS,
)
from kiro_crew.connections.vendors.zoom import (
    ZOOM_CREDENTIAL_MODES,
    ZOOM_SERVER_TO_SERVER,
    ZOOM_USER_OAUTH,
    contains_zoom_credential,
)
from kiro_crew.connections.vendors.zoom.identity import (
    HOST_REACHABILITY_UNKNOWN,
    OccurrenceTarget,
    encode_uuid_path_segment,
)
from kiro_crew.connections.vendors.zoom.meetings import (
    OP_CREATE,
    OP_GET,
    OP_LIST,
    OP_UPDATE,
    auth_mode_host_reachability,
    build_create_request,
    build_get_request,
    build_list_request,
    build_update_request,
    descriptor,
    descriptors,
    encode_meeting_uuid_segment,
    license_scope,
    map_error,
    map_list_result,
    map_single_result,
    update_request_target,
    verify_host_readback,
)


class TestDescriptors:
    def test_four_operations_declared(self):
        got = {d["operation_id"] for d in descriptors()}
        assert got == {OP_LIST, OP_GET, OP_CREATE, OP_UPDATE}

    def test_all_service_id_zoom_and_in_shared_set(self):
        for d in descriptors():
            assert d["service_id"] == "zoom"
            assert d["service_id"] in SERVICE_IDS

    def test_operation_kinds_are_shared_closed_set(self):
        assert descriptor(OP_LIST)["operation_kind"] == "list"
        assert descriptor(OP_GET)["operation_kind"] == "single_fetch"
        assert descriptor(OP_CREATE)["operation_kind"] == "mutation"
        assert descriptor(OP_UPDATE)["operation_kind"] == "mutation"
        for d in descriptors():
            assert d["operation_kind"] in OPERATION_KINDS

    def test_effects_read_for_reads_write_for_mutations(self):
        assert descriptor(OP_LIST)["effect"] == "read"
        assert descriptor(OP_GET)["effect"] == "read"
        assert descriptor(OP_CREATE)["effect"] == "write"
        assert descriptor(OP_UPDATE)["effect"] == "write"
        for d in descriptors():
            assert d["effect"] in EFFECTS

    def test_credential_modes_are_two_zoom_modes_no_pat(self):
        for d in descriptors():
            assert d["credential_modes"] == ZOOM_CREDENTIAL_MODES
            assert set(d["credential_modes"]) <= set(CREDENTIAL_MODES)
            assert "fine_grained_pat" not in d["credential_modes"]
            assert ZOOM_USER_OAUTH in d["credential_modes"]
            assert ZOOM_SERVER_TO_SERVER in d["credential_modes"]

    def test_unknown_operation_refused(self):
        with pytest.raises(KeyError):
            descriptor("zoom.meetings.delete")


class TestListRequest:
    def test_list_is_cursor_paged_request(self):
        req = build_list_request("me", page_size=30)
        assert req.operation_id == OP_LIST
        assert req.method == "GET"
        assert req.path == "/users/me/meetings"
        assert req.query["page_size"] == 30
        assert "next_page_token" not in req.query

    def test_list_carries_cursor_token(self):
        req = build_list_request("me", page_size=30, next_page_token="tok123")
        assert req.query["next_page_token"] == "tok123"

    def test_list_specific_user_id_in_path(self):
        req = build_list_request("abc@ex.com", page_size=10)
        assert req.path == "/users/abc@ex.com/meetings"

    def test_list_refuses_nonpositive_page_size(self):
        # delegated to the paging unit's cursor discipline.
        with pytest.raises(ValueError):
            build_list_request("me", page_size=0)

    def test_list_requires_user_id(self):
        with pytest.raises(ValueError):
            build_list_request("", page_size=10)


class TestGetRequest:
    def test_get_is_cursorless_single_fetch(self):
        req = build_get_request("97763643886")
        assert req.operation_id == OP_GET
        assert req.method == "GET"
        assert req.path == "/meetings/97763643886"
        # cursor-less: no page token attached
        assert "next_page_token" not in req.query
        assert "page_size" not in req.query

    def test_get_optional_occurrence_id_query(self):
        req = build_get_request("97763643886", occurrence_id="1648194360000")
        assert req.query["occurrence_id"] == "1648194360000"

    def test_get_no_occurrence_id_reads_the_object(self):
        req = build_get_request("97763643886", occurrence_id=None)
        assert "occurrence_id" not in req.query

    def test_get_requires_meeting_id(self):
        with pytest.raises(ValueError):
            build_get_request("")


class TestCreateRequest:
    def test_create_posts_to_user_meetings(self):
        req = build_create_request("me", topic="Sync", duration=30)
        assert req.operation_id == OP_CREATE
        assert req.method == "POST"
        assert req.path == "/users/me/meetings"
        assert req.body["topic"] == "Sync"
        assert req.body["duration"] == 30

    def test_create_binds_start_time_to_timezone(self):
        req = build_create_request(
            "me",
            topic="Planning",
            start_time="2022-03-25T07:46:00Z",
            timezone="America/Los_Angeles",
        )
        assert req.body["start_time"] == "2022-03-25T07:46:00Z"
        assert req.body["timezone"] == "America/Los_Angeles"

    def test_create_missing_timezone_not_inferred(self):
        # negative: a start_time with no series timezone is carried WITHOUT a
        # fabricated zone -- no local-time inference.
        req = build_create_request("me", start_time="2022-03-25T07:46:00Z")
        assert req.body["start_time"] == "2022-03-25T07:46:00Z"
        assert "timezone" not in req.body

    def test_create_requires_user_id(self):
        with pytest.raises(ValueError):
            build_create_request("")

    def test_create_extra_never_overrides_time_fields(self):
        req = build_create_request(
            "me",
            start_time="2022-03-25T07:46:00Z",
            timezone="UTC",
            extra={"start_time": "1999-01-01T00:00:00Z", "agenda": "notes"},
        )
        # the identity/time fields win; extra only fills what is not set.
        assert req.body["start_time"] == "2022-03-25T07:46:00Z"
        assert req.body["timezone"] == "UTC"
        assert req.body["agenda"] == "notes"


class TestUpdateRequestRecurrence:
    def test_update_with_occurrence_id_targets_single_occurrence(self):
        req = build_update_request("97763643886", occurrence_id="1648194360000", topic="x")
        assert req.method == "PATCH"
        assert req.path == "/meetings/97763643886"
        assert req.query["occurrence_id"] == "1648194360000"
        assert update_request_target("1648194360000") is OccurrenceTarget.SINGLE_OCCURRENCE

    def test_update_missing_occurrence_id_targets_parent_series(self):
        # negative fault test 2: a missing occurrence_id hits the parent series,
        # NOT a silently-promoted single-occurrence edit.
        req = build_update_request("97763643886", topic="x")
        assert "occurrence_id" not in req.query
        assert update_request_target(None) is OccurrenceTarget.PARENT_SERIES

    def test_update_empty_occurrence_id_targets_parent_series(self):
        req = build_update_request("97763643886", occurrence_id="", topic="x")
        assert "occurrence_id" not in req.query
        assert update_request_target("") is OccurrenceTarget.PARENT_SERIES

    def test_update_binds_start_time_to_timezone_no_inference(self):
        req = build_update_request(
            "97763643886",
            start_time="2022-04-01T09:00:00Z",
            timezone="Europe/London",
        )
        assert req.body["start_time"] == "2022-04-01T09:00:00Z"
        assert req.body["timezone"] == "Europe/London"

    def test_update_missing_timezone_not_inferred(self):
        req = build_update_request("97763643886", start_time="2022-04-01T09:00:00Z")
        assert "timezone" not in req.body

    def test_update_requires_meeting_id(self):
        with pytest.raises(ValueError):
            build_update_request("")


class TestUuidRouting:
    def test_uuid_path_double_encoding_matches_identity_unit(self):
        raw = "/abc=="
        assert encode_meeting_uuid_segment(raw) == encode_uuid_path_segment(raw)
        assert "%252F" in encode_meeting_uuid_segment(raw)

    def test_ordinary_uuid_single_encoded(self):
        raw = "aDYlohsHRtCd4ii1uC2+hA=="
        assert encode_meeting_uuid_segment(raw) == encode_uuid_path_segment(raw)
        assert "%25" not in encode_meeting_uuid_segment(raw)


class TestResultMapping:
    def test_list_result_present_token_becomes_cursor(self):
        res = map_list_result("nexttok")
        # a present cursor downgrades status to partial (a successor remains).
        assert res["status"] == "partial"
        assert res["next_cursor"] == "nexttok"
        # the neutral collection channel is carried (empty by default here).
        assert res["payload"] is not None

    def test_list_result_absent_token_terminal(self):
        assert map_list_result(None)["next_cursor"] is None
        assert map_list_result(None)["status"] == "ok"
        assert map_list_result("")["next_cursor"] is None

    def test_single_result_has_no_cursor(self):
        res = map_single_result()
        assert res["status"] == "ok"
        assert res["next_cursor"] is None
        assert res["payload"] is None

    def test_single_result_is_fresh_dict_each_call(self):
        a = map_single_result()
        a["next_cursor"] = "mutated"
        assert map_single_result()["next_cursor"] is None


class TestErrorMapping:
    def test_3001_stays_ambiguous(self):
        # negative fault test 1 (error side), routed through the meetings module.
        err = map_error(3001, "meeting not found")
        assert err["error_class"] == "ambiguous"
        assert err["error_class"] != "not_found"

    def test_http_status_fallback(self):
        assert map_error(None, "denied", http_status=403)["error_class"] == "forbidden"

    def test_leaked_bearer_scrubbed(self):
        # negative fault test 6, on the meetings error path.
        err = map_error(124, "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aBcDeF123456")
        assert "eyJhbGciOiJIUzI1NiJ9" not in err["detail"]
        assert contains_zoom_credential(err["detail"]) is False

    def test_leaked_signed_url_scrubbed(self):
        err = map_error(1001, "download https://zoom.us/rec/download/Qg75t7xZBtEbAkjdlgbfdng")
        assert contains_zoom_credential(err["detail"]) is False

    def test_leaked_token_field_scrubbed(self):
        err = map_error(300, '{"access_token": "abcDEF1234567890xyz"}')
        assert "abcDEF1234567890xyz" not in err["detail"]
        assert contains_zoom_credential(err["detail"]) is False


class TestHostReadback:
    def test_matching_host_is_verified(self):
        v = verify_host_readback("host_A", "host_A")
        assert v.verified is True
        assert v.reachability == "verified"
        assert v.target_host == "host_A"
        assert v.readback_host == "host_A"

    def test_mismatched_host_not_verified(self):
        # the silent wrong-host write this gate exists to catch.
        v = verify_host_readback("host_A", "host_B")
        assert v.verified is False
        assert v.reachability == "mismatch"

    def test_absent_readback_is_unknown_not_inferred(self):
        v = verify_host_readback("host_A", None)
        assert v.verified is False
        assert v.reachability == HOST_REACHABILITY_UNKNOWN

    def test_absent_target_is_unknown(self):
        v = verify_host_readback(None, "host_B")
        assert v.verified is False
        assert v.reachability == HOST_REACHABILITY_UNKNOWN


class TestAuthModeHostReachability:
    def test_s2s_account_credential_does_not_imply_reachable(self):
        # account-level S2S is NOT asserted reachable from its mode alone.
        assert (
            auth_mode_host_reachability(ZOOM_SERVER_TO_SERVER, verified=False)
            == HOST_REACHABILITY_UNKNOWN
        )

    def test_oauth_user_unverified_is_unknown_not_unreachable(self):
        assert (
            auth_mode_host_reachability(ZOOM_USER_OAUTH, verified=False)
            == HOST_REACHABILITY_UNKNOWN
        )

    def test_verified_pair_is_verified_for_both_modes(self):
        assert auth_mode_host_reachability(ZOOM_SERVER_TO_SERVER, verified=True) == "verified"
        assert auth_mode_host_reachability(ZOOM_USER_OAUTH, verified=True) == "verified"

    def test_unknown_mode_refused(self):
        with pytest.raises(ValueError):
            auth_mode_host_reachability("fine_grained_pat", verified=True)


class TestLicenseScope:
    def test_read_ops_need_meeting_read(self):
        assert license_scope(OP_LIST).oauth_scopes == ("meeting:read",)
        assert license_scope(OP_GET).oauth_scopes == ("meeting:read",)

    def test_write_ops_need_meeting_write(self):
        assert license_scope(OP_CREATE).oauth_scopes == ("meeting:write",)
        assert license_scope(OP_UPDATE).oauth_scopes == ("meeting:write",)

    def test_other_user_target_is_conditional_admin_scope(self):
        # scope is declared conditionally, not asserted unconditionally.
        assert license_scope(OP_CREATE).conditional["other_user_target"] == "meeting:write:admin"
        assert license_scope(OP_UPDATE).conditional["other_user_target"] == "meeting:write:admin"

    def test_basic_crud_has_no_min_plan_gate(self):
        assert license_scope(OP_LIST).min_plan is None
        assert license_scope(OP_CREATE).min_plan is None

    def test_unknown_operation_refused(self):
        with pytest.raises(KeyError):
            license_scope("zoom.meetings.delete")
