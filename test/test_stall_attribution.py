"""In-flight cron markers and loop-stall attribution.

The dumps come from ``stall_dump_helpers`` (faulthandler's own format behind
the store's real header). Every PID used is one that cannot be alive: the tests use a
``pid_exists`` stand-in wired through ``RunningMarker.owner_alive`` so no real
process table is consulted.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from stall_dump_helpers import CHAT_STACK, CRON_STACK, IDLE_WORKER, SLACK_STACK, write_dump

from kiro_crew import cron_inflight
from kiro_crew.dashboard import crash_dump_store
from kiro_crew.stall_attribution import (
    attribute_dump,
    attribute_latest_stall,
    classify_surface,
    describe,
    parse_frames,
)


@pytest.fixture
def dead_pids(monkeypatch: pytest.MonkeyPatch) -> set[int]:
    """Every PID is dead except this process (and those a test adds)."""
    alive: set[int] = set()
    monkeypatch.setattr(cron_inflight, "pid_exists", lambda pid: pid in alive)
    return alive


# ─────────────────────────────────────────────────────────────────────────────
# cron_inflight
# ─────────────────────────────────────────────────────────────────────────────


class TestMarkers:
    def test_write_read_clear_round_trip(self, tmp_path: Path) -> None:
        cron_inflight.write_marker(tmp_path, "caeb441a", "twb-refresh", 1000.0)
        (marker,) = cron_inflight.read_markers(tmp_path)
        assert (marker.job_id, marker.name, marker.started_at, marker.pid) == (
            "caeb441a",
            "twb-refresh",
            1000.0,
            os.getpid(),
        )
        assert marker.owner_alive() is True
        cron_inflight.clear_marker(tmp_path, "caeb441a")
        assert cron_inflight.read_markers(tmp_path) == []
        # clearing twice is not an error
        cron_inflight.clear_marker(tmp_path, "caeb441a")

    @pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b", "../x"])
    def test_marker_path_refuses_ids_that_leave_the_directory(
        self, tmp_path: Path, bad: str
    ) -> None:
        with pytest.raises(ValueError):
            cron_inflight.marker_path(tmp_path, bad)

    def test_write_is_best_effort(self, tmp_path: Path) -> None:
        # A bad id raises inside; the writer swallows it -- a marker must never
        # fail a run.
        cron_inflight.write_marker(tmp_path, "../escape", "x", 1.0)
        assert not (tmp_path.parent / "escape.json").exists()

    def test_unparseable_and_tmp_files_are_skipped(self, tmp_path: Path) -> None:
        d = cron_inflight.running_dir(tmp_path)
        d.mkdir()
        (d / "junk.json").write_text("not json", encoding="utf-8")
        (d / "half.json.tmp").write_text("{}", encoding="utf-8")
        (d / "missing.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
        (d / "big.json").write_text("{" + " " * 5000 + "}", encoding="utf-8")
        assert cron_inflight.read_markers(tmp_path) == []

    def test_abandoned_is_dead_owner_only(self, tmp_path: Path, dead_pids: set[int]) -> None:
        cron_inflight.write_marker(tmp_path, "live", "l", 1.0)  # this process
        d = cron_inflight.running_dir(tmp_path)
        (d / "dead.json").write_text(
            json.dumps({"job_id": "dead", "name": "d", "started_at": 2.0, "pid": 4_000_001}),
            encoding="utf-8",
        )
        (d / "other.json").write_text(
            json.dumps({"job_id": "other", "name": "o", "started_at": 3.0, "pid": 4_000_002}),
            encoding="utf-8",
        )
        dead_pids.add(4_000_002)  # a live sibling gateway
        assert [m.job_id for m in cron_inflight.abandoned_markers(tmp_path)] == ["dead"]
        assert cron_inflight.sweep_abandoned_markers(tmp_path) == 1
        assert sorted(m.job_id for m in cron_inflight.read_markers(tmp_path)) == ["live", "other"]


# ─────────────────────────────────────────────────────────────────────────────
# stall_attribution
# ─────────────────────────────────────────────────────────────────────────────


class TestSurface:
    def test_frames_parse(self) -> None:
        frames = parse_frames(CRON_STACK)
        assert frames[0].func == "is_sensitive_bash_command"
        assert frames[0].line == 7969
        assert frames[0].short == "security.py:7969 is_sensitive_bash_command"
        assert len(frames) == len(CRON_STACK)

    def test_cron_wins_over_the_slack_gateway_module_it_passes_through(self) -> None:
        # A cron turn's stack contains slack/gateway.py frames; the OUTERMOST
        # Kiro Crew frame is the cron run, and that is what names the surface.
        assert classify_surface(parse_frames(CRON_STACK)) == "cron"

    def test_dashboard_chat_and_slack(self) -> None:
        assert classify_surface(parse_frames(CHAT_STACK)) == "dashboard chat"
        assert classify_surface(parse_frames(SLACK_STACK)) == "slack"

    def test_unknown_when_no_crew_frame(self) -> None:
        assert classify_surface(parse_frames(IDLE_WORKER)) == "unknown"
        assert classify_surface([]) == "unknown"

    def test_windows_paths_classify_too(self) -> None:
        win = [r'  File "C:\Users\u\venv\Lib\site-packages\kiro_crew\cron.py", line 1 in _execute']
        assert classify_surface(parse_frames(win)) == "cron"


class TestAttribution:
    def _marker(self, base: Path, job_id: str, name: str, pid: int, started_at: float) -> None:
        d = cron_inflight.running_dir(base)
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{job_id}.json").write_text(
            json.dumps({"job_id": job_id, "name": name, "started_at": started_at, "pid": pid}),
            encoding="utf-8",
        )

    def test_single_matching_marker_names_the_job(
        self, tmp_path: Path, dead_pids: set[int]
    ) -> None:
        dumps = tmp_path / "dumps"
        now = time.time()
        dump = write_dump(dumps, 4_000_010, CRON_STACK, mtime=now - 60)
        self._marker(tmp_path, "caeb441a", "twb-refresh", 4_000_010, now - 90)
        a = attribute_dump(dump, tmp_path)
        assert a.surface == "cron"
        assert a.owner_pid == 4_000_010
        assert a.gate is not None and a.gate.func == "is_sensitive_bash_command"
        assert a.job is not None and a.job.job_id == "caeb441a"
        lines = describe(a)
        assert (
            lines[0]
            == "stuck in the tool permission gate (security.py:7969 is_sensitive_bash_command)"
        )
        assert "was executing cron job 'twb-refresh' (caeb441a)" in lines[1]
        assert lines[2] == "recommended: kirocrew cron pause caeb441a"

    def test_two_markers_name_candidates_not_a_job(
        self, tmp_path: Path, dead_pids: set[int]
    ) -> None:
        now = time.time()
        dump = write_dump(tmp_path / "dumps", 4_000_011, CRON_STACK, mtime=now)
        self._marker(tmp_path, "a1", "hourly", 4_000_011, now - 10)
        self._marker(tmp_path, "b2", "daily", 4_000_011, now - 5)
        a = attribute_dump(dump, tmp_path)
        assert a.job is None and len(a.candidates) == 2
        text = "\n".join(describe(a))
        assert "2 jobs were in flight" in text
        assert "cannot name one job" in text
        assert "recommended:" not in text

    def test_pid_mismatch_and_later_marker_are_unrelated(
        self, tmp_path: Path, dead_pids: set[int]
    ) -> None:
        now = time.time()
        dump = write_dump(tmp_path / "dumps", 4_000_012, CRON_STACK, mtime=now - 100)
        self._marker(tmp_path, "older", "from-another-crash", 4_000_099, now - 500)
        self._marker(tmp_path, "later", "next-session", 4_000_012, now - 50)  # after the dump
        a = attribute_dump(dump, tmp_path)
        assert a.job is None and a.candidates == []
        assert sorted(m.job_id for m in a.unrelated_abandoned) == ["later", "older"]
        text = "\n".join(describe(a))
        assert "no in-flight marker matches the dump's PID" in text
        assert "not by this dump" in text

    def test_live_owner_marker_is_not_evidence(self, tmp_path: Path, dead_pids: set[int]) -> None:
        now = time.time()
        dump = write_dump(tmp_path / "dumps", 4_000_013, CRON_STACK, mtime=now)
        self._marker(tmp_path, "running", "still-running", 4_000_013, now - 10)
        dead_pids.add(4_000_013)
        a = attribute_dump(dump, tmp_path)
        assert a.candidates == [] and a.unrelated_abandoned == []

    def test_non_cron_surface_is_named_and_implicates_no_job(
        self, tmp_path: Path, dead_pids: set[int]
    ) -> None:
        now = time.time()
        dump = write_dump(tmp_path / "dumps", 4_000_014, CHAT_STACK, mtime=now)
        self._marker(tmp_path, "x", "bystander", 4_000_014, now - 10)
        a = attribute_dump(dump, tmp_path)
        assert a.surface == "dashboard chat"
        assert a.is_cron is False
        # The marker still matches by PID (the job WAS in flight) but the stack
        # says the loop was serving chat, so no job is named.
        assert len(a.candidates) == 1
        text = "\n".join(describe(a))
        assert "serving a dashboard chat turn; no cron job is implicated" in text
        assert "recommended:" not in text

    def test_unknown_surface_says_so(self, tmp_path: Path, dead_pids: set[int]) -> None:
        dump = write_dump(tmp_path / "dumps", 4_000_015, IDLE_WORKER, mtime=time.time())
        a = attribute_dump(dump, tmp_path)
        text = "\n".join(describe(a))
        assert "names no known surface; cannot attribute" in text

    def test_latest_picks_the_newest_dump_with_stacks(
        self, tmp_path: Path, dead_pids: set[int]
    ) -> None:
        dumps = tmp_path / "dumps"
        now = time.time()
        write_dump(dumps, 4_000_016, CHAT_STACK, mtime=now - 200)
        newest = write_dump(dumps, 4_000_017, CRON_STACK, mtime=now - 100)
        crash_dump_store.open_dump_file(dumps)  # header-only, this session
        a = attribute_latest_stall(tmp_path, dumps)
        assert a is not None and a.dump == newest and a.surface == "cron"

    def test_no_dump_no_attribution(self, tmp_path: Path) -> None:
        assert attribute_latest_stall(tmp_path, tmp_path / "empty") is None
