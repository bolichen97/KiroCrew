"""The cron loop-stall breaker and the in-flight markers behind it.

A gateway the loop-stall watchdog hard-exits runs no ``finally``: the run in
flight writes no ``last_run_ts``, so on the next boot the job is due again,
fires again and stalls again -- an hourly crash loop in the field. These tests
pin the two halves that end it: the run task leaves a marker on disk while it
executes and clears it on every ``finally`` path, and ``CronService.start()``
pauses the one job a cron-surface dump plus a single abandoned marker name,
BEFORE the timer is armed, once per dump.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest
from stall_dump_helpers import CHAT_STACK, CRON_STACK, write_dump

from kiro_crew import cron_inflight
from kiro_crew.cron import CronJob, CronService

pytestmark = pytest.mark.asyncio


@pytest.fixture
def dead_pids(monkeypatch: pytest.MonkeyPatch) -> set[int]:
    alive: set[int] = set()
    monkeypatch.setattr(cron_inflight, "pid_exists", lambda pid: pid in alive)
    return alive


def _abandoned_marker(base: Path, job_id: str, name: str, pid: int, started_at: float) -> None:
    d = cron_inflight.running_dir(base)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{job_id}.json").write_text(
        json.dumps({"job_id": job_id, "name": name, "started_at": started_at, "pid": pid}),
        encoding="utf-8",
    )


async def _started_service(base: Path, dumps: Path) -> CronService:
    svc = await CronService.create(base_dir=base)
    svc._dumps_dir = dumps
    await svc.start()
    return svc


class TestBreaker:
    async def test_pauses_the_attributed_job_before_the_timer_arms(
        self, tmp_path: Path, dead_pids: set[int]
    ) -> None:
        seed = CronService(base_dir=tmp_path)
        job = seed.add_job(
            name="twb-refresh", message="refresh", every_secs=3600, strict_schedule=True
        )
        now = time.time()
        # The run the watchdog killed never wrote its last_run_ts, so the store
        # still says the job last ran two periods ago: OVERDUE, and strict, so
        # the timer would dispatch it at zero delay on the first tick.
        job.last_run_ts = now - 7200
        seed._save()
        write_dump(tmp_path / "dumps", 4_100_001, CRON_STACK, mtime=now - 30)
        _abandoned_marker(tmp_path, job.id, job.name, 4_100_001, now - 60)

        fired: list[str] = []
        svc = await CronService.create(base_dir=tmp_path, on_job=lambda j: _record(fired, j))
        svc._dumps_dir = tmp_path / "dumps"
        await svc.start()
        try:
            # Let a timer tick happen: an unpaused overdue `every` job would fire.
            await asyncio.sleep(0.2)
            assert (
                fired == []
            ), "the overdue job fired: the breaker ran after the timer, or not at all"
            paused = svc.get_job(job.id)
            assert paused is not None
            assert paused.auto_paused is True and paused.enabled is False
            assert paused.last_status == "error"
            assert paused.last_error is not None
            assert "loop-stall watchdog" in paused.last_error
            assert f"kirocrew cron resume {job.id}" in paused.last_error
            # Persisted, so a reload sees the pause.
            raw = json.loads((tmp_path / "crons.json").read_text(encoding="utf-8"))
            (rec,) = [r for r in raw["jobs"] if r["id"] == job.id]
            assert rec["auto_paused"] is True
            # The marker was consumed and the dump claimed.
            assert cron_inflight.read_markers(tmp_path) == []
            claim = cron_inflight.running_dir(tmp_path) / CronService._BREAKER_CLAIM_FILE
            assert claim.read_text(encoding="utf-8").strip().startswith("loopstall-")
        finally:
            await svc.stop()

    async def test_second_boot_does_not_re_pause_a_resumed_job(
        self, tmp_path: Path, dead_pids: set[int]
    ) -> None:
        seed = CronService(base_dir=tmp_path)
        job = seed.add_job(name="hourly", message="m", every_secs=3600)
        now = time.time()
        write_dump(tmp_path / "dumps", 4_100_002, CRON_STACK, mtime=now - 30)
        _abandoned_marker(tmp_path, job.id, job.name, 4_100_002, now - 60)
        svc = await _started_service(tmp_path, tmp_path / "dumps")
        await svc.stop()
        assert svc.get_job(job.id).auto_paused is True  # type: ignore[union-attr]
        # Operator resumes; the dump is still on disk for a week.
        resumed = CronService(base_dir=tmp_path)
        assert resumed.enable_job(job.id, True) is True
        again = await _started_service(tmp_path, tmp_path / "dumps")
        try:
            j = again.get_job(job.id)
            assert j is not None and j.auto_paused is False and j.enabled is True
        finally:
            await again.stop()

    async def test_non_cron_dump_pauses_nothing(self, tmp_path: Path, dead_pids: set[int]) -> None:
        seed = CronService(base_dir=tmp_path)
        job = seed.add_job(name="bystander", message="m", every_secs=3600)
        now = time.time()
        write_dump(tmp_path / "dumps", 4_100_003, CHAT_STACK, mtime=now - 30)
        _abandoned_marker(tmp_path, job.id, job.name, 4_100_003, now - 60)
        svc = await _started_service(tmp_path, tmp_path / "dumps")
        try:
            j = svc.get_job(job.id)
            assert j is not None and j.auto_paused is False and j.enabled is True
            # Consumed anyway: the evidence has been read.
            assert cron_inflight.read_markers(tmp_path) == []
        finally:
            await svc.stop()

    async def test_two_candidates_pause_nothing(self, tmp_path: Path, dead_pids: set[int]) -> None:
        seed = CronService(base_dir=tmp_path)
        a = seed.add_job(name="a", message="m", every_secs=3600)
        b = seed.add_job(name="b", message="m", every_secs=3600)
        now = time.time()
        write_dump(tmp_path / "dumps", 4_100_004, CRON_STACK, mtime=now - 30)
        _abandoned_marker(tmp_path, a.id, a.name, 4_100_004, now - 60)
        _abandoned_marker(tmp_path, b.id, b.name, 4_100_004, now - 50)
        svc = await _started_service(tmp_path, tmp_path / "dumps")
        try:
            for jid in (a.id, b.id):
                j = svc.get_job(jid)
                assert j is not None and j.auto_paused is False
        finally:
            await svc.stop()

    async def test_no_dump_is_a_no_op(self, tmp_path: Path, dead_pids: set[int]) -> None:
        seed = CronService(base_dir=tmp_path)
        job = seed.add_job(name="fine", message="m", every_secs=3600)
        svc = await _started_service(tmp_path, tmp_path / "no-dumps")
        try:
            j = svc.get_job(job.id)
            assert j is not None and j.enabled is True
        finally:
            await svc.stop()

    async def test_breaker_audits_the_pause(
        self, tmp_path: Path, dead_pids: set[int], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from kiro_crew import sel as sel_mod

        seed = CronService(base_dir=tmp_path)
        job = seed.add_job(name="audited", message="m", every_secs=3600)
        now = time.time()
        write_dump(tmp_path / "dumps", 4_100_005, CRON_STACK, mtime=now - 30)
        _abandoned_marker(tmp_path, job.id, job.name, 4_100_005, now - 60)
        stub = MagicMock()
        monkeypatch.setattr(sel_mod, "sel", lambda: stub)
        svc = await _started_service(tmp_path, tmp_path / "dumps")
        await svc.stop()
        outcomes = [
            c.kwargs.get("outcome")
            for c in stub.log_tool_invocation.call_args_list
            if c.kwargs.get("tool_kind") == "cron_auto_pause"
        ]
        assert outcomes == ["auto_paused_loop_stall"]


async def _record(sink: list[str], job: CronJob) -> str | None:
    sink.append(job.id)
    return None


class TestRunMarker:
    async def test_marker_exists_during_the_run_and_is_gone_after(self, tmp_path: Path) -> None:
        seen: list[list[cron_inflight.RunningMarker]] = []

        async def on_job(job: CronJob) -> str | None:
            seen.append(cron_inflight.read_markers(tmp_path))
            return None

        svc = await CronService.create(base_dir=tmp_path, on_job=on_job)
        job = svc.add_job(name="probe", message="m", every_secs=3600, strict_schedule=True)
        svc._running = True
        await svc._run_job_isolated(job)
        assert len(seen) == 1
        (marker,) = seen[0]
        assert marker.job_id == job.id and marker.name == "probe" and marker.pid == os.getpid()
        assert cron_inflight.read_markers(tmp_path) == []

    async def test_marker_is_cleared_when_the_callback_raises(self, tmp_path: Path) -> None:
        async def on_job(job: CronJob) -> str | None:
            raise RuntimeError("boom")

        svc = await CronService.create(base_dir=tmp_path, on_job=on_job)
        job = svc.add_job(name="raiser", message="m", every_secs=3600, strict_schedule=True)
        svc._running = True
        await svc._run_job_isolated(job)
        assert cron_inflight.read_markers(tmp_path) == []
        assert svc.get_job(job.id).last_status == "error"  # type: ignore[union-attr]
