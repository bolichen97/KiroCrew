"""Exercise the real timer, durable cursor and ledger without model requests."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from kiro_crew import conductor_standby as standby
from kiro_crew import work_ledger
from kiro_crew.autonudge import AutoNudgeService

SLOT = "chat-standby"
pytestmark = pytest.mark.asyncio


@pytest.fixture
def rig(tmp_path, monkeypatch, event_loop):
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path / "home"))
    clock = SimpleNamespace(now=100000.0)
    monkeypatch.setattr(standby, "time", SimpleNamespace(time=lambda: clock.now))
    fire = AsyncMock(return_value=True)
    busy = set()
    service = AutoNudgeService(
        base_dir=tmp_path / "store",
        on_fire=fire,
        worker_running=lambda key: key in busy or key.startswith("worker"),
    )
    monkeypatch.setattr(service, "_arm_timer", Mock())
    monkeypatch.setattr(service, "_persist_soon", Mock())
    monkeypatch.setattr(
        service,
        "_monitor_tick_is_quiet",
        AsyncMock(side_effect=AssertionError("judge path")),
    )
    standby.grant("standby", SLOT)
    loop = event_loop.run_until_complete(
        service.add(
            SLOT,
            "Read the work ledger and verify completed work.",
            loop_id="standby",
            watch="work-ledger",
            standby=True,
            max_cycles=0,
            max_runtime_secs=0,
            idle_secs=60,
        )
    )
    rig = SimpleNamespace(svc=service, loop=loop, clock=clock, fire=fire, busy=busy)

    async def complete_delivery(loop):
        from kiro_crew.monitoring.models import MonitorActionDisposition

        if loop.standby and fire.return_value:
            hook = standby.completion_hook(rig.svc, loop)
            hook.mark_accepted()
            await hook.complete(MonitorActionDisposition.SUCCESS)
        return fire.return_value

    fire.side_effect = complete_delivery
    yield rig
    service.stop()
    event_loop.run_until_complete(asyncio.sleep(0))


def report(status="done", worker="worker-1"):
    work_ledger.ensure_conductor(SLOT, goal="test standby")
    created = work_ledger.apply_conductor_action(
        SLOT, "create", title=worker, acceptance={"kind": "human_approval"}
    )
    item_id = created["item"].item_id
    work_ledger.apply_conductor_action(SLOT, "bind", item_id=item_id, worker_session_key=worker)
    work_ledger.apply_worker_report(
        SLOT, item_id, status=status, summary="Please verify the result."
    )
    return item_id


async def tick(rig, seconds=60):
    rig.clock.now += seconds
    await rig.svc._timer(rig.loop, delay=0)


async def test_quiet_over_old_lifetime_and_quiet_floor_has_no_model_calls(rig):
    for _ in range(1001):
        await tick(rig, 3600)
    assert rig.loop.active
    assert rig.loop.cycle_count == 0
    rig.fire.assert_not_awaited()
    rig.svc._monitor_tick_is_quiet.assert_not_awaited()
    assert standby._read(rig.loop.id)["probes"] == 1001


@pytest.mark.parametrize("status", ["done", "blocked", "question"])
async def test_actionable_report_wakes_once_without_followup_or_realert(rig, status):
    report(status)
    await tick(rig)
    rig.fire.assert_not_awaited()
    await tick(rig, standby.COALESCE_SECS)
    rig.fire.assert_awaited_once()
    for _ in range(20):
        await tick(rig, 3600)
    rig.fire.assert_awaited_once()


async def test_events_coalesce_and_busy_events_survive(rig):
    rig.busy.add(SLOT)
    report(worker="worker-1")
    report(worker="worker-2")
    await tick(rig)
    rig.fire.assert_not_awaited()
    rig.busy.remove(SLOT)
    await tick(rig)
    report(worker="worker-3")
    await tick(rig, standby.COALESCE_SECS)
    rig.fire.assert_awaited_once()
    await tick(rig)
    rig.fire.assert_awaited_once()


async def test_due_check_keeps_pending_acceptance_live_without_early_turns(rig):
    report()
    await tick(rig)
    await tick(rig, standby.COALESCE_SECS)
    await standby.schedule_check(rig.svc, rig.loop, 600)
    await tick(rig, 599)
    assert rig.fire.await_count == 1
    await tick(rig, 1)
    assert rig.fire.await_count == 2
    await tick(rig, 3600)
    assert rig.fire.await_count == 2


async def test_restart_recovers_unhandled_events_and_dedup_cursor(rig, monkeypatch):
    report()
    await tick(rig)  # Persist the pending batch before shutdown.
    rig.svc.stop()
    restored = AutoNudgeService(
        base_dir=rig.svc._base_dir,
        on_fire=rig.fire,
        worker_running=lambda key: key.startswith("worker"),
    )
    monkeypatch.setattr(restored, "_arm_timer", Mock())
    monkeypatch.setattr(restored, "_persist_soon", Mock())
    restored._load()
    rig.svc = restored
    rig.loop = restored.get_by_id("standby")
    try:
        report(worker="worker-during-restart")
        await tick(rig, standby.COALESCE_SECS)
        rig.fire.assert_awaited_once()
        restored._load()
        rig.loop = restored.get_by_id("standby")
        await tick(rig, 86400)
        rig.fire.assert_awaited_once()
    finally:
        restored.stop()


async def test_stop_and_replayed_row_cannot_restore_authority(rig):
    report()
    await tick(rig)
    await rig.svc.update(rig.loop.id, active=False)
    await tick(rig)
    rig.fire.assert_not_awaited()
    rig.loop.active = True  # An agent-writable persisted row is not authorization.
    await tick(rig)
    assert not rig.loop.active
    rig.fire.assert_not_awaited()
    assert not standby._read(rig.loop.id)["enabled"]


async def test_interrupted_delivery_is_not_automatically_replayed(rig, monkeypatch):
    report()
    await tick(rig)

    async def fire(loop):
        rig.busy.add(SLOT)
        return True

    rig.fire.side_effect = fire
    await tick(rig, standby.COALESCE_SECS)
    assert standby._read(rig.loop.id)["claimed"]
    rig.svc._standby_deliveries.clear()  # Simulate process loss of delivery knowledge.
    rig.busy.clear()
    await tick(rig)
    assert not rig.loop.active
    assert rig.loop.stopped_reason == "interrupted_cycle"
    rig.fire.assert_awaited_once()


async def test_delivery_failures_back_off_even_when_events_pull_forward(rig):
    report()
    rig.fire.return_value = False
    await tick(rig)
    await tick(rig, standby.COALESCE_SECS)
    rig.fire.assert_awaited_once()
    for _ in range(10):
        await tick(rig, 1)
    rig.fire.assert_awaited_once()
    await tick(rig, 20)
    assert rig.fire.await_count == 2
    await tick(rig, 60)
    assert rig.fire.await_count == 3
    assert not rig.loop.active
    assert rig.loop.stopped_reason == "standby_delivery_failed"


async def test_completed_board_stays_quiet_then_accepts_new_work(rig):
    item = report()
    await tick(rig)
    await tick(rig, standby.COALESCE_SECS)
    work_ledger.apply_conductor_action(SLOT, "verdict", item_id=item, verdict="pass")
    for _ in range(12):
        await tick(rig, 3600)
    assert rig.loop.active
    rig.fire.assert_awaited_once()
    report(worker="worker-new-task")
    await tick(rig)
    await tick(rig, standby.COALESCE_SECS)
    assert rig.fire.await_count == 2


async def test_unsigned_standby_never_falls_through_to_a_model(rig):
    standby._path(rig.loop.id).unlink()
    await tick(rig)
    assert rig.loop.stopped_reason == "standby_authorization_unavailable"
    rig.fire.assert_not_awaited()


async def test_legacy_finite_loop_keeps_its_cap(rig):
    loop = await rig.svc.add("chat-finite", "finite", max_cycles=1, idle_secs=60)
    rig.svc._monitor_tick_is_quiet.side_effect = None
    rig.svc._monitor_tick_is_quiet.return_value = False
    await rig.svc._timer(loop, delay=0)
    await rig.svc._timer(loop, delay=0)
    assert loop.cycle_count == 1
    assert not loop.active
    assert loop.stopped_reason == "cycle_cap"


async def test_probe_errors_are_bounded_without_calling_a_judge(rig, monkeypatch):
    monkeypatch.setattr(standby.WorkLedgerProbe, "observe", Mock(side_effect=OSError("unreadable")))
    await tick(rig)
    for _ in range(10):
        await tick(rig, 1)
    assert standby._read(rig.loop.id)["failures"] == 1
    await tick(rig, 20)
    await tick(rig, 60)
    assert rig.loop.stopped_reason == "standby_probe_failed"
    assert not rig.loop.active
    rig.fire.assert_not_awaited()


async def test_rolling_execution_limit_defers_without_expiring_standby(rig):
    for _ in range(standby.MAX_WAKES_PER_WINDOW):
        await standby.schedule_check(rig.svc, rig.loop, 15)
        await tick(rig, 15)
    await standby.schedule_check(rig.svc, rig.loop, 15)
    await tick(rig, 15)
    assert rig.fire.await_count == standby.MAX_WAKES_PER_WINDOW
    assert rig.loop.active
    assert rig.loop.stopped_reason == "standby_rate_limit"
    await tick(rig, standby.WINDOW_SECS)
    assert rig.fire.await_count == standby.MAX_WAKES_PER_WINDOW + 1


async def test_live_delivery_finishes_before_another_event_is_dispatched(rig):
    from kiro_crew.monitoring.models import MonitorActionDisposition

    report()
    await tick(rig)
    hooks = []

    async def fire(loop):
        hook = standby.completion_hook(rig.svc, loop)
        hook.mark_accepted()
        hooks.append(hook)
        rig.busy.add(SLOT)
        return True

    rig.fire.side_effect = fire
    await tick(rig, standby.COALESCE_SECS)
    report(worker="worker-next")
    await tick(rig)
    rig.fire.assert_awaited_once()
    assert rig.loop.active
    await hooks[0].complete(MonitorActionDisposition.SUCCESS)
    rig.busy.clear()
    await tick(rig)
    await tick(rig, standby.COALESCE_SECS)
    assert rig.fire.await_count == 2


async def test_check_update_authority_and_bounds_agree_with_tool_schema(rig):
    from kiro_crew.autonudge_authz import authorize_and_update_nudge
    from kiro_crew.validation import (
        MONITOR_UPDATE_SCHEMA,
        ValidationError,
        validate_tool_args,
    )

    for bad in (-1, 2592001, "soon"):
        with pytest.raises(ValidationError):
            validate_tool_args({"check_after_secs": bad}, MONITOR_UPDATE_SCHEMA)
        row, error, status = await authorize_and_update_nudge(
            svc=rig.svc,
            loop_id=rig.loop.id,
            check_after_secs=bad,
            source="mcp-directive",
        )
        assert row is None and error and status == 400
    row, error, status = await authorize_and_update_nudge(
        svc=rig.svc, loop_id=rig.loop.id, check_after_secs=30, source="mcp-directive"
    )
    assert row is rig.loop and error is None and status == 200
    await rig.svc.update(rig.loop.id, active=False)
    row, error, status = await authorize_and_update_nudge(
        svc=rig.svc, loop_id=rig.loop.id, check_after_secs=30, source="mcp-directive"
    )
    assert row is None and error and status == 400
    rig.fire.assert_not_awaited()


async def test_owner_arm_is_required_and_model_update_cannot_resume(rig):
    from kiro_crew.autonudge_authz import (
        authorize_and_add_nudge,
        authorize_and_update_nudge,
    )

    state = SimpleNamespace(
        _slots={"chat-second": SimpleNamespace(mode="chat", memory_mode="persistent")}
    )
    row, error, status = await authorize_and_add_nudge(
        svc=rig.svc,
        state=state,
        slot_key="chat-second",
        message="ledger",
        idle_secs=60,
        max_cycles=5,
        source="mcp-directive",
        standby=True,
        watch="work-ledger",
    )
    assert row is None and error and status == 403
    row, error, status = await authorize_and_add_nudge(
        svc=rig.svc,
        state=state,
        slot_key="chat-second",
        message="ledger",
        idle_secs=60,
        max_cycles=5,
        source="dashboard",
        standby=True,
        watch="work-ledger",
    )
    assert error is None and status == 200
    assert row.standby and row.max_cycles == row.max_runtime_secs == 0
    await rig.svc.update(row.id, active=False)
    resumed, error, status = await authorize_and_update_nudge(
        svc=rig.svc, loop_id=row.id, active=True, source="mcp-directive"
    )
    assert resumed is None and error and status == 400
    assert not row.active
    resumed, error, status = await authorize_and_update_nudge(
        svc=rig.svc, loop_id=row.id, active=True, source="dashboard"
    )
    assert error is None and status == 200 and resumed.active


async def test_stop_waits_for_a_cancelled_delivery_claim_write(rig, monkeypatch):
    import threading

    report()
    await tick(rig)
    entered, release = threading.Event(), threading.Event()
    original = standby._write

    def slow_claim(record):
        if record["claimed"]:
            entered.set()
            assert release.wait(5)
        original(record)

    monkeypatch.setattr(standby, "_write", slow_claim)
    pending = asyncio.create_task(tick(rig, standby.COALESCE_SECS))
    stopping = None
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait, 3), 4)
        pending.cancel()
        stopping = asyncio.create_task(rig.svc.update(rig.loop.id, active=False))
        await asyncio.sleep(0)
        assert not stopping.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(pending, 3)
        await asyncio.wait_for(stopping, 3)
        assert not standby._read(rig.loop.id)["enabled"]
        rig.fire.assert_not_awaited()
    finally:
        release.set()
        await asyncio.gather(pending, *([stopping] if stopping else []), return_exceptions=True)


@pytest.mark.parametrize("stop_at", ["queue", "provider"])
async def test_stop_rejects_queued_or_preparing_dashboard_wake(rig, monkeypatch, stop_at):
    from test.test_autonudge_dashboard_fire import _orchestrator, _slot

    from kiro_crew.slack import gateway

    orch = _orchestrator()
    orch.autonudge_svc = rig.svc
    slot = _slot(SLOT)
    orch.dashboard_state.get_slot = Mock(return_value=slot)
    record = standby._read(rig.loop.id)
    record["claimed"] = True
    record["claim_id"] = f"standby:{rig.loop.config_generation}:{rig.loop.cycle_count + 1}"
    standby._write(record)
    entered = asyncio.Event()
    proceed = asyncio.Event()
    provider = Mock()
    tasks = []

    async def background(_slot, coro):
        if stop_at == "queue":
            entered.set()
            await proceed.wait()
        await coro

    async def run_chat(*args, **kwargs):
        if stop_at == "provider":
            entered.set()
            await proceed.wait()
        hook = kwargs["monitor_completion"]
        if await hook.authorize():
            hook.mark_accepted()
            provider()

    def spawn(_state, _slot, coro):
        task = asyncio.create_task(coro)
        tasks.append(task)
        return task

    monkeypatch.setattr(orch.dashboard_state, "run_background_turn", background)
    monkeypatch.setattr(gateway, "spawn_guarded_turn", spawn)
    monkeypatch.setattr("kiro_crew.dashboard.chat._run_chat", run_chat)
    fire = asyncio.create_task(orch._fire_dashboard_nudge(rig.loop))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        await rig.svc.update(rig.loop.id, active=False)
        proceed.set()
        assert await asyncio.wait_for(fire, 5) is False
        await asyncio.gather(*tasks)
        provider.assert_not_called()
        slot.append.assert_not_called()
    finally:
        proceed.set()
        fire.cancel()
        for task in tasks:
            task.cancel()
        await asyncio.gather(fire, *tasks, return_exceptions=True)


async def test_old_admission_hook_cannot_run_after_owner_resume(rig):
    record = standby._read(rig.loop.id)
    record["claimed"] = True
    record["claim_id"] = f"standby:{rig.loop.config_generation}:{rig.loop.cycle_count + 1}"
    standby._write(record)
    hook = standby.completion_hook(rig.svc, rig.loop)
    assert await hook.authorize()
    await rig.svc.update(rig.loop.id, active=False)
    await standby.resume(rig.svc, rig.loop)
    await rig.svc.update(rig.loop.id, active=True)
    record = standby._read(rig.loop.id)
    record["claimed"] = True
    record["claim_id"] = f"standby:{rig.loop.config_generation}:{rig.loop.cycle_count + 1}"
    standby._write(record)
    assert not await hook.authorize()


@pytest.mark.parametrize("running", [False, True])
async def test_dashboard_chat_stop_revokes_standby_before_late_event(rig, monkeypatch, running):
    from test.test_stop_handler_idempotent import _FakeSlot, _FakeState

    from kiro_crew.dashboard import chat_handlers

    slot = _FakeSlot()
    slot.key = SLOT
    slot.running = running
    state = _FakeState(slot)
    monkeypatch.setattr("kiro_crew.autonudge.get_instance", lambda: rig.svc)
    monkeypatch.setattr(chat_handlers, "_compaction_in_flight", lambda *_: False)
    monkeypatch.setattr(chat_handlers, "_unblock_pending_waits", Mock())
    result = await chat_handlers.stop_slot_turn(state, slot)
    assert result["ok"]
    assert not rig.loop.active
    assert not standby._read(rig.loop.id)["enabled"]
    report()
    await tick(rig)
    rig.fire.assert_not_awaited()
    if running:
        state.sessions.stop_turn.assert_awaited_once()


async def test_chat_stop_storage_failure_cancels_turn_and_reports_failure(rig, monkeypatch):
    from test.test_stop_handler_idempotent import _FakeSlot, _FakeState

    from aiohttp import web

    from kiro_crew.dashboard import chat_handlers

    slot = _FakeSlot()
    slot.key = SLOT
    state = _FakeState(slot)
    monkeypatch.setattr("kiro_crew.autonudge.get_instance", lambda: rig.svc)
    monkeypatch.setattr(standby, "revoke", Mock(side_effect=OSError("read-only store")))
    with pytest.raises(web.HTTPServiceUnavailable, match="Service Unavailable"):
        await chat_handlers.stop_slot_turn(state, slot)
    assert not rig.loop.active
    state.sessions.stop_turn.assert_awaited_once()


async def test_scheduled_checks_cross_old_execution_limit_and_restart(rig, monkeypatch):
    for _ in range(50):
        await standby.schedule_check(rig.svc, rig.loop, 3600)
        await tick(rig, 3600)
    assert rig.loop.active
    assert rig.loop.cycle_count == 50
    rig.svc.stop()
    restored = AutoNudgeService(base_dir=rig.svc._base_dir, on_fire=rig.fire)
    monkeypatch.setattr(restored, "_arm_timer", Mock())
    restored._load()
    loop = restored.get_by_id(rig.loop.id)
    assert loop is not None and loop.active and loop.cycle_count == 50
    await standby.schedule_check(restored, loop, 3600)
    rig.clock.now += 3600
    await restored._timer(loop, delay=0)
    assert loop.cycle_count == 51 and loop.active
    restored.stop()


async def test_accepted_model_failure_retries_with_backoff_then_pauses(rig):
    from kiro_crew.monitoring.models import MonitorActionDisposition

    async def fail(loop):
        hook = standby.completion_hook(rig.svc, loop)
        assert await hook.authorize()
        hook.mark_accepted()
        await hook.complete(MonitorActionDisposition.FAILURE)
        await hook.complete(MonitorActionDisposition.FAILURE)  # Duplicate callback.
        return True

    rig.fire.side_effect = fail
    report()
    await tick(rig)
    await tick(rig, standby.COALESCE_SECS)
    assert rig.fire.await_count == 1
    assert standby._read(rig.loop.id)["execution_failures"] == 1
    await tick(rig, 29)
    assert rig.fire.await_count == 1
    await tick(rig, 1)
    assert rig.fire.await_count == 2
    await tick(rig, 59)
    assert rig.fire.await_count == 2
    await tick(rig, 1)
    assert rig.fire.await_count == 3
    assert not rig.loop.active
    assert rig.loop.stopped_reason == "standby_execution_failed"
    assert not standby._read(rig.loop.id)["enabled"]
    assert standby._read(rig.loop.id)["wakes"] == 3
    await tick(rig, 86400)
    assert rig.fire.await_count == 3


async def test_successful_retry_returns_to_quiet(rig):
    from kiro_crew.monitoring.models import MonitorActionDisposition

    async def complete(loop):
        hook = standby.completion_hook(rig.svc, loop)
        hook.mark_accepted()
        outcome = (
            MonitorActionDisposition.FAILURE
            if rig.fire.await_count == 1
            else MonitorActionDisposition.SUCCESS
        )
        await hook.complete(outcome)
        return True

    rig.fire.side_effect = complete
    report()
    await tick(rig)
    await tick(rig, standby.COALESCE_SECS)
    await tick(rig, 30)
    assert rig.fire.await_count == 2
    await tick(rig, 86400)
    assert rig.fire.await_count == 2
    assert rig.loop.active
    assert standby._read(rig.loop.id)["execution_failures"] == 0


async def test_erasing_standby_bit_cannot_bypass_grant_or_use_legacy_judge(rig):
    report()
    rig.loop.standby = False
    await tick(rig)
    rig.fire.assert_not_awaited()
    rig.svc._monitor_tick_is_quiet.assert_not_awaited()
    assert not rig.loop.active


async def test_stop_revokes_grant_even_if_mode_bit_was_erased(rig, monkeypatch):
    monkeypatch.setattr("kiro_crew.autonudge.get_instance", lambda: rig.svc)
    rig.loop.standby = False
    await standby.stop_for_slot(SLOT)
    assert not standby._read(rig.loop.id)["enabled"]
    rig.loop.standby = True
    rig.loop.active = True
    await tick(rig)
    assert not rig.loop.active
    rig.fire.assert_not_awaited()


async def test_standby_cannot_be_replaced_with_uncapped_prompt_loop(rig):
    from kiro_crew.autonudge_service.model import MonitorUpdateConflict

    with pytest.raises(MonitorUpdateConflict, match="owner must remove"):
        await rig.svc.add(SLOT, "keep running", max_cycles=0)
    assert rig.svc.get_by_slot(SLOT) is rig.loop
    assert standby._read(rig.loop.id)["enabled"]
    assert not rig.loop.monitor.token_usage_known


async def test_agent_inspection_and_owner_read_retain_standby_mode(rig):
    from kiro_crew.dashboard.handlers.autonudge import (
        _autonudge_loop_reading,
        _serialize,
    )

    assert _autonudge_loop_reading(rig.loop)["standby"] is True
    assert _serialize(rig.loop)["standby"] is True
    finite = await rig.svc.add("chat-finite", "finite", max_cycles=2)
    assert "standby" not in _autonudge_loop_reading(finite)


@pytest.mark.parametrize("outcome", ["success", "failure", None])
@pytest.mark.parametrize("finish_immediately", [False, True])
async def test_dashboard_wrapped_completion_or_missing_evidence(
    rig, monkeypatch, outcome, finish_immediately
):
    from test.test_autonudge_dashboard_fire import _orchestrator, _slot

    from kiro_crew.monitoring.models import MonitorActionDisposition
    from kiro_crew.slack import gateway

    orch = _orchestrator()
    orch.autonudge_svc = rig.svc
    slot = _slot(SLOT)
    orch.dashboard_state.get_slot = Mock(return_value=slot)
    release = asyncio.Event()
    tasks = []

    async def run_chat(*args, **kwargs):
        hook = kwargs["monitor_completion"]
        assert await hook.authorize()
        hook.mark_accepted()
        rig.busy.add(SLOT)
        try:
            if not finish_immediately:
                await release.wait()
            if outcome is not None:
                disposition = MonitorActionDisposition(outcome)
                await hook.complete(disposition)
                await hook.complete(disposition)
        finally:
            rig.busy.discard(SLOT)

    def spawn(_state, _slot, coro):
        task = asyncio.create_task(coro)
        tasks.append(task)
        return task

    monkeypatch.setattr(gateway, "spawn_guarded_turn", spawn)
    monkeypatch.setattr("kiro_crew.dashboard.chat._run_chat", run_chat)
    rig.fire.side_effect = orch._fire_dashboard_nudge
    report()
    try:
        await tick(rig)
        await tick(rig, standby.COALESCE_SECS)
        release.set()
        await asyncio.gather(*tasks)
        record = standby._read(rig.loop.id)
        if outcome is None:
            assert record["claimed"]
            await tick(rig)
            assert not rig.loop.active
            assert rig.loop.stopped_reason == "interrupted_cycle"
            assert standby._read(rig.loop.id)["claimed"]
        else:
            assert record["last_completed"] == record["claim_id"]
            assert record["completion"] == outcome
            if outcome == "failure":
                assert record["execution_failures"] == 1
                assert record["check_at"] == rig.clock.now + standby.RETRY_SECS
                await tick(rig, standby.RETRY_SECS - 1)
            else:
                await tick(rig, 3600)
                assert rig.loop.active
        rig.fire.assert_awaited_once()
    finally:
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("during_fire", [False, True])
async def test_check_deadline_survives_turn_completion_and_reload(rig, monkeypatch, during_fire):
    from kiro_crew.autonudge_service import timers
    from kiro_crew.monitoring.models import MonitorActionDisposition

    monkeypatch.setattr(timers, "time", SimpleNamespace(time=lambda: rig.clock.now))
    rig.loop.idle_secs = 3600
    rig.loop.next_due_ts = rig.clock.now + 3600
    if during_fire:

        async def complete(loop):
            hook = standby.completion_hook(rig.svc, loop)
            hook.mark_accepted()
            await standby.schedule_check(rig.svc, loop, 300)
            await hook.complete(MonitorActionDisposition.SUCCESS)
            return True

        rig.fire.side_effect = complete
        report()
        await tick(rig)
        await tick(rig, standby.COALESCE_SECS)
    else:
        await standby.schedule_check(rig.svc, rig.loop, 300)
    expected = rig.clock.now + 300
    rig.svc.notify_turn_complete(SLOT)
    assert rig.loop.next_due_ts == expected
    assert rig.svc._arm_timer.call_args.kwargs["delay"] == 300
    rig.svc._load()
    restored = rig.svc.get_by_id(rig.loop.id)
    assert restored.next_due_ts == expected
    rig.svc._arm_from_deadline(restored)
    assert rig.svc._arm_timer.call_args.kwargs["delay"] == 300


async def test_due_check_waits_for_busy_user_turn_without_losing_deadline(rig, monkeypatch):
    from kiro_crew.autonudge_service import timers

    monkeypatch.setattr(timers, "time", SimpleNamespace(time=lambda: rig.clock.now))
    rig.loop.idle_secs = 3600
    await standby.schedule_check(rig.svc, rig.loop, 300)
    rig.busy.add(SLOT)
    await tick(rig, 300)
    rig.fire.assert_not_awaited()
    rig.busy.clear()
    rig.svc.notify_turn_complete(SLOT)
    assert rig.svc._arm_timer.call_args.kwargs["delay"] <= 15
    await tick(rig, 15)
    rig.fire.assert_awaited_once()
