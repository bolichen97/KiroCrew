"""Owner-authorized work-ledger standby on the existing auto-nudge timer.

The ledger probe supplies typed observations. A durable delivery cursor, one-shot
check deadline and bounded wake window decide when those observations need a turn.
Authorization and cursors live in the already sandbox-hidden tag-grants leaf;
agent-writable loop rows cannot create or restore this authority.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from kiro_crew.atomic_write import atomic_write
from kiro_crew.config.paths import data_home
from kiro_crew.dashboard import token_secret
from kiro_crew.monitoring.completion import MonitorCompletionHook
from kiro_crew.monitoring.models import MonitorActionCompletion, MonitorActionDisposition
from kiro_crew.probes.work_ledger import WorkLedgerProbe

if TYPE_CHECKING:
    from kiro_crew.autonudge import AutoNudgeService, NudgeLoop

logger = logging.getLogger(__name__)

COALESCE_SECS = 2.0
RETRY_SECS = 30.0
MAX_FAILURES = 3
WINDOW_SECS = 3600.0
MAX_WAKES_PER_WINDOW = 12
MAX_SEEN_KEYS = 8192
MAX_RECORD_BYTES = 2 * 1024 * 1024
CHECK_MAX_SECS = 30 * 86400
_DOMAIN = b"kiro-crew:conductor-standby:v1\x00"


async def joined(task: asyncio.Task[Any]) -> Any:
    """Keep a mutation's lock until its worker settles, even after cancellation."""
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    result = task.result()
    if cancelled:
        raise asyncio.CancelledError
    return result


async def joined_io(function: Any, *args: Any, **kwargs: Any) -> Any:
    return await joined(asyncio.create_task(asyncio.to_thread(function, *args, **kwargs)))


def _path(loop_id: str) -> Path:
    digest = hashlib.sha256(loop_id.encode()).hexdigest()
    return data_home() / "tag-grants" / "conductor-standby" / (digest + ".json")


def has_record(loop_id: str) -> bool:
    """An agent-writable mode bit cannot discard a protected standby record."""
    try:
        return _path(loop_id).exists()
    except OSError:
        return True  # An unreadable authorization store cannot grant legacy dispatch.


def _signature(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(token_secret._get_secret(), _DOMAIN + payload, hashlib.sha256).hexdigest()


def _read(loop_id: str) -> dict[str, Any]:
    path = _path(loop_id)
    with path.open("rb") as stream:
        raw = stream.read(MAX_RECORD_BYTES + 1)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("standby record exceeds its bound")
    envelope = json.loads(raw)
    record = envelope["record"]
    signature = envelope["signature"]
    if not isinstance(signature, str) or not signature.isascii():
        raise ValueError("invalid standby signature")
    if not hmac.compare_digest(signature, _signature(record)):
        raise ValueError("untrusted standby record")
    if record.get("version") != 1 or record.get("loop") != loop_id:
        raise ValueError("unsupported standby record")
    return record


def _write(record: dict[str, Any]) -> None:
    path = _path(record["loop"])
    path.parent.mkdir(parents=True, exist_ok=True)
    envelope = {"record": record, "signature": _signature(record)}
    atomic_write(path, json.dumps(envelope), fsync=True, restrict_to_owner=True)


def grant(loop_id: str, slot_key: str, *, perpetual: bool = False) -> None:
    """Called only by the authenticated owner arm, before publishing the loop."""
    _write(
        {
            "version": 1,
            "loop": loop_id,
            "slot": slot_key,
            "enabled": True,
            "perpetual": perpetual,
            "seen": [],
            "pending": [],
            "opened_at": 0.0,
            "check_at": 0.0,
            "claimed": False,
            "failures": 0,
            "wake_times": [],
            "probes": 0,
            "wakes": 0,
            "retry_at": 0.0,
        }
    )


def revoke(loop_id: str) -> None:
    """Remove authorization before stopping or removing its agent-writable row."""
    try:
        record = _read(loop_id)
    except FileNotFoundError:
        return
    record["enabled"] = False
    _write(record)


async def stop_for_slot(slot_key: str) -> None:
    """A chat Stop also retires standby, including while the session is idle."""
    from kiro_crew.autonudge import get_instance

    svc = get_instance()
    loop = svc.get_by_slot(slot_key) if svc is not None else None
    if loop is None:
        return
    if getattr(loop, "standby", False) is not True and not await asyncio.to_thread(
        has_record, loop.id
    ):
        return
    assert svc is not None
    # Fence queued admission synchronously before waiting for the durable
    # revocation. A claim write may already own the service lock.
    loop.active = False
    svc._cancel_timer(loop.id)
    if await svc.update(loop.id, active=False, stopped_reason="manual") is None:
        raise RuntimeError("standby Stop could not acquire its mutation boundary")


async def resume(svc: AutoNudgeService, loop: NudgeLoop) -> None:
    """An owner acknowledges an interrupted delivery when explicitly resuming."""
    async with svc._lock:
        if svc.get_by_id(loop.id) is not loop:
            raise ValueError("standby changed before resume")
        record = await asyncio.to_thread(_read, loop.id)
        if record["slot"] != loop.slot_key:
            raise ValueError("standby belongs to another session")
        record.update(enabled=True, claimed=False, failures=0, execution_failures=0)
        await joined_io(_write, record)


def authorized(loop: NudgeLoop, record: dict[str, Any]) -> bool:
    return (
        record.get("enabled") is True
        and record.get("slot") == loop.slot_key
        and loop.active
        and loop.standby is True
        and loop.gate
        and loop.monitor is not None
        and loop.monitor.kind == "work-ledger"
        and loop.monitor.target == loop.slot_key
    )


async def schedule_check(svc: AutoNudgeService, loop: NudgeLoop, seconds: int) -> None:
    """Register one check; zero cancels it. This never grants standby authority."""
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, int)
        or not 0 <= seconds <= CHECK_MAX_SECS
    ):
        raise ValueError("check_after_secs must be an integer between 0 and 2592000")
    if not loop.standby or not loop.active:
        raise ValueError("an active owner-authorized standby is required")
    async with svc._lock:
        record = await asyncio.to_thread(_read, loop.id)
        if svc.get_by_id(loop.id) is not loop or not authorized(loop, record):
            raise ValueError("an active owner-authorized work-ledger standby is required")
        record["check_at"] = time.time() + max(15, seconds) if seconds else 0.0
        await joined_io(_write, record)
        delay = float(min(loop.idle_secs, max(15, seconds)) if seconds else loop.idle_secs)
        if loop.next_due_ts:
            delay = min(delay, max(0.0, loop.next_due_ts - time.time()))
        loop.next_due_ts = time.time() + delay
        await svc._write_monitor_snapshot_locked()
    if loop.id not in svc._firing:
        svc._arm_timer(loop, delay=delay)


def completion_hook(svc: AutoNudgeService, loop: NudgeLoop) -> MonitorCompletionHook:
    """Use the existing admission gates before setup and provider entry."""
    generation = loop.config_generation
    fingerprint = f"standby:{generation}:{loop.cycle_count + 1}"

    async def check(_loop_id: str, _fingerprint: str) -> bool:
        try:
            record = await asyncio.to_thread(_read, loop.id)
        except (OSError, ValueError, KeyError, TypeError):
            return False
        if record.get("perpetual"):
            from kiro_crew.autonudge_selfarm import is_recorded_owner_arm

            if not await asyncio.to_thread(is_recorded_owner_arm, loop.id, loop.slot_key):
                return False
        return (
            svc.get_by_id(loop.id) is loop
            and loop.config_generation == generation
            and authorized(loop, record)
            and record.get("claimed") is True
            and record.get("claim_id") == fingerprint
        )

    async def complete(result: MonitorActionCompletion) -> None:
        if not hook.accepted:
            return
        async with svc._lock:
            record = await asyncio.to_thread(_read, loop.id)
            if (
                svc.get_by_id(loop.id) is not loop
                or not authorized(loop, record)
                or record.get("claim_id") != fingerprint
                or record.get("last_completed") == fingerprint
            ):
                return
            record["last_completed"] = fingerprint
            record["completion"] = result.disposition.value
            if result.disposition == MonitorActionDisposition.FAILURE:
                failures = record.get("execution_failures", 0) + 1
                record["execution_failures"] = failures
                retry_at = time.time() + RETRY_SECS * 2 ** min(failures - 1, MAX_FAILURES)
                record["retry_at"] = retry_at
                record["check_at"] = (
                    min(record["check_at"], retry_at)
                    if record["check_at"] > time.time()
                    else retry_at
                )
                if failures >= MAX_FAILURES:
                    record["enabled"] = False
                    loop.active = False
                    loop.stopped_reason = "standby_execution_failed"
                else:
                    loop.next_due_ts = min(loop.next_due_ts or retry_at, retry_at)
            elif result.disposition == MonitorActionDisposition.SUCCESS:
                record["execution_failures"] = 0
            await joined_io(_write, record)
            await svc._write_monitor_snapshot_locked()
            if not loop.active:
                svc._emit("expired", loop)
            elif loop.id not in svc._firing:
                svc._arm_from_deadline(loop)
        # The existing usage pipeline owns provider totals; retain their real
        # dimensions here only for correlating this standby wake with its turn.
        logger.info(
            "standby completion loop=%s session=%s disposition=%s input=%s output=%s",
            loop.id,
            loop.slot_key,
            result.disposition.value,
            result.input_tokens,
            result.output_tokens,
        )

    hook = MonitorCompletionHook(
        loop.id,
        fingerprint,
        complete,
        authorization_callback=check,
    )
    return hook


async def run_tick(svc: AutoNudgeService, loop: NudgeLoop) -> None:
    """Observe without a judge, coalesce changes, then use the normal fire adapter."""
    if loop.id in svc._firing or not loop.active or svc.get_by_id(loop.id) is not loop:
        return
    svc._firing.add(loop.id)
    delay = float(loop.idle_secs)
    not_before = 0.0
    try:
        async with svc._lock:
            try:
                record = await asyncio.to_thread(_read, loop.id)
            except (OSError, ValueError, KeyError, TypeError):
                loop.active = False
                loop.stopped_reason = "standby_authorization_unavailable"
                await svc._write_monitor_snapshot_locked()
                svc._emit("expired", loop)
                return
            if record.get("perpetual"):
                from kiro_crew.autonudge_selfarm import is_recorded_owner_arm

                if not await asyncio.to_thread(is_recorded_owner_arm, loop.id, loop.slot_key):
                    record["enabled"] = False
            if not authorized(loop, record):
                loop.active = False
                loop.stopped_reason = "standby_authorization_unavailable"
                await svc._write_monitor_snapshot_locked()
                svc._emit("expired", loop)
                return
            if record["check_at"]:
                delay = min(delay, max(15.0, record["check_at"] - time.time()))
            if record["claimed"] and loop.id in svc._standby_deliveries:
                if svc._worker_running(loop.slot_key):
                    return
                if record.get("last_completed") == record.get("claim_id"):
                    record["claimed"] = False
                    await joined_io(_write, record)
                svc._standby_deliveries.discard(loop.id)
            if record["claimed"]:
                # A crash cannot prove whether the accepted turn performed work.
                # Retain its claim and require an explicit owner recovery.
                loop.active = False
                loop.stopped_reason = "interrupted_cycle"
                await svc._write_monitor_snapshot_locked()
                svc._emit("expired", loop)
                return
            if svc._worker_running(loop.slot_key):
                return
            now = time.time()
            not_before = record["retry_at"]
            if now < not_before:
                delay = not_before - now
                return
            record["wake_times"] = [t for t in record["wake_times"] if t > now - WINDOW_SECS]
            if len(record["wake_times"]) >= MAX_WAKES_PER_WINDOW:
                not_before = record["wake_times"][0] + WINDOW_SECS
                delay = max(1.0, not_before - now)
                loop.stopped_reason = "standby_rate_limit"
                return
            loop.stopped_reason = ""
            probe = WorkLedgerProbe(
                worker_running=svc._worker_running, worker_closed=svc._worker_closed, standby=True
            )
            try:
                tick = await asyncio.to_thread(
                    probe.observe, SimpleNamespace(message=json.dumps({"conductor": loop.slot_key}))
                )
                if not tick.fetch_ok:
                    raise OSError("work ledger unreadable")
            except Exception:
                record["failures"] += 1
                delay = RETRY_SECS * 2 ** min(record["failures"] - 1, MAX_FAILURES)
                not_before = record["retry_at"] = now + delay
                await joined_io(_write, record)
                if record["failures"] >= MAX_FAILURES:
                    record["enabled"] = False
                    await joined_io(_write, record)
                    loop.active = False
                    loop.stopped_reason = "standby_probe_failed"
                    await svc._write_monitor_snapshot_locked()
                    svc._emit("expired", loop)
                return
            record["probes"] += 1
            keys = [observation.key for observation in tick.observations]
            unseen = [key for key in keys if key not in record["seen"]]
            record["pending"] = list(dict.fromkeys(record["pending"] + unseen))
            due = bool(record["check_at"] and record["check_at"] <= now)
            if not record["pending"] and not due:
                record["failures"] = 0
                if record["check_at"]:
                    delay = min(delay, max(0.0, record["check_at"] - now))
                await joined_io(_write, record)
                return
            if not record["opened_at"]:
                record["opened_at"] = now
            if not due and now < record["opened_at"] + COALESCE_SECS:
                delay = record["opened_at"] + COALESCE_SECS - now
                await joined_io(_write, record)
                return
            record["claimed"] = True
            record["claim_id"] = f"standby:{loop.config_generation}:{loop.cycle_count + 1}"
            await joined_io(_write, record)
        # Stop/remove may land during the durable write. Never dispatch that stale row.
        if not loop.active or svc.get_by_id(loop.id) is not loop:
            return
        logger.info(
            "standby wake loop=%s session=%s reason=%s events=%d",
            loop.id,
            loop.slot_key,
            (
                ("retry" if record.get("execution_failures") else "check_due")
                if due
                else "ledger_event"
            ),
            len(record["pending"]),
        )
        before = loop.cycle_count
        await svc._run_fire_cycle(loop)
        async with svc._lock:
            if svc.get_by_id(loop.id) is not loop:
                return
            delivered = loop.cycle_count > before
            if not loop.active and not delivered:
                return
            # A completed turn can pause the loop, but still counts as a wake.
            # A concurrent explicit deadline update must survive this delivery.
            fresh = await asyncio.to_thread(_read, loop.id)
            fresh["claimed"] = delivered and (
                svc._worker_running(loop.slot_key)
                or fresh.get("last_completed") != record["claim_id"]
            )
            if fresh["claimed"]:
                svc._standby_deliveries.add(loop.id)
            if delivered:
                fresh["seen"] = list(dict.fromkeys(fresh["seen"] + record["pending"]))[
                    -MAX_SEEN_KEYS:
                ]
                fresh["pending"] = []
                fresh["opened_at"] = 0.0
                if due and fresh["check_at"] == record["check_at"]:
                    fresh["check_at"] = 0.0
                fresh["wake_times"].append(now)
                fresh["wakes"] += 1
                fresh["failures"] = 0
                completed_failure = (
                    fresh.get("last_completed") == record["claim_id"]
                    and fresh.get("completion") == MonitorActionDisposition.FAILURE.value
                )
                if completed_failure:
                    not_before = fresh["retry_at"]
                    delay = max(0.0, not_before - time.time())
                else:
                    fresh["retry_at"] = 0.0
            else:
                fresh["failures"] += 1
                delay = RETRY_SECS * 2 ** min(fresh["failures"] - 1, MAX_FAILURES)
                not_before = fresh["retry_at"] = now + delay
                if fresh["failures"] >= MAX_FAILURES:
                    fresh["enabled"] = False
                    loop.active = False
                    loop.stopped_reason = "standby_delivery_failed"
            if fresh["check_at"]:
                delay = min(delay, max(0.0, fresh["check_at"] - time.time()))
            await joined_io(_write, fresh)
            loop.next_due_ts = max(time.time() + delay, not_before) if loop.active else 0.0
            await svc._write_monitor_snapshot_locked()
            if not loop.active:
                svc._emit("expired", loop)
    except asyncio.CancelledError:
        raise
    except Exception:
        # Storage failure is a visible pause, never permission to fall through to a model.
        logger.exception("standby tick failed for %s", loop.id)
        loop.active = False
        loop.stopped_reason = "standby_storage_failed"
        svc._persist_soon()
        svc._emit("expired", loop)
    finally:
        svc._firing.discard(loop.id)
        svc._pushed_running.discard(loop.id)
        svc._rearm_pending.discard(loop.id)
        if loop.id in svc._pulled_forward:
            svc._pulled_forward.discard(loop.id)
            delay = min(delay, COALESCE_SECS)
        if loop.active and svc.get_by_id(loop.id) is loop:
            loop.next_due_ts = max(time.time() + delay, not_before)
            svc._persist_soon()
            svc._arm_from_deadline(loop)


async def enable_perpetual(svc: AutoNudgeService, loop: NudgeLoop) -> None:
    """Reuse an existing owner Perpetual grant when its session watches the ledger."""
    from kiro_crew.autonudge_selfarm import is_recorded_owner_arm
    from kiro_crew.monitoring.models import MONITOR_STATE_VERSION

    if (
        getattr(loop, "standby", False)
        or getattr(loop, "active", False) is not True
        or loop.max_cycles
        or loop.max_runtime_secs
        or loop.monitor is None
        or loop.monitor.kind != "work-ledger"
        or loop.monitor.version != MONITOR_STATE_VERSION
    ):
        return
    async with svc._lock:
        if svc.get_by_id(loop.id) is not loop or not loop.active or loop.standby:
            return
        if not await asyncio.to_thread(is_recorded_owner_arm, loop.id, loop.slot_key):
            return
        try:
            record = await asyncio.to_thread(_read, loop.id)
        except FileNotFoundError:
            await joined_io(grant, loop.id, loop.slot_key, perpetual=True)
        else:
            # Never recreate revoked or interrupted authority from the loop row.
            if not record["enabled"] or record["claimed"]:
                loop.active = False
                loop.stopped_reason = "standby_authorization_unavailable"
                await svc._write_monitor_snapshot_locked()
                return
        loop.standby = True
        loop.monitor.token_usage_known = False
        await svc._write_monitor_snapshot_locked()
