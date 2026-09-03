"""In-flight markers for cron runs -- the record a hard exit leaves behind.

A cron run writes its ``last_run_ts``, its history row and its status in the
``finally`` of the run task. A gateway that the loop-stall watchdog hard-exits
(``os._exit`` from faulthandler's thread) runs no ``finally``: the store shows
the job as never having fired, so on the next boot it is due again, fires
again, and stalls again. Nothing on disk said WHICH job was running when the
process died, so ``kirocrew doctor`` could show the stack but not the job, and
nothing could break the loop.

This module is that record. ``write_marker`` drops one small JSON file per
running job under ``<cron dir>/cron-running/`` when the run starts executing,
and ``clear_marker`` removes it when the run ends by any path that runs
``finally``. A marker that is still there for a PID that is no longer alive is
therefore exactly "this job was in flight when that gateway died", with no
inference from timestamps or schedules. The stall attribution
(:mod:`kiro_crew.stall_attribution`) joins it to the crash dump by PID; the
cron service's boot-time breaker pauses the job it names; ``doctor`` prints it.

Every function here is synchronous filesystem I/O and is called off the event
loop (``asyncio.to_thread`` from the run task, a worker from ``start()``, the
doctor CLI). Writes are best-effort: a marker failure must never fail a run.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from kiro_crew.platform_compat import pid_exists

logger = logging.getLogger(__name__)

#: Directory (under the cron store's base directory) holding one file per
#: running job.
RUNNING_DIR_NAME = "cron-running"
_MARKER_SUFFIX = ".json"
#: A marker is never read past this size: it is written by this module and
#: holds five short fields, so anything larger is not a marker.
_MARKER_MAX_BYTES = 4096


@dataclass(frozen=True)
class RunningMarker:
    """One in-flight (or abandoned) cron run."""

    job_id: str
    name: str
    started_at: float
    pid: int
    path: Path

    def owner_alive(self) -> bool:
        return self.pid == os.getpid() or pid_exists(self.pid)


def running_dir(base_dir: Path) -> Path:
    return base_dir / RUNNING_DIR_NAME


def marker_path(base_dir: Path, job_id: str) -> Path:
    # Job ids are hex tokens minted by the service; a stray separator is
    # rejected rather than resolved into a path outside the marker directory.
    if not job_id or "/" in job_id or "\\" in job_id or job_id in (".", ".."):
        raise ValueError(f"not a cron job id: {job_id!r}")
    return running_dir(base_dir) / f"{job_id}{_MARKER_SUFFIX}"


def write_marker(base_dir: Path, job_id: str, name: str, started_at: float | None = None) -> None:
    """Record that *job_id* is executing in this process. Best-effort."""
    try:
        path = marker_path(base_dir, job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "job_id": job_id,
            "name": name,
            "started_at": float(started_at if started_at is not None else time.time()),
            "pid": os.getpid(),
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)
    except Exception:
        logger.debug("cron in-flight marker not written for %s", job_id, exc_info=True)


def clear_marker(base_dir: Path, job_id: str) -> None:
    """Remove *job_id*'s marker. Best-effort; a missing marker is not an error."""
    try:
        marker_path(base_dir, job_id).unlink(missing_ok=True)
    except Exception:
        logger.debug("cron in-flight marker not cleared for %s", job_id, exc_info=True)


def _read_marker(path: Path) -> RunningMarker | None:
    try:
        if path.stat().st_size > _MARKER_MAX_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return RunningMarker(
            job_id=str(data["job_id"]),
            name=str(data.get("name") or ""),
            started_at=float(data.get("started_at") or 0.0),
            pid=int(data["pid"]),
            path=path,
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None


def read_markers(base_dir: Path) -> list[RunningMarker]:
    """Every readable marker, oldest start first. Unparseable files are skipped."""
    d = running_dir(base_dir)
    if not d.is_dir():
        return []
    out: list[RunningMarker] = []
    for path in d.iterdir():
        if path.suffix != _MARKER_SUFFIX or not path.name.endswith(_MARKER_SUFFIX):
            continue
        marker = _read_marker(path)
        if marker is not None:
            out.append(marker)
    out.sort(key=lambda m: m.started_at)
    return out


def abandoned_markers(base_dir: Path) -> list[RunningMarker]:
    """Markers whose owning process is gone: runs cut short by a hard exit."""
    return [m for m in read_markers(base_dir) if not m.owner_alive()]


def sweep_abandoned_markers(base_dir: Path) -> int:
    """Delete the abandoned markers once they have been read. Returns the count.

    Called by the cron service after its boot-time attribution has consumed
    them, so a run interrupted long ago is not re-attributed on every boot. A
    marker owned by a live PID (another gateway on the same data home, or this
    one) is never touched.
    """
    removed = 0
    for marker in abandoned_markers(base_dir):
        try:
            marker.path.unlink(missing_ok=True)
            removed += 1
        except OSError:
            logger.debug("abandoned cron marker not removed: %s", marker.path, exc_info=True)
    return removed
