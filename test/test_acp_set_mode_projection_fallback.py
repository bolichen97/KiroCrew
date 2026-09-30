"""``session/set_mode`` never bricks a session over a skill-view alias.

kiro-cli 2.25.0 and 2.26.0 reload ``~/.kiro/agents`` on a data write and never on
a rename, so an alias ``atomic_write`` renamed into place after the process
started answers ``Mode '<alias>' not found`` while the file is on disk. The
runtime re-prepares the projection right before ``set_mode``, so any change to a
source spec since spawn names exactly such an alias.

These drive the REAL reader and ``_send_and_await`` against a fake kiro-cli that
answers ``set_mode`` from the set of names it has "loaded", so the name
translation, the error mapping and the fallback are all the product's own.
"""

from __future__ import annotations

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from test_update_provider import _UNALLOCATABLE_PID

from kiro_crew.acp import runtime as runtime_mod
from kiro_crew.acp.runtime import AcpRuntime
from kiro_crew.acp.session_handle import AcpModeNotFound, AcpRuntimeError
from kiro_crew.acp.skill_projection import NativeSkillProjection
from kiro_crew.acp.types import METHOD_SET_MODE

STALE_ALIAS = "kirocrew-skill-view-" + "a" * 24
FRESH_ALIAS = "kirocrew-skill-view-" + "b" * 24


class _FakeKiro:
    """Answers awaited requests the way kiro-cli does, from what it has loaded."""

    def __init__(self, reader: asyncio.StreamReader, loaded: set[str]) -> None:
        self.reader = reader
        self.loaded = loaded
        self.set_modes: list[str] = []
        self.reload_after_misses: int | None = None
        self.other_error: dict | None = None
        self._misses = 0

    def write(self, data: bytes) -> None:
        frame = json.loads(data)
        if "id" not in frame:
            return
        method = frame.get("method")
        if method == METHOD_SET_MODE:
            mode = frame["params"]["modeId"]
            self.set_modes.append(mode)
            if self.other_error is not None:
                self._answer(frame["id"], error=self.other_error)
            elif mode in self.loaded:
                self._answer(frame["id"], result={})
            else:
                self._misses += 1
                if (
                    self.reload_after_misses is not None
                    and self._misses >= self.reload_after_misses
                ):
                    self.loaded.add(FRESH_ALIAS)
                self._answer(
                    frame["id"],
                    error={
                        "code": -32603,
                        "message": "Internal error",
                        "data": f"Mode '{mode}' not found",
                    },
                )
        else:
            self._answer(frame["id"], result={})

    def _answer(self, req_id: int, **body: object) -> None:
        self.reader.feed_data(
            (json.dumps({"jsonrpc": "2.0", "id": req_id, **body}) + "\n").encode()
        )


def _runtime(loaded: set[str]) -> tuple[AcpRuntime, _FakeKiro]:
    rt = AcpRuntime(work_dir="/tmp")
    reader = asyncio.StreamReader()
    kiro = _FakeKiro(reader, loaded)
    proc = MagicMock()
    proc.stdout = reader
    proc.stdin = MagicMock()
    proc.stdin.write = MagicMock(side_effect=kiro.write)
    proc.stdin.drain = AsyncMock()
    proc.returncode = None
    proc.pid = _UNALLOCATABLE_PID
    rt._process = proc
    rt._pid = _UNALLOCATABLE_PID
    rt._initialized = True
    rt._native_skill_projection = NativeSkillProjection({"ops": FRESH_ALIAS})
    return rt, kiro


@pytest.fixture
def no_retry_wait(monkeypatch):
    monkeypatch.setattr(runtime_mod, "_PROJECTED_MODE_RETRY_DELAYS_SECS", (0.0, 0.0))


async def _with_reader(rt: AcpRuntime, coro):
    task = asyncio.ensure_future(rt._reader_loop())
    await asyncio.sleep(0)
    try:
        return await asyncio.wait_for(coro, timeout=10)
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass


async def _activate(
    rt: AcpRuntime, projection: NativeSkillProjection, *, snapshot: object = None
) -> None:
    """Run the real bracket with the re-preparation returning *projection*.

    *snapshot* stands in for the derived-spec bracket's verified snapshot: not
    ``None`` means *mode_agent*'s spec is freshness-checked."""
    rt.terminate_session = AsyncMock()  # type: ignore[method-assign]
    with (
        patch(
            "kiro_crew.acp.skill_projection.prepare_native_skill_projection",
            return_value=projection,
        ),
        patch("kiro_crew.agent.require_unchanged_derived_spec", return_value=None),
    ):
        await rt._activate_mode_bracketed(
            "s1", "ops", budget=5.0, payload_snapshot=snapshot, wire_registered=True
        )


@pytest.mark.asyncio
async def test_a_freshly_published_alias_the_host_never_loads_falls_back_to_the_authored_agent(
    no_retry_wait, caplog
):
    """The incident: the bracket re-prepares, the view changed since spawn, the
    new alias was renamed into place, and kiro-cli never loads it. The session
    must come up on the authored agent -- not be terminated with "is not
    installed" on every turn."""
    rt, kiro = _runtime({STALE_ALIAS, "ops"})
    caplog.set_level(logging.WARNING, logger="kiro_crew.acp.runtime")

    await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))

    rt.terminate_session.assert_not_awaited()
    retries = len(runtime_mod._PROJECTED_MODE_RETRY_DELAYS_SECS)
    assert kiro.set_modes == [FRESH_ALIAS] * (1 + retries) + ["ops"]
    assert any(
        "runs the authored agent instead" in r.getMessage() and FRESH_ALIAS in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.asyncio
async def test_an_alias_the_host_loads_after_its_reload_is_used_without_falling_back(
    no_retry_wait, caplog
):
    """The publication's in-place rewrite makes kiro-cli reload; a retry after
    that lands on the alias, so bounded skill discovery is kept."""
    rt, kiro = _runtime({"ops"})
    kiro.reload_after_misses = 1
    caplog.set_level(logging.WARNING, logger="kiro_crew.acp.runtime")

    await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))

    rt.terminate_session.assert_not_awaited()
    assert kiro.set_modes == [FRESH_ALIAS, FRESH_ALIAS]
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.asyncio
async def test_a_missing_authored_agent_still_fails_with_the_repair_sentence(no_retry_wait):
    """The fallback is for a projection miss only. When the authored spec is
    gone too, the old actionable error stands and the session is torn down."""
    rt, kiro = _runtime(set())

    with pytest.raises(AcpModeNotFound) as excinfo:
        await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))

    assert excinfo.value.mode_id == "ops"
    assert "kirocrew setup --agent-only --clean" in str(excinfo.value)
    rt.terminate_session.assert_awaited_once_with("s1")
    assert kiro.set_modes[-1] == "ops"


@pytest.mark.asyncio
async def test_without_a_projection_a_missing_mode_is_not_retried(no_retry_wait):
    """No alias was involved, so there is nothing to wait for or fall back from."""
    rt, kiro = _runtime(set())
    rt._native_skill_projection = None

    with pytest.raises(AcpModeNotFound):
        await _with_reader(rt, _activate(rt, rt._native_skill_projection))

    assert kiro.set_modes == ["ops"]


@pytest.mark.asyncio
async def test_any_other_set_mode_error_propagates_without_a_retry(no_retry_wait):
    rt, kiro = _runtime({FRESH_ALIAS})
    kiro.other_error = {"code": -32603, "message": "Internal error", "data": "boom"}

    with pytest.raises(AcpRuntimeError) as excinfo:
        await _with_reader(rt, _activate(rt, rt._native_skill_projection))

    assert not isinstance(excinfo.value, AcpModeNotFound)
    assert kiro.set_modes == [FRESH_ALIAS]


def test_the_retry_schedule_outlasts_kiro_clis_reload_debounce_and_stays_bounded():
    """kiro-cli reloads 500 ms after the LAST data write (a trailing debounce,
    then a full rescan); measured on 2.26.0 a written alias became selectable
    between 0.7 s and 1.5 s after it was published. No wait may be shorter than
    the debounce, the schedule must cover that window with room to spare, and
    it must stay a small fraction of the set_mode budget."""
    delays = runtime_mod._PROJECTED_MODE_RETRY_DELAYS_SECS
    assert delays and min(delays) >= 0.5
    assert 2.5 <= sum(delays) <= 5.0


@pytest.fixture
def counted(monkeypatch):
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(runtime_mod, "emit_counter", lambda name, attrs: seen.append((name, attrs)))
    return seen


@pytest.mark.asyncio
async def test_a_view_changed_since_spawn_keeps_the_alias_the_host_listed_at_spawn(
    no_retry_wait, counted
):
    """Judged against the SPAWN projection: a re-preparation
    naming a new alias for the agent sends the alias kiro-cli listed at spawn,
    with no miss at all, and the process keeps that projection."""
    rt, kiro = _runtime({STALE_ALIAS, "ops"})
    spawn = NativeSkillProjection({"ops": STALE_ALIAS})
    rt._native_skill_projection = spawn
    rt._spawn_skill_projection = spawn

    await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))

    rt.terminate_session.assert_not_awaited()
    assert kiro.set_modes == [STALE_ALIAS]
    assert rt._native_skill_projection is spawn
    assert counted == [(runtime_mod.SKILL_VIEW_FALLBACKS, {"outcome": "kept_spawn_view"})]


@pytest.mark.asyncio
async def test_the_spawn_alias_is_kept_even_after_another_agent_adopted_a_fresh_view(
    no_retry_wait, counted
):
    """Comparing against the projection adopted LAST is not enough: once any
    set_mode adopted a fresh projection, it already names the new alias, so the
    comparison sees "unchanged" and sends a name the host never loaded."""
    rt, kiro = _runtime({STALE_ALIAS, "ops"})
    rt._spawn_skill_projection = NativeSkillProjection({"ops": STALE_ALIAS})
    rt._native_skill_projection = NativeSkillProjection({"ops": FRESH_ALIAS})

    await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))

    assert kiro.set_modes == [STALE_ALIAS]
    rt.terminate_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_spawn_alias_the_host_lost_still_ends_on_the_authored_agent(no_retry_wait, counted):
    """The spawn alias is the best guess, not a guarantee (someone deleted it,
    the host dropped it on a reload): its miss walks the same retry ladder."""
    rt, kiro = _runtime({"ops"})
    spawn = NativeSkillProjection({"ops": STALE_ALIAS})
    rt._native_skill_projection = spawn
    rt._spawn_skill_projection = spawn

    await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))

    retries = len(runtime_mod._PROJECTED_MODE_RETRY_DELAYS_SECS)
    assert kiro.set_modes == [STALE_ALIAS] * (1 + retries) + ["ops"]
    assert [a["outcome"] for _n, a in counted] == ["kept_spawn_view", "authored_agent"]
    rt.terminate_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_re_preparation_that_cannot_run_keeps_the_view_instead_of_dropping_it(
    no_retry_wait, counted
):
    """``None`` (the alias lock was busy) keeps the view the host loaded rather
    than switching the whole process's translation off."""
    rt, kiro = _runtime({STALE_ALIAS})
    spawn = NativeSkillProjection({"ops": STALE_ALIAS})
    rt._native_skill_projection = spawn

    await _with_reader(rt, _activate(rt, None))

    assert kiro.set_modes == [STALE_ALIAS]
    assert rt._native_skill_projection is spawn
    assert counted == [(runtime_mod.SKILL_VIEW_FALLBACKS, {"outcome": "kept_previous_view"})]


@pytest.mark.asyncio
async def test_every_rung_below_the_first_try_is_counted(no_retry_wait, counted):
    rt, kiro = _runtime({"ops"})
    kiro.reload_after_misses = 1
    await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))
    assert counted == [(runtime_mod.SKILL_VIEW_FALLBACKS, {"outcome": "loaded_after_retry"})]

    counted.clear()
    rt, kiro = _runtime({"ops"})
    await _with_reader(rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS})))
    assert counted == [(runtime_mod.SKILL_VIEW_FALLBACKS, {"outcome": "authored_agent"})]


SIBLING_SPAWN_ALIAS = "kirocrew-skill-view-" + "c" * 24
SIBLING_FRESH_ALIAS = "kirocrew-skill-view-" + "d" * 24


@pytest.mark.asyncio
async def test_a_sibling_agents_new_alias_keeps_the_spawn_projection_for_the_process(
    no_retry_wait, counted
):
    """Another agent's view changed; the mode agent's did not. Adopting the fresh
    projection would drop the sibling's spawn alias from the frame filter, so the
    host's advertised ``availableModes`` would lose it and the sibling's next
    session start would fail ``_mode_available``. The spawn projection stays."""
    rt, kiro = _runtime({STALE_ALIAS, SIBLING_SPAWN_ALIAS})
    spawn = NativeSkillProjection({"ops": STALE_ALIAS, "dev": SIBLING_SPAWN_ALIAS})
    rt._spawn_skill_projection = spawn
    rt._native_skill_projection = spawn

    await _with_reader(
        rt,
        _activate(rt, NativeSkillProjection({"ops": STALE_ALIAS, "dev": SIBLING_FRESH_ALIAS})),
    )

    assert kiro.set_modes == [STALE_ALIAS]
    assert rt._native_skill_projection is spawn
    advertised = {"availableModes": [{"id": STALE_ALIAS}, {"id": SIBLING_SPAWN_ALIAS}]}
    assert [m["id"] for m in rt._native_skill_projection.frame(advertised)["availableModes"]] == [
        "ops",
        "dev",
    ]
    assert rt._mode_available(
        "dev",
        {
            "modes": rt._native_skill_projection.frame(
                {"availableModes": advertised["availableModes"]}
            )
        },
    )
    assert counted == []
    rt.terminate_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_freshness_checked_agent_whose_view_changed_runs_the_verified_authored_agent(
    no_retry_wait, counted, caplog
):
    """Under the derived-spec bracket the spawn alias holds a generation nothing
    verified (a server since revoked, say), so the session must not activate it:
    it runs the authored agent the bracket just checked, untranslated."""
    rt, kiro = _runtime({STALE_ALIAS, "ops"})
    spawn = NativeSkillProjection({"ops": STALE_ALIAS})
    rt._spawn_skill_projection = spawn
    rt._native_skill_projection = spawn

    with caplog.at_level(logging.WARNING, logger="kiro_crew.acp.runtime"):
        await _with_reader(
            rt, _activate(rt, NativeSkillProjection({"ops": FRESH_ALIAS}), snapshot=object())
        )

    assert kiro.set_modes == ["ops"]
    assert STALE_ALIAS not in kiro.set_modes
    assert [attrs["outcome"] for _name, attrs in counted] == ["authored_agent"]
    assert "freshness-checked" in caplog.text
    rt.terminate_session.assert_not_awaited()
