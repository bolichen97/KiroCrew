"""Off-loop DB discipline for the auto_research campaigns DB.

Every connection from ``_get_db()`` carries a 30s busy timeout, and the
watchdog writes the campaigns table every cycle while HTTP handlers read and
write the same rows — so a single ``_get_db()`` entered directly on the
asyncio event loop can freeze the whole gateway past the loop-stall watchdog
budget (25s) and hard-exit the process. These tests pin the discipline from
three directions:

1. the runtime chokepoint guard in ``_get_db()`` (strict raise / production
   warn / off-loop no-op),
2. a static AST ratchet: no ``async def`` in handlers.py calls a DB-touching
   function directly (the offload pattern is ``asyncio.to_thread`` /
   ``run_in_executor``, optionally via a nested sync helper),
3. an end-to-end contention proof: a held write lock on the campaigns DB
   stalls the affected handler, not the event loop's heartbeat.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from kiro_crew.apps.builtins.auto_research import handlers as h
from kiro_crew.apps.builtins.auto_research.handlers import (
    CampaignStatus,
    OnLoopDBError,
    _get_db,
    create_campaign,
    get_campaign,
    register_routes,
    update_campaign_status,
)


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path):
    """Isolate DB and research dir per test (same shape as test_auto_research)."""
    with (
        patch(
            "kiro_crew.apps.builtins.auto_research.handlers.DB_PATH",
            tmp_path / "test.db",
        ),
        patch(
            "kiro_crew.apps.builtins.auto_research.handlers.RESEARCH_DIR",
            tmp_path / "research",
        ),
    ):
        yield tmp_path


class TestOnLoopGuard:
    """The runtime chokepoint: ``_get_db()`` flags on-loop entry."""

    @pytest.mark.asyncio
    async def test_on_loop_get_db_raises_under_strict(self, monkeypatch):
        monkeypatch.setenv("KIROCREW_STRICT_ON_LOOP_PERSIST", "1")
        with pytest.raises(OnLoopDBError):
            _get_db()

    def test_off_loop_get_db_allowed_under_strict(self, monkeypatch):
        """No running loop (worker thread / executor / CLI) is the sanctioned
        path — strict mode must not flag it."""
        monkeypatch.setenv("KIROCREW_STRICT_ON_LOOP_PERSIST", "1")
        conn = _get_db()
        try:
            assert conn.execute("SELECT 1").fetchone()[0] == 1
        finally:
            conn.close()

    @pytest.mark.asyncio
    async def test_on_loop_get_db_warns_in_production_mode(self, monkeypatch, caplog):
        """Strict off (production): the on-loop entry proceeds but logs loudly,
        so a mis-wired call-site is never silent."""
        monkeypatch.setenv("KIROCREW_STRICT_ON_LOOP_PERSIST", "0")
        monkeypatch.setattr(h, "_on_loop_db_warn_last", 0.0)  # reset throttle window
        with caplog.at_level("WARNING", logger=h.logger.name):
            conn = _get_db()
            conn.close()
        assert any("event loop" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_on_loop_warning_is_throttled(self, monkeypatch, caplog):
        monkeypatch.setenv("KIROCREW_STRICT_ON_LOOP_PERSIST", "0")
        monkeypatch.setattr(h, "_on_loop_db_warn_last", 0.0)
        with caplog.at_level("WARNING", logger=h.logger.name):
            for _ in range(3):
                conn = _get_db()
                conn.close()
        assert sum("event loop" in r.message for r in caplog.records) == 1

    def test_get_db_enters_the_guard(self):
        """Mutation guard: removing the discipline check from ``_get_db``
        silently disarms every other protection here — pin the call."""
        tree = ast.parse(inspect.getsource(h._get_db))
        fn = tree.body[0]
        calls = [
            n.func.id
            for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        assert "_check_on_loop_db_discipline" in calls


# Functions that open (or transitively open) the campaigns DB. A direct call
# to any of these inside an ``async def`` in handlers.py runs the 30s busy
# timeout on the event loop. Extend this set when adding a new sync DB helper.
_DB_TOUCHING_FNS = frozenset(
    {
        "_get_db",
        "update_campaign_status",
        "delete_campaign",
        "create_campaign",
        "get_campaign",
        "list_campaigns",
        "validate_campaign",
        "_campaign_execution_mode",
        "_should_finalize",
        "_ingest_emergent_questions",
        "_activate_emergent",
        "_advance_exploration",
        "_settle_cycle_advance",
        "_fetch_running_campaigns",
        "_set_total_cycles",
    }
)


class TestStaticRatchet:
    def test_no_async_def_calls_db_functions_directly(self):
        """AST ratchet: every DB touch from async code must be offloaded.

        Enforced shape: inside an ``async def``, a DB-touching function may
        only appear as an ARGUMENT to ``asyncio.to_thread`` /
        ``run_in_executor`` — never called directly. A nested sync ``def``
        whose body touches the DB is the other offload pattern; it must
        itself be passed to ``to_thread``/``run_in_executor`` in the
        enclosing async def, and a direct in-line call to it (``row =
        _read_row()``) is flagged, since that re-runs the 30s busy wait on
        the loop while staying invisible to a name-based scan.
        """
        src = Path(inspect.getsourcefile(h)).read_text(encoding="utf-8")
        tree = ast.parse(src)
        violations: list[str] = []

        def _body_touches_db(fn: ast.FunctionDef) -> bool:
            for n in ast.walk(fn):
                if (
                    isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name)
                    and n.func.id in _DB_TOUCHING_FNS
                ):
                    return True
            return False

        def _is_offload_call(n: ast.Call) -> bool:
            return isinstance(n.func, ast.Attribute) and n.func.attr in (
                "to_thread",
                "run_in_executor",
            )

        def scan(node: ast.AsyncFunctionDef) -> None:
            db_closures = {
                child.name
                for child in ast.walk(node)
                if isinstance(child, ast.FunctionDef) and _body_touches_db(child)
            }
            offloaded: set[str] = set()
            flagged = _DB_TOUCHING_FNS | db_closures
            stack = list(ast.iter_child_nodes(node))
            while stack:
                n = stack.pop()
                if isinstance(n, ast.FunctionDef):
                    continue  # nested sync helper body runs off-loop when offloaded
                if isinstance(n, ast.Call):
                    if _is_offload_call(n):
                        offloaded.update(
                            a.id for a in n.args if isinstance(a, ast.Name) and a.id in flagged
                        )
                    elif isinstance(n.func, ast.Name) and n.func.id in flagged:
                        violations.append(f"{node.name}:{n.lineno} calls {n.func.id}() on the loop")
                stack.extend(ast.iter_child_nodes(n))
            for name in sorted(db_closures - offloaded):
                violations.append(
                    f"{node.name}: nested DB helper {name}() is defined but never "
                    "passed to asyncio.to_thread / run_in_executor"
                )

        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                scan(node)
        assert not violations, (
            "direct campaigns-DB call(s) on the event loop (offload via "
            "asyncio.to_thread / run_in_executor):\n" + "\n".join(violations)
        )


class TestContention:
    @pytest.fixture
    def app(self, tmp_path: Path):
        @web.middleware
        async def _inject_user(request, handler):
            request["user"] = "test-user"
            return await handler(request)

        a = web.Application(middlewares=[_inject_user])
        register_routes(a)
        return a

    @pytest.mark.asyncio
    async def test_held_write_lock_stalls_handler_not_heartbeat(self, app, tmp_path: Path):
        """A write lock held on the campaigns DB must stall only the request
        that needs the lock — never the event loop. This is the production
        failure shape: the watchdog writes every cycle, a user clicks Pause
        mid-write, and before the fix the handler's 30s busy wait ran ON the
        loop, silencing the gateway heartbeat past the watchdog kill budget.
        """
        async with TestClient(TestServer(app)) as c:
            cr = await c.post(
                "/api/apps/auto-research/campaigns",
                json={"question": "How do teams handle rate limiting?", "sources": ["web"]},
            )
            assert cr.status == 201
            cid = (await cr.json())["id"]
            # Pause is only legal from RUNNING.
            await asyncio.to_thread(update_campaign_status, cid, CampaignStatus.RUNNING)

            # Hold the campaigns-DB write lock like a mid-write watchdog cycle.
            blocker = sqlite3.connect(str(tmp_path / "test.db"))
            blocker.execute("BEGIN IMMEDIATE")

            ticks = 0

            async def heartbeat() -> None:
                nonlocal ticks
                while True:
                    ticks += 1
                    await asyncio.sleep(0.02)

            hb = asyncio.create_task(heartbeat())
            req = asyncio.create_task(
                c.patch(f"/api/apps/auto-research/campaigns/{cid}", json={"action": "pause"})
            )
            try:
                await asyncio.sleep(0.6)
                # The handler is genuinely blocked on the contended write...
                assert not req.done(), "handler finished despite a held write lock"
                # ...while the event loop stayed live (~30 ticks expected; >=5
                # is a generous slow-CI floor — an on-loop 30s busy wait yields
                # 0-1 because this sleep itself cannot run either).
                assert ticks >= 5, f"event loop starved during contended DB write (ticks={ticks})"
            finally:
                blocker.rollback()
                blocker.close()
                hb.cancel()
            resp = await req
            assert resp.status == 200
            assert (await resp.json())["status"] == CampaignStatus.PAUSED


class TestOffloadRaces:
    """The offload removes the event loop's run-to-completion serialization,
    so the check-then-act and read-modify-write sequences that used to be
    atomic-by-construction must now be atomic in the database."""

    @pytest.fixture
    def app(self, tmp_path: Path):
        @web.middleware
        async def _inject_user(request, handler):
            request["user"] = "test-user"
            return await handler(request)

        a = web.Application(middlewares=[_inject_user])
        register_routes(a)
        return a

    def test_allowed_current_rejects_wrong_source_state(self):
        c = create_campaign({"question": "How do teams handle rate limiting?", "sources": ["web"]})
        cid = c["id"]
        # READY is not a legal 'pause' source.
        res = update_campaign_status(
            cid, CampaignStatus.PAUSED, allowed_current={CampaignStatus.RUNNING}
        )
        assert res.get("code") == "invalid_state"
        assert res["current_status"] == CampaignStatus.READY
        # Nothing was written.
        assert get_campaign(cid)["status"] == CampaignStatus.READY
        # The matching source state transitions normally.
        res = update_campaign_status(
            cid, CampaignStatus.RUNNING, allowed_current={CampaignStatus.READY}
        )
        assert res == {"id": cid, "status": CampaignStatus.RUNNING}

    @pytest.mark.asyncio
    async def test_concurrent_start_launches_exactly_once(self, app):
        """Two racing start requests: exactly one wins the atomic conditional
        transition; the loser gets 409 instead of relaunching a duplicate
        worker (before the fix both could observe READY across the thread
        hop)."""
        async with TestClient(TestServer(app)) as c:
            cr = await c.post(
                "/api/apps/auto-research/campaigns",
                json={"question": "How do teams handle rate limiting?", "sources": ["web"]},
            )
            cid = (await cr.json())["id"]
            r1, r2 = await asyncio.gather(
                c.patch(f"/api/apps/auto-research/campaigns/{cid}", json={"action": "start"}),
                c.patch(f"/api/apps/auto-research/campaigns/{cid}", json={"action": "start"}),
            )
            assert sorted([r1.status, r2.status]) == [200, 409]

    @pytest.mark.asyncio
    async def test_concurrent_add_question_loses_nothing(self, app):
        """N concurrent appends must all land: the RMW takes the write lock
        BEFORE the read, so whole-list replacements serialize instead of
        overwriting each other."""
        async with TestClient(TestServer(app)) as c:
            cr = await c.post(
                "/api/apps/auto-research/campaigns",
                json={"question": "How do teams handle rate limiting?", "sources": ["web"]},
            )
            cid = (await cr.json())["id"]
            n = 12
            responses = await asyncio.gather(
                *(
                    c.post(
                        f"/api/apps/auto-research/campaigns/{cid}/questions",
                        json={"text": f"question number {i}"},
                    )
                    for i in range(n)
                )
            )
            assert all(r.status == 200 for r in responses)
            final = await asyncio.to_thread(get_campaign, cid)
            texts = {q["text"] for q in json.loads(final["sub_questions"])}
            missing = {f"question number {i}" for i in range(n)} - texts
            assert not missing, f"lost concurrent sub-question appends: {sorted(missing)}"

    @pytest.mark.parametrize(
        "user_state",
        [CampaignStatus.STOPPED, CampaignStatus.PAUSED],
    )
    def test_settle_suppresses_terminal_event_when_transition_rejected(
        self, tmp_path: Path, user_state
    ):
        """A user action landing before the watchdog's settle (Stop OR Pause —
        the settle observed RUNNING, so any moved row wins) must make the
        settle's terminal write a refused no-op with no terminal SSE event."""
        c = create_campaign(
            {
                "question": "How do teams handle rate limiting?",
                "sources": ["web"],
                "max_cycles": 1,
            }
        )
        cid = c["id"]
        if user_state == CampaignStatus.PAUSED:
            update_campaign_status(cid, CampaignStatus.RUNNING)
        gen = (get_campaign(cid) or {}).get("started_at")
        update_campaign_status(cid, user_state)
        # count >= max_cycles would normally yield "complete"; the moved row
        # must suppress both the write and the event.
        terminal = h._settle_cycle_advance(cid, {"cycle": 1}, 1, 1, gen)
        assert terminal is None
        assert get_campaign(cid)["status"] == user_state

    def test_settle_refuses_a_restarted_run_with_matching_status(self, tmp_path: Path):
        """The ABA case: pause+resume while the settle thread was deciding.
        The row is RUNNING again — same status the settle observed — but it is
        a NEW run; the started_at generation fence must refuse the stale
        terminal write instead of completing (and tearing down) the fresh
        run."""
        c = create_campaign(
            {
                "question": "How do teams handle rate limiting?",
                "sources": ["web"],
                "max_cycles": 1,
            }
        )
        cid = c["id"]
        update_campaign_status(cid, CampaignStatus.RUNNING)
        old_gen = get_campaign(cid)["started_at"]
        update_campaign_status(cid, CampaignStatus.PAUSED)
        time.sleep(0.01)  # ensure the resume mints a distinct started_at
        update_campaign_status(cid, CampaignStatus.RUNNING)
        new_gen = get_campaign(cid)["started_at"]
        assert new_gen != old_gen
        terminal = h._settle_cycle_advance(cid, {"cycle": 1}, 1, 1, old_gen)
        assert terminal is None
        assert get_campaign(cid)["status"] == CampaignStatus.RUNNING

    def test_stale_generation_is_refused_with_a_typed_code(self, tmp_path: Path):
        c = create_campaign({"question": "How do teams handle rate limiting?", "sources": ["web"]})
        cid = c["id"]
        update_campaign_status(cid, CampaignStatus.RUNNING)
        old_gen = get_campaign(cid)["started_at"]
        update_campaign_status(cid, CampaignStatus.PAUSED)
        time.sleep(0.01)
        update_campaign_status(cid, CampaignStatus.RUNNING)
        res = update_campaign_status(
            cid,
            CampaignStatus.COMPLETE,
            allowed_current={CampaignStatus.RUNNING},
            expected_started_at=old_gen,
        )
        assert res.get("code") == "stale_generation"
        assert get_campaign(cid)["status"] == CampaignStatus.RUNNING
        # The matching generation transitions normally.
        cur_gen = get_campaign(cid)["started_at"]
        res = update_campaign_status(
            cid,
            CampaignStatus.COMPLETE,
            allowed_current={CampaignStatus.RUNNING},
            expected_started_at=cur_gen,
        )
        assert res == {"id": cid, "status": CampaignStatus.COMPLETE}
