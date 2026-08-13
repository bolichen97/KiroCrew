"""Tests for perpetual agents: CronSchedule kind='self' + agent_sleep.

RFC rev 3 Phase 1 floor items 1/4/5: the code-owned §7 contract preamble with
the ranking step, agent_sleep's wake-sooner half, and the §9 inheritance
decisions. Each §9 row pinned here is a path that would otherwise silently
kill or distort an agent nobody is watching.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from kiro_crew.cron import (
    _AUTO_PAUSE_THRESHOLD,
    _AUTO_PAUSE_THRESHOLD_SELF,
    _MIN_INTERVAL_SECS,
    _SELF_CONTRACT_PREAMBLE,
    CronJob,
    CronSchedule,
    CronService,
    build_cron_session_context,
    compute_next_run_ts,
    format_schedule,
)


def _svc(tmp_path: Path) -> CronService:
    svc = CronService(base_dir=tmp_path)
    svc._load()
    return svc


#: The agent id used throughout the shell-gate cases, and the session key of the
#: agent that OWNS it. Round 27 owner-scoped the journal allowance, so both the
#: allowed and the refused cases are asserted as that owner acting: a refusal
#: proven only by the ABSENCE of identity would pass for the wrong reason.
_OWNER_AGENT_ID = "ab12cd34"
_OWNER_SESSION_KEY = f"cron:{_OWNER_AGENT_ID}"

#: Whether this platform can open a file relative to a directory fd. Round 20
#: retired the no-``dir_fd`` fallback and made the life-context reader FAIL
#: CLOSED instead, because the fallback could not refuse a symlinked component.
#: The documented cost is that a perpetual agent on such a platform (Windows)
#: gets the §7 preamble and the operator message but no LIFE.md/JOURNAL.md.
#:
#: Tests that assert life-context CONTENT therefore cannot run there — the
#: content is deliberately absent. They are gated on this flag, and
#: :class:`TestLifeContextWithoutDirFd` asserts the fail-closed contract itself
#: so the platform is covered by an assertion rather than merely skipped.
_HAS_DIR_FD = os.open in getattr(os, "supports_dir_fd", set())
_needs_dir_fd = pytest.mark.skipif(
    not _HAS_DIR_FD, reason="life-context reads fail closed without dir_fd support (round 20)"
)


def _add_self(svc: CronService, name: str = "warden", every: int = 3600) -> CronJob:
    # The operator session key mirrors what the MCP tool passes after its allowlist
    # decides the caller is an operator surface (GPT round-23). A test that
    # omitted it would be exercising a path the product refuses.
    return svc.add_job(
        name=name,
        message="pursue the goal",
        every_secs=every,
        perpetual=True,
        operator_session_key="dashboard:main",
    )


class TestSelfScheduleCreation:
    def test_perpetual_requires_operator_authorization(self, tmp_path: Path) -> None:
        """GPT round-23: the operator-only rule lived ONLY at the MCP tool, so
        the invariant was true by convention of a single caller rather than
        enforced by the owner of the write. Now checked where the job is built,
        keyword-only and default-false so no existing caller keeps legacy status.

        This does not pretend to stop an agent that can already run arbitrary
        in-process Python; it stops the invariant living in exactly one place.
        """
        svc = _svc(tmp_path)
        with pytest.raises(ValueError, match="operator session key"):
            svc.add_job(name="w", message="m", every_secs=3600, perpetual=True)
        # GPT round-42: the layer now VALIDATES a claimed identity instead of
        # trusting a caller-computed boolean. An automation identity is refused
        # even though the caller supplied one.
        for forged in ("cron:job1", "subagent:x", "webhook:y", "heartbeat:z", "taskrunner:t"):
            with pytest.raises(ValueError, match="operator session key"):
                svc.add_job(
                    name="w",
                    message="m",
                    every_secs=3600,
                    perpetual=True,
                    operator_session_key=forged,
                )
        # Non-perpetual jobs are unaffected — no caller has to opt in for those.
        plain = svc.add_job(name="p", message="m", every_secs=3600)
        assert plain.schedule.kind == "every"

    def test_perpetual_creates_kind_self(self, tmp_path: Path) -> None:
        job = _add_self(_svc(tmp_path))
        assert job.schedule.kind == "self"
        assert job.schedule.every_secs == 3600
        assert job.next_wake_ts is None

    def test_perpetual_requires_every(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="every_secs"):
            _svc(tmp_path).add_job(
                name="w",
                message="m",
                at_ts=time.time() + 60,
                perpetual=True,
                operator_session_key="dashboard:main",
            )

    def test_perpetual_refuses_delete_after_run(self, tmp_path: Path) -> None:
        """§9: one-shot semantics are refused at validation."""
        with pytest.raises(ValueError, match="delete_after_run"):
            _svc(tmp_path).add_job(
                name="w",
                message="m",
                every_secs=3600,
                perpetual=True,
                delete_after_run=True,
                operator_session_key="dashboard:main",
            )

    def test_perpetual_forces_strict_schedule_and_persistence(self, tmp_path: Path) -> None:
        """§9: jitter off (strict_schedule), continuity on (persistent_session)."""
        job = _svc(tmp_path).add_job(
            name="w", message="m", every_secs=3600, perpetual=True, operator_session_key="dashboard:main",
            strict_schedule=False, persistent_session=False,
        )
        assert job.strict_schedule is True
        assert job.persistent_session is True

    def test_round_trips_through_store(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "did a thing", "next thing")
        svc2 = _svc(tmp_path)
        got = svc2.list_jobs()[0]
        assert got.schedule.kind == "self"
        assert got.next_wake_ts is not None
        assert "did: did a thing" in got.last_sleep_record

    def test_format_schedule(self) -> None:
        assert "self-scheduled" in format_schedule(CronSchedule(kind="self", every_secs=3600))


class TestSelfNextRun:
    def test_fallback_is_operator_ceiling(self, tmp_path: Path) -> None:
        """No agent choice -> behaves like 'every' (the ceiling)."""
        job = _add_self(_svc(tmp_path))
        job.last_run_ts = 1000.0
        assert compute_next_run_ts(job, now=1100.0) == 1000.0 + 3600

    def test_agent_choice_wins(self, tmp_path: Path) -> None:
        job = _add_self(_svc(tmp_path))
        job.last_run_ts = 1000.0
        job.next_wake_ts = 1600.0
        assert compute_next_run_ts(job, now=1100.0) == 1600.0

    def test_missed_wake_fires_on_recovery(self, tmp_path: Path) -> None:
        """A deadline that passed while the host was down fires NOW, not one
        interval later — the property that made cron the host."""
        job = _add_self(_svc(tmp_path))
        job.next_wake_ts = 1000.0
        assert compute_next_run_ts(job, now=5000.0) == 5000.0


class TestAgentSleep:
    def test_records_wake_and_result(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        t0 = time.time()
        got = svc.record_agent_sleep(job.id, 600, "fixed the flake", "verify at population level")
        assert got.next_wake_ts is not None
        assert t0 + 595 <= got.next_wake_ts <= t0 + 605
        assert "did: fixed the flake" in got.last_sleep_record
        assert "next: verify at population level" in got.last_sleep_record

    def test_wake_sooner_allowed_sleep_longer_clamped(self, tmp_path: Path) -> None:
        """The wake-sooner half: earlier than the ceiling is allowed, past it
        is clamped TO the ceiling (RFC rev 3: sleep-longer is §4 config, not
        agent-chosen distant deadlines)."""
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        t0 = time.time()
        got = svc.record_agent_sleep(job.id, 86400, "idle", "")
        assert got.next_wake_ts is not None
        assert got.next_wake_ts <= t0 + 3600 + 5

    def test_floor_clamped(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        t0 = time.time()
        got = svc.record_agent_sleep(job.id, 1, "quick continue", "")
        assert got.next_wake_ts is not None
        assert got.next_wake_ts >= t0 + _MIN_INTERVAL_SECS - 5

    def test_rejected_for_non_self_jobs(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = svc.add_job(name="plain", message="m", every_secs=3600)
        with pytest.raises(ValueError, match="kind='self'"):
            svc.record_agent_sleep(job.id, 600, "did", "")

    def test_unknown_job(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            _svc(tmp_path).record_agent_sleep("deadbeef", 600, "did", "")


class TestConsumeOnFire:
    def test_consume_clears_matching_deadline(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "did", "")
        target = svc.list_jobs()[0]
        assert target.next_wake_ts is not None
        svc._consume_self_wake_locked(target)
        assert target.next_wake_ts is None
        svc2 = _svc(tmp_path)
        assert svc2.list_jobs()[0].next_wake_ts is None

    def test_consume_preserves_newer_choice(self, tmp_path: Path) -> None:
        """An agent_sleep landing during the run must survive the clear."""
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "did", "")
        fired = svc.list_jobs()[0]
        stale = CronJob(id=fired.id, name=fired.name, message=fired.message,
                        schedule=fired.schedule)
        stale.next_wake_ts = (fired.next_wake_ts or 0) - 100  # a DIFFERENT value
        svc._consume_self_wake_locked(stale)
        # Disk value differed from what this fire consumed -> preserved.
        assert svc.list_jobs()[0].next_wake_ts is not None


class TestSelfPromptAssembly:
    def test_contract_preamble_prepended(self, tmp_path: Path) -> None:
        job = _add_self(_svc(tmp_path))
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            key, prompt = build_cron_session_context(job)
        assert key == f"cron:{job.id}"
        assert prompt.startswith("[Perpetual agent contract]")
        assert "RANK FIRST" in prompt
        assert prompt.rstrip().endswith("pursue the goal")

    @_needs_dir_fd
    def test_life_and_journal_included_when_present(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        base = tmp_path / "agents" / job.id
        base.mkdir(parents=True)
        (base / "LIFE.md").write_text("## 1. The goal\nKeep CI trustworthy.\n", encoding="utf-8")
        (base / "JOURNAL.md").write_text(
            "\n".join(f"line {i}" for i in range(50)) + "\n", encoding="utf-8"
        )
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(job)
        assert "Keep CI trustworthy." in prompt
        assert "line 49" in prompt
        assert "line 0" not in prompt  # tail only

    def test_missing_life_dir_degrades_gracefully(self, tmp_path: Path) -> None:
        job = _add_self(_svc(tmp_path))
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "nope"):
            _, prompt = build_cron_session_context(job)
        assert "[Perpetual agent contract]" in prompt

    @_needs_dir_fd
    def test_life_md_capped(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        base = tmp_path / "agents" / job.id
        base.mkdir(parents=True)
        (base / "LIFE.md").write_text("x" * 50_000, encoding="utf-8")
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(job)
        assert "[truncated at cap]" in prompt
        assert len(prompt) < 40_000

    def test_no_idle_punishment_language(self) -> None:
        """§7: the preamble must never claim idle will be refused/punished —
        that instruction is what produces invented work."""
        low = _SELF_CONTRACT_PREAMBLE.lower()
        assert "honest idle is a legitimate outcome" in low
        for banned in ("will be refused", "punish", "must produce"):
            assert banned not in low.replace("never punished", "")

    def test_plain_jobs_unchanged(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = svc.add_job(name="plain", message="hello", every_secs=3600)
        _, prompt = build_cron_session_context(job)
        assert "[Perpetual agent contract]" not in prompt


class TestSelfAutoPause:
    def test_higher_threshold_for_self(self, tmp_path: Path) -> None:
        """§9: a self job survives the ordinary threshold and pauses only at
        the raised one — it must never die quietly on an ordinary bad day."""
        job = _add_self(_svc(tmp_path))
        for _ in range(_AUTO_PAUSE_THRESHOLD):
            job.record_failure()
        assert job.auto_paused is False  # survived the ordinary threshold
        for _ in range(_AUTO_PAUSE_THRESHOLD_SELF - _AUTO_PAUSE_THRESHOLD):
            job.record_failure()
        assert job.auto_paused is True

    def test_plain_jobs_keep_ordinary_threshold(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = svc.add_job(name="plain", message="m", every_secs=3600)
        for _ in range(_AUTO_PAUSE_THRESHOLD):
            job.record_failure()
        assert job.auto_paused is True


class TestSelfIsDue:
    """GPT round-1 F5: _is_due must support kind='self' or nothing ever fires."""

    def test_due_when_agent_deadline_passed(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        job.next_wake_ts = 1000.0
        assert CronService._is_due(job, now=1001.0) is True
        assert CronService._is_due(job, now=999.0) is False

    def test_fallback_ceiling_when_no_choice(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        job.last_run_ts = 1000.0
        assert CronService._is_due(job, now=1000.0 + 3599) is False
        assert CronService._is_due(job, now=1000.0 + 3601) is True


class TestLifeContextSafety:
    """GPT round-1 F1: the job name must not escape the agents directory."""

    @pytest.mark.parametrize("bad", ["/tmp/private", "../outside", "a/../../b"])
    def test_hostile_names_cannot_select_files(self, tmp_path: Path, bad: str) -> None:
        """GPT round-4: the life dir is keyed by generated job.id, so a name
        — hostile or colliding with an existing agent — selects nothing."""
        svc = _svc(tmp_path)
        job = svc.add_job(
            name=bad,
            message="m",
            every_secs=3600,
            perpetual=True,
            operator_session_key="dashboard:main",
        )
        outside = tmp_path / "private"
        outside.mkdir()
        (outside / "LIFE.md").write_text("SECRET", encoding="utf-8")
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(job)
        assert "SECRET" not in prompt
        assert "[Perpetual agent contract]" in prompt

    def test_name_collision_cannot_steal_another_agents_life(self, tmp_path: Path) -> None:
        """A job named after an existing agent must NOT read that agent's
        LIFE.md — directories are keyed by id, not name."""
        svc = _svc(tmp_path)
        victim = _add_self(svc, name="warden")
        base = tmp_path / "agents" / victim.id
        base.mkdir(parents=True)
        (base / "LIFE.md").write_text("VICTIM GOAL", encoding="utf-8")
        impostor = _add_self(svc, name="warden")  # same NAME, different id
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(impostor)
        assert "VICTIM GOAL" not in prompt

    @_needs_dir_fd
    def test_reads_are_byte_bounded(self, tmp_path: Path) -> None:
        """A huge journal must not be read whole — only the tail cap."""
        from kiro_crew.cron import _JOURNAL_TAIL_CAP_BYTES, _read_tail_bytes

        big = tmp_path / "JOURNAL.md"
        big.write_text("x" * 5_000_000 + "\nlast line", encoding="utf-8")
        tail = _read_tail_bytes(big, _JOURNAL_TAIL_CAP_BYTES, tmp_path)
        assert tail is not None
        assert len(tail.encode("utf-8")) <= _JOURNAL_TAIL_CAP_BYTES
        assert tail.endswith("last line")


class TestSleepRecordSurvivesTurnMerge:
    """GPT round-1 F4: the sleep record must not be clobbered by the
    turn-completion merge (last_result belongs to the turn)."""

    def test_merge_preserves_sleep_record(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "the real record", "next step")
        # Simulate the gateway's turn-completion merge with a stale in-memory
        # snapshot whose last_result is the turn's own text.
        snapshot = svc.list_jobs()[0]
        snapshot.set_run_result("turn output text")
        svc._merge_job_result(snapshot)
        svc2 = _svc(tmp_path)
        got = svc2.list_jobs()[0]
        assert "the real record" in got.last_sleep_record
        assert got.last_result == "turn output text"

    def test_sleep_record_reaches_next_prompt(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "did the thing", "verify it")
        target = svc.list_jobs()[0]
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(target)
        assert "did: did the thing" in prompt
        assert "next: verify it" in prompt


class TestLifeContextSymlinkGuard:
    """GPT round-2: a symlinked LIFE.md must never pull outside bytes into
    the prompt — O_NOFOLLOW at the open plus a realpath containment check."""

    def test_symlinked_life_md_refused(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        secret = tmp_path / "id_rsa"
        secret.write_text("PRIVATE KEY BYTES", encoding="utf-8")
        base = tmp_path / "agents" / "warden"
        base.mkdir(parents=True)
        (base / "LIFE.md").symlink_to(secret)
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(job)
        assert "PRIVATE KEY BYTES" not in prompt
        assert "[Perpetual agent contract]" in prompt

    def test_symlinked_parent_dir_refused(self, tmp_path: Path) -> None:
        """A symlinked intermediate directory is refused because the walk opens
        every component with O_NOFOLLOW — it is never traversed, rather than
        being traversed and then compared (GPT round-15)."""
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "LIFE.md").write_text("OUTSIDE BYTES", encoding="utf-8")
        agents = tmp_path / "agents"
        agents.mkdir()
        (agents / job.id).symlink_to(outside, target_is_directory=True)
        with patch("kiro_crew.cron._agents_dir", return_value=agents):
            _, prompt = build_cron_session_context(job)
        assert "OUTSIDE BYTES" not in prompt

    def test_intermediate_symlink_inside_root_is_still_refused(
        self, tmp_path: Path
    ) -> None:
        """The case a containment COMPARISON cannot catch: the link target is
        itself inside the agents root, so realpath containment passes — only
        refusing to traverse the link at all rejects it. This is what makes the
        guard structural instead of a check that can go stale.

        Requires ``dir_fd`` support: the per-component ``openat`` walk is what
        refuses the traversal, and on a platform without it
        (``_open_inside_nofollow_no_dirfd``, i.e. Windows) this exact case is the
        documented residual rather than a regression — the fallback can only
        compare the resolved path, which lands inside the root here. Confirmed
        on CI: this assertion is the one that used to fail on the Windows shard.

        No longer platform-gated: since round 19 the no-``dir_fd`` path fails
        closed rather than falling back, so the refusal holds on EVERY platform
        and the Windows shard runs this assertion for real.
        """
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        agents = tmp_path / "agents"
        victim = agents / "victim"
        victim.mkdir(parents=True)
        (victim / "LIFE.md").write_text("VICTIM GOAL BYTES", encoding="utf-8")
        (agents / job.id).symlink_to(victim, target_is_directory=True)
        with patch("kiro_crew.cron._agents_dir", return_value=agents):
            _, prompt = build_cron_session_context(job)
        assert "VICTIM GOAL BYTES" not in prompt

    def test_no_dirfd_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GPT round-19 retired the realpath fallback instead of hardening it.

        Round 16 pinned its inability to refuse an inside-root link as a
        documented residual; that was the wrong call for a shipped default,
        because on Windows a ``mklink /J`` junction reaches the same state with
        no symlink privilege. The reader now refuses to ingest at all when the
        per-component walk is unavailable — an agent there runs with its
        contract preamble and operator message but no goal file, which beats
        ingesting a possibly-attacker-chosen one.
        """
        from kiro_crew.cron import _open_inside_nofollow

        monkeypatch.setattr(os, "supports_dir_fd", set())
        agents = tmp_path / "agents"
        (agents / "warden").mkdir(parents=True)
        (agents / "warden" / "LIFE.md").write_text("GOAL", encoding="utf-8")
        # Even a perfectly ordinary, link-free path is refused: the guarantee is
        # structural, so it cannot be granted selectively.
        assert _open_inside_nofollow(agents / "warden" / "LIFE.md", agents) is None

    def test_no_dirfd_degrades_the_prompt_without_killing_the_wake(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Failing closed must degrade, not raise: the contract preamble still
        reaches the agent, only the LIFE/JOURNAL sections are absent."""
        monkeypatch.setattr(os, "supports_dir_fd", set())
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        agents = tmp_path / "agents"
        (agents / job.id).mkdir(parents=True)
        (agents / job.id / "LIFE.md").write_text("GOAL BYTES", encoding="utf-8")
        with patch("kiro_crew.cron._agents_dir", return_value=agents):
            _, prompt = build_cron_session_context(job)
        assert "GOAL BYTES" not in prompt
        assert "[Perpetual agent contract]" in prompt

    # ── GPT round-18 ─────────────────────────────────────────────────────

    def test_replaced_agents_root_is_refused(self, tmp_path: Path) -> None:
        """The root was the one component exempted from O_NOFOLLOW, on a claim
        that turned out to be false: ``agents`` is NOT write-protected, so an
        agent can move it aside and put a link there. Now the data home above it
        keeps the exemption (an operator may legitimately link it) while
        ``agents`` itself is opened with O_NOFOLLOW."""
        from kiro_crew.cron import _open_inside_nofollow

        home = tmp_path / "crew"
        home.mkdir()
        outside = tmp_path / "outside"
        (outside / "warden").mkdir(parents=True)
        (outside / "warden" / "LIFE.md").write_text("ATTACKER GOAL", encoding="utf-8")
        agents = home / "agents"
        agents.symlink_to(outside, target_is_directory=True)
        assert _open_inside_nofollow(agents / "warden" / "LIFE.md", agents) is None

    def test_replaced_agents_root_is_refused_end_to_end(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        home = tmp_path / "crew"
        home.mkdir()
        outside = tmp_path / "outside"
        (outside / job.id).mkdir(parents=True)
        (outside / job.id / "LIFE.md").write_text("ATTACKER GOAL", encoding="utf-8")
        agents = home / "agents"
        agents.symlink_to(outside, target_is_directory=True)
        with patch("kiro_crew.cron._agents_dir", return_value=agents):
            _, prompt = build_cron_session_context(job)
        assert "ATTACKER GOAL" not in prompt

    def test_linked_root_refused_in_the_no_dirfd_path_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Trivially true now that the no-dir_fd path fails closed, but kept as
        the regression anchor: if someone reintroduces a fallback, this case
        (which a containment comparison cannot catch) must stay refused."""
        from kiro_crew.cron import _open_inside_nofollow

        monkeypatch.setattr(os, "supports_dir_fd", set())
        home = tmp_path / "crew"
        home.mkdir()
        outside = tmp_path / "outside"
        (outside / "warden").mkdir(parents=True)
        (outside / "warden" / "LIFE.md").write_text("ATTACKER GOAL", encoding="utf-8")
        agents = home / "agents"
        agents.symlink_to(outside, target_is_directory=True)
        assert _open_inside_nofollow(agents / "warden" / "LIFE.md", agents) is None

    @_needs_dir_fd
    def test_a_legitimately_linked_data_home_still_reads(self, tmp_path: Path) -> None:
        """The exemption that survives: the operator may link the DATA HOME."""
        from kiro_crew.cron import _open_inside_nofollow

        real_home = tmp_path / "real-crew"
        (real_home / "agents" / "warden").mkdir(parents=True)
        (real_home / "agents" / "warden" / "LIFE.md").write_text("GOAL", encoding="utf-8")
        linked_home = tmp_path / "crew"
        linked_home.symlink_to(real_home, target_is_directory=True)
        fd = _open_inside_nofollow(
            linked_home / "agents" / "warden" / "LIFE.md", linked_home / "agents"
        )
        assert fd is not None
        os.close(fd)

    def test_dotdot_segment_in_the_life_path_is_refused(self, tmp_path: Path) -> None:
        from kiro_crew.cron import _open_inside_nofollow
        agents = tmp_path / "agents"
        (agents / "warden").mkdir(parents=True)
        (agents / "warden" / "LIFE.md").write_text("x", encoding="utf-8")
        assert _open_inside_nofollow(agents / "warden" / ".." / "warden" / "LIFE.md", agents) is None
        assert _open_inside_nofollow(tmp_path / "elsewhere" / "LIFE.md", agents) is None

    @_needs_dir_fd
    def test_regular_files_still_read(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        base = tmp_path / "agents" / job.id
        base.mkdir(parents=True)
        (base / "LIFE.md").write_text("normal goal text", encoding="utf-8")
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(job)
        assert "normal goal text" in prompt


class TestRound3Fixes:
    """GPT round-3: FIFO refusal, contention propagation, last_run advance."""

    def test_fifo_life_md_refused(self, tmp_path: Path) -> None:
        """A FIFO at LIFE.md must not hang the open — refused via O_NONBLOCK
        + regular-file check."""
        import os as _os
        import sys

        if sys.platform == "win32":
            pytest.skip("mkfifo is POSIX-only")
        svc = _svc(tmp_path)
        job = _add_self(svc, name="warden")
        base = tmp_path / "agents" / job.id
        base.mkdir(parents=True)
        _os.mkfifo(base / "LIFE.md")
        with patch("kiro_crew.cron._agents_dir", return_value=tmp_path / "agents"):
            _, prompt = build_cron_session_context(job)  # must return, not hang
        assert "[Perpetual agent contract]" in prompt
        assert "[LIFE.md" not in prompt.replace("[LIFE.md truncated", "")

    def test_consume_propagates_store_busy(self, tmp_path: Path) -> None:
        """Contention must propagate — an in-memory-only clear would leave the
        past-due deadline live on disk and refire every tick."""
        from kiro_crew.cron import CronStoreBusy

        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "did", "")
        target = svc.list_jobs()[0]
        fired_value = target.next_wake_ts

        class _Busy:
            def __enter__(self):
                raise CronStoreBusy("contended")

            def __exit__(self, *a):
                return False

        with patch.object(svc, "_file_lock", return_value=_Busy()):
            with pytest.raises(CronStoreBusy):
                svc._consume_self_wake_locked(target)
        # In-memory value untouched on the failure path too.
        assert target.next_wake_ts == fired_value

    def test_self_last_run_advances_like_every(self, tmp_path: Path) -> None:
        """A completed self wake must advance last_run_ts so the fallback
        deadline moves forward even when agent_sleep was never called."""
        import asyncio as _aio

        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        job.last_run_ts = None

        async def _noop(_j: CronJob) -> None:
            return None

        svc._on_job = _noop
        svc._job_run_meta[job.id] = (1234.5, "scheduled")
        svc._executing.add(job.id)
        _aio.run(svc._run_job_isolated(job))
        assert job.last_run_ts == 1234.5


class TestSkippedWakeNotFinalized:
    """GPT round-4: a wake skipped on consumption contention must not be
    finalized — no last_run_ts advance, no phantom history row."""

    def test_contention_skip_leaves_run_state_untouched(self, tmp_path: Path) -> None:
        import asyncio as _aio

        from kiro_crew.cron import CronStoreBusy

        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "did", "")
        target = svc.list_jobs()[0]
        target.last_run_ts = None
        # GPT round-35: this scenario is a wake that FIRED and then hit
        # contention while being consumed, so the deadline must be PAST DUE. The
        # test previously left it 600s in the future and passed only because the
        # consume path was entered unconditionally — i.e. it depended on the very
        # bug round 35 fixed. A future deadline is no longer consumed at all.
        target.next_wake_ts = time.time() - 1
        ran = []

        async def _mark(_j: CronJob) -> None:
            ran.append(True)

        svc._on_job = _mark
        svc._job_run_meta[target.id] = (999.0, "scheduled")
        svc._executing.add(target.id)
        with patch.object(
            svc, "_consume_self_wake_locked", side_effect=CronStoreBusy("busy")
        ):
            _aio.run(svc._run_job_isolated(target))
        assert ran == []  # never executed
        assert target.last_run_ts is None  # not finalized as a run


class TestLifeMdWriteDeny:
    """GPT round-5: LIFE.md is agent-read-only — both tool gates hard-deny
    writes so a perpetual agent cannot self-modify its goal."""

    def test_edit_gate_denies_agents_life_md(self, tmp_path: Path) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        home = _P.home()
        life = home / ".kiro" / "crew" / "agents" / "abcd1234" / "LIFE.md"
        assert is_sensitive_write_path(str(life)) is True

    def test_edit_gate_allows_journal_md(self) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        home = _P.home()
        journal = home / ".kiro" / "crew" / "agents" / "abcd1234" / "JOURNAL.md"
        # Round 27: the journal exemption is owner-scoped, so it is asserted as
        # the agent that owns THIS directory.
        assert is_sensitive_write_path(str(journal), session_key="cron:abcd1234") is False
        # and refused for anyone else, including an unidentified caller
        assert is_sensitive_write_path(str(journal), session_key="cron:other") is True
        assert is_sensitive_write_path(str(journal)) is True

    def test_bash_gate_catches_life_md_write(self) -> None:
        from kiro_crew.security import _build_sensitive_regex

        rx = _build_sensitive_regex()
        assert rx.search('echo hacked > ~/.kiro/crew/agents/ab12cd34/LIFE.md')
        assert rx.search("tee $HOME/.kiro/crew/agents/x/LIFE.md")
        # JOURNAL.md writes stay allowed.
        assert not rx.search("echo entry >> ~/.kiro/crew/agents/ab12cd34/JOURNAL.md")

    # ── GPT round-6 ──────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # single-dot segment right before the leaf (the reported bypass)
            "echo hacked > ~/.kiro/crew/agents/ab12cd34/./LIFE.md",
            # dot segment inside the crew prefix
            "echo hacked > ~/.kiro/./crew/agents/ab12cd34/LIFE.md",
            # same-level down-up excursion re-entering the id segment
            "echo hacked > ~/.kiro/crew/agents/x/../x/LIFE.md",
            # excursion through the agents dir itself
            "tee $HOME/.kiro/crew/agents/./ab12cd34/LIFE.md",
        ],
    )
    def test_bash_gate_catches_dot_segment_spellings(self, cmd: str) -> None:
        from kiro_crew.security import _build_sensitive_regex

        assert _build_sensitive_regex().search(cmd), cmd

    def test_bash_gate_dot_segments_leave_journal_alone(self) -> None:
        from kiro_crew.security import _build_sensitive_regex

        rx = _build_sensitive_regex()
        assert not rx.search("echo e >> ~/.kiro/crew/agents/ab12cd34/./JOURNAL.md")

    def test_edit_gate_denies_life_md_under_kirocrew_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew.security import is_sensitive_write_path

        crew = tmp_path / "crew-home"
        life = crew / "agents" / "ab12cd34" / "LIFE.md"
        life.parent.mkdir(parents=True)
        life.write_text("goal", encoding="utf-8")
        monkeypatch.setenv("KIROCREW_HOME", str(crew))
        assert is_sensitive_write_path(str(life)) is True
        # JOURNAL.md in the same env-anchored dir stays writable for its OWNER
        # (round 27 owner-scoped the exemption).
        journal = life.parent / "JOURNAL.md"
        owner_key = f"cron:{life.parent.name}"
        assert is_sensitive_write_path(str(journal), session_key=owner_key) is False
        assert is_sensitive_write_path(str(journal)) is True

    def test_bash_gate_catches_life_md_under_kirocrew_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew.security import _build_sensitive_regex

        crew = tmp_path / "crew-home"
        (crew / "agents" / "ab12cd34").mkdir(parents=True)
        monkeypatch.setenv("KIROCREW_HOME", str(crew))
        rx = _build_sensitive_regex()
        assert rx.search(f"echo hacked > {crew}/agents/ab12cd34/LIFE.md")
        assert rx.search(f"echo hacked > {crew}/agents/ab12cd34/./LIFE.md")
        assert not rx.search(f"echo e >> {crew}/agents/ab12cd34/JOURNAL.md")

    def test_full_bash_gate_denies_env_anchored_write_via_normalizer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The live gate (regex pass may be process-cached from before the env
        was set) still denies via the normalizer second-pass, because
        ``_is_agent_life_md`` consults ``KIROCREW_HOME`` at call time."""
        from kiro_crew.security import is_sensitive_write_path

        crew = tmp_path / "crew-home"
        life = crew / "agents" / "ab12cd34" / "LIFE.md"
        life.parent.mkdir(parents=True)
        life.write_text("goal", encoding="utf-8")
        monkeypatch.setenv("KIROCREW_HOME", str(crew))
        # dot-segment spelling resolves to the same guarded file
        dotted = crew / "agents" / "ab12cd34" / "." / "LIFE.md"
        assert is_sensitive_write_path(str(dotted)) is True

    # ── GPT round-7 ──────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # the reported bypass: cd into the agents dir, write relatively
            "cd ~/.kiro/crew/agents/ab12cd34 && echo hacked > LIFE.md",
            # other chained-relative verbs
            "cd $HOME/.kiro/crew/agents/x; cp /tmp/evil LIFE.md",
            "cd ~/.kirocrew/agents/ab12cd34 && tee LIFE.md < /tmp/evil",
            # dot-segment spelling of the cd target
            "cd ~/.kiro/crew/agents/./ab12cd34 && echo hacked > LIFE.md",
        ],
    )
    def test_bash_gate_catches_chained_relative_write(self, cmd: str) -> None:
        # The chain check lives in the gate function, not the compiled
        # alternation (kept out to avoid two whole-command scans per call).
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            r"cmd /c echo hacked > C:\Users\u\.kiro\crew\agents\ab12\LIFE.md",
            r"Set-Content $env:USERPROFILE\.kirocrew\agents\x\LIFE.md evil",
            r"echo hacked > %USERPROFILE%\.kiro\crew\agents\ab12\LIFE.md",
            # native cd + relative write chain
            r"cd C:\Users\u\.kiro\crew\agents\ab12 && echo hacked > LIFE.md",
        ],
    )
    def test_bash_gate_catches_windows_native_spellings(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    def test_chained_journal_work_stays_allowed(self) -> None:
        from kiro_crew.security import _build_sensitive_regex

        rx = _build_sensitive_regex()
        assert not rx.search(
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md"
        )

    def test_env_anchored_chain_caught_when_regex_built_with_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew.security import (
            _build_sensitive_regex,
            is_sensitive_bash_command,
        )

        crew = tmp_path / "crew-home"
        crew.mkdir()
        monkeypatch.setenv("KIROCREW_HOME", str(crew))
        # Rebuild so the env-anchored halves are recomputed for this HOME.
        _build_sensitive_regex()
        cmd = f"cd {crew}/agents/ab12cd34 && echo hacked > LIFE.md"
        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None

    # ── GPT round-8 ──────────────────────────────────────────────────────

    @pytest.mark.parametrize("leaf", ["life.md", "Life.md", "LIFE.MD"])
    def test_edit_gate_denies_recased_life_md(self, leaf: str) -> None:
        """On case-insensitive filesystems (macOS/Windows) ``life.md`` names
        the same goal file — the guard compares casefolded."""
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        home = _P.home()
        life = home / ".kiro" / "crew" / "agents" / "abcd1234" / leaf
        assert is_sensitive_write_path(str(life)) is True

    def test_edit_gate_recased_journal_stays_writable(self) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        home = _P.home()
        journal = home / ".kiro" / "crew" / "agents" / "abcd1234" / "journal.md"
        assert is_sensitive_write_path(str(journal), session_key="cron:abcd1234") is False

    def test_bash_gate_recased_spelling_matches(self) -> None:
        from kiro_crew.security import _build_sensitive_regex

        # the bash regex already compiles with re.IGNORECASE — pin it
        rx = _build_sensitive_regex()
        assert rx.search("echo hacked > ~/.kiro/crew/agents/ab12cd34/life.md")

    # ── GPT round-9 ──────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # quote-splice inside the leaf name (the reported bypass)
            "echo hacked > ~/.kiro/crew/agents/ab12cd34/LI''FE.md",
            'echo hacked > ~/.kiro/crew/agents/ab12cd34/"LIFE".md',
            'echo hacked > ~/.kiro/crew/agents/ab12cd34/L"IF"E.md',
            "tee ~/.kiro/crew/agents/x1/LI''FE.md < /tmp/x",
            # quote-splice on the chained-relative form
            "cd ~/.kiro/crew/agents/ab12cd34 && echo hacked > LI''FE.md",
            # unquoted forms must keep working
            "echo hacked > ~/.kiro/crew/agents/ab12cd34/LIFE.md",
        ],
    )
    def test_full_bash_gate_denies_quote_spliced_life_md(self, cmd: str) -> None:
        """The FULL gate (regex pass 1 + normalizer pass 2) must deny every
        shell-quoting spelling — the regex cannot see through quotes, so the
        normalizer pass is the layer that has to check the write-protected
        goal file, not only the read-blocked credential set."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo entry >> ~/.kiro/crew/agents/ab12cd34/JOURNAL.md",
            "echo entry >> ~/.kiro/crew/agents/ab12cd34/JOUR''NAL.md",
            "ls ~/.kiro/crew/agents",
            "cat README.md",
        ],
    )
    def test_full_bash_gate_leaves_journal_and_reads_alone(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    # ── GPT round-10 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # variable indirection removes the literal entirely
            'cd ~/.kiro/crew/agents/ab12cd34 && n=LIFE; echo hacked > "$n.md"',
            "cd ~/.kiro/crew/agents/ab12cd34 && f=LIFE.md; echo hacked > $f",
            'cd ~/.kiro/crew/agents/ab12cd34 && printf x > "${n}.md"',
            "cd ~/.kiro/crew/agents/ab12cd34 && tee $f < /tmp/evil",
            'echo hacked > ~/.kiro/crew/agents/ab12cd34/"$n".md',
            # command substitution is the same class
            "cd ~/.kiro/crew/agents/ab12cd34 && echo x > `basename LIFE.md`",
        ],
    )
    def test_variable_derived_write_in_agents_dir_is_refused(self, cmd: str) -> None:
        """No static layer can resolve a variable-derived target, so a write
        whose destination is variable-derived is refused when the command
        already names a crew agents directory. Fail closed: the caller can
        always spell the path literally."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # variable write targets ELSEWHERE stay allowed — the refusal is
            # scoped to the agents-directory conjunction
            "cd /tmp && f=out.txt; echo x > $f",
            "cd ~/Repos/proj && echo x > $OUT",
            "echo $HOME",
            # literal JOURNAL.md work in the agents dir stays allowed
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md",
        ],
    )
    def test_variable_write_scope_is_narrow(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd


class TestSelfInvariantsSurviveUpdate:
    """GPT round-11: the generic update path must not un-make a perpetual job.

    Each field here silently BREAKS the agent rather than erroring, which is
    why refusal beats coercion: a coerced update would report success for a
    change that did not happen.
    """

    def test_interval_change_keeps_kind_self(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        got = svc.update_job(job.id, every_secs=7200)
        assert got is not None
        assert got.schedule.kind == "self"
        assert got.schedule.every_secs == 7200

    def test_interval_change_leaves_agent_sleep_usable(self, tmp_path: Path) -> None:
        """The regression this guards: after an interval change the job used to
        become kind='every', and agent_sleep then refused it outright."""
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        svc.update_job(job.id, every_secs=7200)
        got = svc.record_agent_sleep(job.id, 600, "did", "next")
        assert got.next_wake_ts is not None

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"persistent_session": False},
            {"strict_schedule": False},
            {"delete_after_run": True},
        ],
    )
    def test_invariant_breaking_updates_are_refused(
        self, tmp_path: Path, kwargs: dict
    ) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        with pytest.raises(ValueError):
            svc.update_job(job.id, **kwargs)

    def test_refused_update_leaves_the_job_untouched(self, tmp_path: Path) -> None:
        """Validation runs before ANY field assignment, so a rejected update
        must not have applied the fields that came with it."""
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        with pytest.raises(ValueError):
            svc.update_job(job.id, name="renamed", persistent_session=False)
        got = svc.get_job(job.id)
        assert got is not None
        assert got.name == job.name
        assert got.persistent_session is True

    def test_enabling_the_invariants_is_still_allowed(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        got = svc.update_job(job.id, persistent_session=True, strict_schedule=True)
        assert got is not None
        assert got.persistent_session is True
        assert got.strict_schedule is True

    def test_plain_jobs_keep_generic_update_semantics(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = svc.add_job(name="plain", message="m", every_secs=3600)
        got = svc.update_job(job.id, every_secs=7200, persistent_session=False)
        assert got is not None
        assert got.schedule.kind == "every"
        assert got.persistent_session is False

    # ── GPT round-12 ─────────────────────────────────────────────────────

    def test_cron_expr_update_is_refused_on_self_job(self, tmp_path: Path) -> None:
        """The other route that converted the job away from kind='self'."""
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        with pytest.raises(ValueError):
            svc.update_job(job.id, cron_expr="0 9 * * MON-FRI")
        got = svc.get_job(job.id)
        assert got is not None
        assert got.schedule.kind == "self"

    def test_at_ts_update_is_refused_on_self_job(self, tmp_path: Path) -> None:
        """Refused LOUDLY rather than left as a silent no-op: this path ignores
        at_ts (no branch applies it), so update_job reported success while
        changing nothing — the same "operator believes the cadence moved"
        failure shape as a silent conversion."""
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        with pytest.raises(ValueError):
            svc.update_job(job.id, at_ts=time.time() + 9999)
        got = svc.get_job(job.id)
        assert got is not None
        assert got.schedule.kind == "self"
        assert got.schedule.every_secs == 3600

    def test_at_ts_still_works_on_plain_jobs(self, tmp_path: Path) -> None:
        """The refusal is scoped to perpetual jobs — a plain job keeps whatever
        generic semantics this path already had for at_ts."""
        svc = _svc(tmp_path)
        job = svc.add_job(name="plain", message="m", every_secs=3600)
        got = svc.update_job(job.id, at_ts=time.time() + 9999)
        assert got is not None

    def test_lowering_the_ceiling_clamps_a_stale_deadline(self, tmp_path: Path) -> None:
        """_is_due honours next_wake_ts first, so a deadline recorded under the
        OLD ceiling would keep the lowered ceiling from taking effect."""
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        svc.record_agent_sleep(job.id, 3500, "did", "next")
        before = svc.get_job(job.id)
        assert before is not None and before.next_wake_ts is not None
        base = before.last_run_ts or before.created_ts

        got = svc.update_job(job.id, every_secs=600)
        assert got is not None
        assert got.next_wake_ts is not None
        assert got.next_wake_ts <= base + 600 + 1

    def test_lowering_the_ceiling_keeps_an_earlier_deadline(self, tmp_path: Path) -> None:
        """The wake-sooner half must survive an unrelated ceiling change: a
        deadline already EARLIER than the new ceiling is left alone."""
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        svc.record_agent_sleep(job.id, 120, "did", "next")
        before = svc.get_job(job.id)
        assert before is not None and before.next_wake_ts is not None
        chosen = before.next_wake_ts

        got = svc.update_job(job.id, every_secs=600)
        assert got is not None
        assert got.next_wake_ts == chosen

    def test_raising_the_ceiling_leaves_the_deadline_alone(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc, every=3600)
        svc.record_agent_sleep(job.id, 1800, "did", "next")
        before = svc.get_job(job.id)
        assert before is not None
        chosen = before.next_wake_ts

        got = svc.update_job(job.id, every_secs=7200)
        assert got is not None
        assert got.next_wake_ts == chosen


class TestCronsStoreWriteProtected:
    """GPT round-11: the scheduler store is an input to an authorization
    decision — every scheduling invariant is enforced at the tool boundary and
    then persisted there, so an agent tool that could rewrite it authors a job
    the tools would have refused."""

    def test_edit_gate_denies_store_write(self) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        assert is_sensitive_write_path(str(_P.home() / ".kiro" / "crew" / "crons.json")) is True

    def test_store_stays_readable(self) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_path

        # write-protected, NOT read-blocked: `cron list` and the dashboard
        # render it constantly and it holds no secret.
        assert is_sensitive_path(str(_P.home() / ".kiro" / "crew" / "crons.json")) is False

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo x > ~/.kiro/crew/crons.json",
            "tee $HOME/.kiro/crew/crons.json < /tmp/evil",
            "cp /tmp/evil ~/.kirocrew/crons.json",
        ],
    )
    def test_bash_gate_denies_store_write(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    # ── GPT round-12 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # dot segment: the write-protected-leaf regex branch carries no
            # dot-segment tolerance, so the normalizer pass is what has to
            # catch these
            "echo x > ~/.kiro/crew/./crons.json",
            "echo x > ~/.kiro/./crew/crons.json",
            "tee ~/.kiro/crew/x/../crons.json < /tmp/evil",
            # quote splice
            "echo x > ~/.kiro/crew/crons''.json",
            # the same normalized coverage must hold for the OTHER
            # write-protected leaves, not just the store
            "echo x > ~/.kiro/crew/./config.json",
            "echo x > ~/.kiro/crew/apps/ops-mission-control/data/./rotation.yaml",
        ],
    )
    def test_normalized_spellings_of_write_protected_paths_are_denied(
        self, cmd: str
    ) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # unrelated writes elsewhere are untouched
            "echo x > /tmp/out.json",
            "cd /tmp && f=out.json; echo x > $f",
        ],
    )
    def test_write_protection_does_not_block_unrelated_writes(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_shell_reads_of_the_store_are_blocked_like_the_other_leaves(self) -> None:
        """Documented posture of _WRITE_PROTECTED_BASH_LEAVES: that branch is
        matched verb-INDEPENDENTLY so no write form can bypass it, which blocks
        shell READS of those leaves too. Harmless for this file (it holds no
        secret) and consistent with .data-home-ready / rotation.yaml: legitimate
        readers use the CLI or the read tool, not shell cat."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command("cat ~/.kiro/crew/crons.json") is not None

    def test_python_api_reads_are_unaffected(self) -> None:
        """is_sensitive_path is the READ gate — the store stays outside it, so
        the CLI, the dashboard and the read tool are unaffected."""
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_path

        assert is_sensitive_path(str(_P.home() / ".kiro" / "crew" / "crons.json")) is False

    # ── GPT round-13 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && printf '{}' > crons.json",
            "cd ~/.kiro/crew; echo x >> crons.json",
            "cd ~/.kirocrew && tee crons.json < /tmp/evil",
            "cd $HOME/.kiro/crew && cp /tmp/evil crons.json",
            "cd ~/.kiro/crew/apps/ops-mission-control/data && echo x > rotation.yaml",
            "cd ~/.kiro/crew && echo x > .data-home-ready",
        ],
    )
    def test_chained_relative_write_to_fenced_leaf_is_denied(self, cmd: str) -> None:
        """After a chained ``cd`` the leaf is a bare relative token, so neither
        a path-anchored branch nor the normalizer's resolved-path check can bind
        it to the crew home — the normalizer resolves against the agent's cwd,
        not against a ``cd`` earlier on the same line."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # reads in the crew home keep the posture their own branch defines
            "cd ~/.kiro/crew && cat config.json",
            "cd ~/.kiro/crew && ls -la",
            "cat ~/.kiro/crew/config.json",
            "sqlite3 ~/.kiro/crew/sessions.db .tables",
            # a same-named file elsewhere, and non-fenced writes in the crew home
            "cd /tmp && echo x > crons.json",
            "cd ~/.kiro/crew && echo x > /tmp/out.txt",
            "cd ~/Repos/proj && echo x > notes.md",
        ],
    )
    def test_chained_relative_check_stays_narrow(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_write_context_ignores_fd_duplication_and_input_redirects(self) -> None:
        """``2>&1`` redirects no file and ``<`` is a read, so neither may count
        as write context and turn a read into a refusal."""
        from kiro_crew.security import _command_has_write_context

        assert _command_has_write_context("cd ~/.kiro/crew && cat crons.json 2>&1") is False
        assert _command_has_write_context("wc -l < crons.json") is False
        assert _command_has_write_context("echo x > crons.json") is True
        assert _command_has_write_context("tee crons.json") is True

    # ── GPT round-14 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # shell terminators immediately after the leaf
            'echo "{}" > ~/.kiro/crew/crons.json;',
            'echo "{}" > ~/.kiro/crew/crons.json|tee /tmp/x',
            '(echo "{}" > ~/.kiro/crew/crons.json)',
            "echo x > ~/.kiro/crew/crons.json&",
            # the PRE-EXISTING fences carried the same gap
            "echo x > ~/.kiro/crew/.data-home-ready;",
            "echo x > ~/.kiro/crew/agents/ab12cd34/LIFE.md;",
            # and the chained-relative half
            "cd ~/.kiro/crew && printf '{}' > crons.json;",
            "cd ~/.kiro/crew && printf '{}' > crons.json)",
        ],
    )
    def test_shell_terminators_do_not_end_the_fence(self, cmd: str) -> None:
        """A path token can END at a shell control character, so the trailing
        boundary has to admit them — otherwise a single ``;`` walks past every
        branch that anchors on the leaf."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    def test_credential_paths_get_the_same_boundary(self) -> None:
        """The boundary is shared, so the credential fences gain the fix too."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command("cat ~/.aws/credentials;") is not None
        assert is_sensitive_bash_command("cat ~/.ssh/id_rsa|base64") is not None

    # ── GPT round-15 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize("ws", ["\t", "\n", "\x0b", "  "])
    def test_write_verbs_are_recognised_after_any_shell_whitespace(self, ws: str) -> None:
        """A shell word separator is not just U+0020, so the write-context test
        must not key on the space character."""
        from kiro_crew.security import _command_has_write_context

        assert _command_has_write_context(f"tee{ws}crons.json") is True

    def test_tab_separated_write_reaches_the_store_fence(self) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command("cd ~/.kiro/crew && tee\tcrons.json") is not None

    # ── GPT round-16 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # a redirect attached with no space ends the path token too
            "echo x > ~/.kiro/crew/crons.json>/tmp/out",
            "echo x > ~/.kiro/crew/crons.json<in",
            "echo x > ~/.kiro/crew/agents/ab12/LIFE.md>/tmp/out",
            # shared boundary, so the credential fences get it as well
            "cat ~/.aws/credentials>/tmp/leak",
        ],
    )
    def test_attached_redirect_does_not_end_the_fence(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            'cd ~/.kiro/crew && f=crons; : > "$f.json"',
            'cd ~/.kiro/crew && n=data-home-ready; echo x > ".$n"',
            "cd ~/.kirocrew && tee $f",
        ],
    )
    def test_variable_composed_leaf_in_crew_home_is_refused(self, cmd: str) -> None:
        """Same answer as the agents-directory case, through the same matcher:
        a variable-derived write target cannot be resolved statically, so inside
        a command that already names the crew home it is refused."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd /tmp && f=out; echo x > $f.json",
            "echo x > /tmp/a.json>/tmp/b",
            "cd ~/.kiro/crew && cat config.json",
        ],
    )
    def test_round16_additions_stay_narrow(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    # ── GPT round-19 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            # operating on the CONTAINER instead of the leaf
            "mv ~/.kiro/crew/agents ~/.kiro/crew/agents.bak",
            "mkdir ~/.kiro/crew/agents/ab12cd34",
            "mv /tmp/staged ~/.kiro/crew/agents/ab12cd34",
            "rmdir ~/.kiro/crew/agents/ab12cd34",
            # deletion is a write
            "rm ~/.kiro/crew/crons.json",
            "cd ~/.kiro/crew && rm crons.json",
            # the UNEXPANDED data-home variable is an anchor too
            'rm "$KIROCREW_HOME/crons.json"',
            "echo x > ${KIROCREW_HOME}/crons.json",
        ],
    )
    def test_container_and_deletion_spellings_are_refused(self, cmd: str) -> None:
        """Sixth spelling of one class: every earlier fence keyed on the leaf
        NAME, so operating on the directory that holds it reached the same
        effect without ever writing that name. The agents subtree is now an
        ALLOWLIST (JOURNAL.md only), which converges where a denylist of
        spellings could not."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "path_leaf,denied",
        [
            ("LIFE.md", True),
            ("life.md", True),
            ("NOTES.md", True),
            ("JOURNAL.md", False),
            ("journal.md", False),
        ],
    )
    def test_agents_subtree_allowlist_is_journal_only(
        self, path_leaf: str, denied: bool
    ) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        p = _P.home() / ".kiro" / "crew" / "agents" / "ab12cd34" / path_leaf
        assert (
            is_sensitive_write_path(str(p), session_key=_OWNER_SESSION_KEY) is denied
        ), path_leaf

    def test_agents_root_and_id_dir_are_write_protected(self) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        agents = _P.home() / ".kiro" / "crew" / "agents"
        assert is_sensitive_write_path(str(agents)) is True
        assert is_sensitive_write_path(str(agents / "ab12cd34")) is True

    @pytest.mark.parametrize(
        "cmd",
        [
            # the journal must stay appendable, including through a chained cd —
            # a navigation argument is not a write target
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md",
            "echo entry >> ~/.kiro/crew/agents/ab12cd34/JOURNAL.md",
            "ls ~/.kiro/crew/agents",
            # deletions elsewhere are untouched
            "rm /tmp/scratch.json",
            "cd /tmp && rm crons.json",
        ],
    )
    def test_round19_additions_stay_narrow(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_navigation_argument_is_not_a_write_target(self) -> None:
        """Positional, so a real write target later in the same command still
        counts: only the token immediately after cd/pushd is exempt."""
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command("cd /tmp && echo x > ~/.kiro/crew/crons.json")
            is not None
        )

    # ── GPT round-21 ─────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "cmd",
        [
            'cd ~/.kiro/crew && python -c \'open("crons.json","w").write("{}")\'',
            'cd ~/.kiro/crew && python3 -c \'import pathlib;pathlib.Path("crons.json").write_text("{}")\'',
            "cd ~/.kiro/crew && perl -e 'open(F,\">crons.json\")'",
            'cd ~/.kiro/crew && node -e \'require("fs").writeFileSync("crons.json","{}")\'',
            "cd ~/.kiro/crew && sh -c 'echo x > crons.json'",
            'cd ~/.kiro/crew/agents/ab12cd34 && python -c \'open("LIFE.md","w").write("x")\'',
            # round 22: a SCRIPT FILE is the same thing
            "cd ~/.kiro/crew && python /tmp/rewrite.py crons.json",
            "cd ~/.kiro/crew && python3 /tmp/x.py crons.json",
            "cd ~/.kiro/crew && node /tmp/x.js crons.json",
            "cd ~/.kiro/crew/agents/ab12cd34 && python /tmp/x.py LIFE.md",
        ],
    )
    def test_inline_interpreter_counts_as_write_context(self, cmd: str) -> None:
        """The leaf name and the crew home are both in the text here — only the
        write-context classifier failed, because an interpreter is neither a
        write verb nor a redirect. Deliberately NOT keyed on mutation calls
        inside the payload: a write can be spelled unboundedly many ways there,
        and enumerating them is the denylist this file has already lost to six
        times."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # an interpreter alone is not a refusal — it only matters where the
            # command also names the crew home or the agents subtree
            "cd /tmp && python -c 'open(\"out.json\",\"w\").write(\"{}\")'",
            "python -c 'print(1)'",
            "python /tmp/probe.py",
            "cd /tmp && python /tmp/x.py crons.json",
            "node_modules/.bin/vite build",
            "cd ~/Repos/proj && node -e 'require(\"fs\").writeFileSync(\"a.json\",\"1\")'",
            # and the pinned crew-home reads stay readable
            "cat ~/.kiro/crew/config.json",
            "sqlite3 ~/.kiro/crew/sessions.db .tables",
            # journal work is unaffected by the new write-context source
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md",
        ],
    )
    def test_round21_addition_stays_narrow(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_interpreter_write_context_covers_script_files_too(self) -> None:
        """Round 21 pinned the opposite of this, and round 22 reversed it.
        The earlier rule matched only the inline ``-c``/``-e`` form and asserted
        ``python /tmp/script.py`` was NOT write context. That was a distinction
        without a difference: a script file mutates exactly as well, and the
        argument naming the target sits in the command line either way
        (``cd ~/.kiro/crew && python /tmp/rewrite.py crons.json``). Where the
        program text lives says nothing about whether it writes, so the rule now
        keys on "an interpreter is running".
        """
        from kiro_crew.security import _command_has_write_context

        assert _command_has_write_context("python /tmp/script.py") is True
        assert _command_has_write_context("python -c 'x'") is True
        assert _command_has_write_context("/usr/bin/python3 -c 'x'") is True
        # A path segment that merely contains an interpreter name is not one.
        # Asserted against the interpreter matcher itself rather than the whole
        # helper: since round 33 an unrecognized executable IS write context, and
        # `node_modules/.bin/vite` is unrecognized — so the helper returning True
        # is correct for a DIFFERENT reason, and asserting False here would only
        # re-pin the old semantics. The original intent — `node_modules` must not
        # be mistaken for the `node` interpreter — is what is checked.
        from kiro_crew.security import _INLINE_INTERPRETER_RE

        assert _INLINE_INTERPRETER_RE.search("node_modules/.bin/vite build") is None
        assert _command_has_write_context("ls -la") is False


class TestAgentSleepGovernance:
    """GPT round-10: writing next_wake_ts IS a cron mutation, so the    capabilities.cron gate applies to agent_sleep as it does to cron_add.

    These go through the real ``_call_tool_inner``, which builds its OWN
    ``CronService(base_dir=config_dir())`` — so the job has to be created in
    that same store (conftest pins ``KIROCREW_HOME`` per test), not in a
    separately-constructed service.
    """

    @staticmethod
    def _handler_svc() -> Any:
        from kiro_crew.config.loader import config_dir
        from kiro_crew.cron import CronService

        return CronService(base_dir=config_dir())

    def test_denied_capability_refuses_and_leaves_deadline_untouched(
        self, tmp_path: Path
    ) -> None:
        import kiro_crew.mcp_cron as mc

        svc = self._handler_svc()
        job = _add_self(svc, every=3600)
        assert job.next_wake_ts is None

        with (
            patch.object(mc, "_resolve_session_key_strict", return_value=f"cron:{job.id}"),
            patch.object(
                mc,
                "_vet_cron_capability_governance",
                return_value="Error: cron scheduling blocked by governance policy: off",
            ),
        ):
            out = mc._call_tool_inner(
                "agent_sleep", {"next_wake_secs": 600, "did": "x", "next_intent": "y"}
            )

        assert "governance policy" in out, out
        # The refused call must not have persisted a deadline.
        assert self._handler_svc().get_job(job.id).next_wake_ts is None

    def test_permitted_capability_records_normally(self, tmp_path: Path) -> None:
        import kiro_crew.mcp_cron as mc

        svc = self._handler_svc()
        job = _add_self(svc, every=3600)

        with (
            patch.object(mc, "_resolve_session_key_strict", return_value=f"cron:{job.id}"),
            patch.object(mc, "_vet_cron_capability_governance", return_value=None),
        ):
            out = mc._call_tool_inner(
                "agent_sleep", {"next_wake_secs": 600, "did": "x", "next_intent": "y"}
            )

        assert "Recorded" in out, out
        assert self._handler_svc().get_job(job.id).next_wake_ts is not None

    def test_gate_is_keyed_to_the_calling_job(self, tmp_path: Path) -> None:
        """The SEL deny trail must name the job, not the generic vetting key."""
        import kiro_crew.mcp_cron as mc

        svc = self._handler_svc()
        job = _add_self(svc, every=3600)
        seen: list[str] = []

        def _spy(session_key: str | None = None) -> str | None:
            seen.append(session_key or "")
            return None

        with (
            patch.object(mc, "_resolve_session_key_strict", return_value=f"cron:{job.id}"),
            patch.object(mc, "_vet_cron_capability_governance", _spy),
        ):
            mc._call_tool_inner("agent_sleep", {"next_wake_secs": 600})

        assert seen == [f"cron:{job.id}"], seen


class TestPerpetualCreationAllowlist:
    """GPT round-5: perpetual creation is a POSITIVE operator allowlist —
    empty and automation identities are refused, not just cron:."""

    @pytest.mark.parametrize(
        "caller,allowed",
        [
            ("dashboard:abc123", True),
            ("slack:C1:169.1", True),
            # GPT round-7: every human messaging channel is an operator
            # surface, via the shared is_channel_session_key predicate.
            ("webex:room1", True),
            ("wecom:u1", True),
            ("teams:conv1", True),
            ("weixin:u1", True),
            ("whatsapp:u1", True),
            ("unified:kirocrew:dm:u1", True),
            ("discord:guild1:chan1", True),
            ("telegram:chat1", True),
            # legacy un-namespaced Slack thread_ts
            ("1785370133.085469", True),
            # automation identities stay refused
            ("cron:ab12cd34", False),
            ("subagent:xyz", False),
            ("webhook:h1", False),
            ("heartbeat:h1", False),
            ("taskrunner:t1", False),
            ("", False),
        ],
    )
    def test_caller_gating(self, tmp_path: Path, caller: str, allowed: bool) -> None:
        import kiro_crew.mcp_cron as mc

        svc = _svc(tmp_path)
        args = {
            "name": "w",
            "message": "goal",
            "every": 3600,
            "perpetual": True,
        }
        with (
            patch.object(mc, "_resolve_session_key_strict", return_value=caller),
            patch.object(mc, "_resolve_session_key", return_value=caller or "x"),
            patch.object(mc, "get_service", return_value=svc, create=True),
        ):
            # Route through the real handler if its service accessor matches;
            # otherwise call the inner tool with the svc patched in place.
            with patch.object(mc, "svc", svc, create=True):
                out = mc._call_tool_inner("cron_add", dict(args))
        if allowed:
            assert "Added job" in out, out
        else:
            assert "operator session" in out, out


class TestAgentsSubtreeRelativeWrites:
    """GPT round-23: the round-19 allowlist works on RESOLVED paths, so a bare
    relative target after a chained ``cd`` never reached it — the normalizer
    resolves it against the agent's cwd, not against the ``cd``. Ninth spelling
    of one class, handled in the conjunction that already existed.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew/agents && rm -rf ab12cd34 && mv /tmp/staged ab12cd34",
            "cd ~/.kiro/crew/agents && mkdir ab12cd34",
            "cd ~/.kiro/crew/agents && mv ab12cd34 ab12cd34.bak",
            "cd ~/.kiro/crew/agents && rmdir ab12cd34",
            "cd ~/.kirocrew/agents && cp -r /tmp/staged ab12cd34",
            "cd ~/.kiro/crew/agents/ab12cd34 && rm LIFE.md",
        ],
    )
    def test_relative_writes_under_agents_are_refused(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # the ONE allowed write in that subtree survives the new rule
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> journal.md",
            "echo entry >> ~/.kiro/crew/agents/ab12cd34/JOURNAL.md",
            # reads keep the posture their own branches define
            "ls ~/.kiro/crew/agents",
            "cd ~/.kiro/crew/agents && ls -la",
            # and an identically-named directory elsewhere is untouched
            "cd /tmp/agents && mkdir ab12cd34",
        ],
    )
    def test_journal_and_reads_survive(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_journal_allowance_does_not_launder_a_second_target(self) -> None:
        """Naming JOURNAL.md must not buy a write to something else in the same
        command — the allowance requires the journal to be the only fenced name."""
        from kiro_crew.security import is_sensitive_bash_command

        cmd = (
            "cd ~/.kiro/crew/agents/ab12cd34 && echo x > LIFE.md && echo y >> JOURNAL.md"
        )
        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None


class TestJournalAllowanceIsPositive:
    """GPT round-24: the round-23 allowance asked "a journal is mentioned AND
    LIFE.md is not" — a denylist nested inside an allowlist. A glob names no
    fenced leaf at all, so ``rm -rf -- * && echo e >> JOURNAL.md`` sailed
    through it. The allowance is now positive: no write verb anywhere, and every
    redirect target is a journal.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            # the finding, verbatim in shape
            "cd ~/.kiro/crew/agents/ab12cd34 && rm -rf -- * && echo entry >> JOURNAL.md",
            # a journal append does not launder a SECOND redirect target
            "cd ~/.kiro/crew/agents/ab12cd34 && echo e >> JOURNAL.md && echo z > state.json",
            # nor a verb whose target is spelled some other way
            "cd ~/.kiro/crew/agents/ab12cd34 && rm LIFE.md && echo e >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && cp /tmp/x LIFE.md && echo e >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo x > LIFE.md && echo y >> JOURNAL.md",
        ],
    )
    def test_journal_mention_cannot_launder_another_write(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> journal.md",
            "echo entry >> ~/.kiro/crew/agents/ab12cd34/JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && printf '%s\\n' x >> JOURNAL.md",
        ],
    )
    def test_the_one_allowed_write_still_works(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd


class TestContractPreambleLeads:
    """GPT round-24: the §7 preamble was prepended BEFORE the last_result block
    was composed, so the previous-run result ended up above the contract for
    every agent that had already run once — the majority case. §7 requires the
    contract to lead, and its RANK FIRST step depends on that position.
    """

    def test_contract_leads_even_with_a_previous_result(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        job.last_result = "ranked three candidates last time"
        _key, msg = build_cron_session_context(job)
        contract_at = msg.index("You are a perpetual agent")
        result_at = msg.index("[Previous run result")
        assert contract_at < result_at, "contract must precede the previous result"
        assert msg.startswith(_SELF_CONTRACT_PREAMBLE.split("\n")[0])

    def test_previous_result_still_present_and_ordered_before_the_task(
        self, tmp_path: Path
    ) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        job.last_result = "prior work"
        _key, msg = build_cron_session_context(job)
        assert msg.index("[Previous run result") < msg.index("pursue the goal")


class TestVerbSpellingIsTokenized:
    """GPT round-25 reported ``/bin/rm``: the verb test was substring membership
    on a space-delimited string, so a path-qualified verb never matched. Probing
    it turned up two more spellings of the same root cause — ``&&rm`` (an
    operator ends a word without a space) and ``'rm'`` (quotes break the window).
    One shape change (split on operators, strip quotes, compare basenames) covers
    all three, which is why they are pinned together here.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && /bin/rm -f crons.json",
            "cd ~/.kiro/crew && /usr/bin/rm -f crons.json",
            "cd ~/.kiro/crew&&rm -f crons.json",
            "cd ~/.kiro/crew;rm -f crons.json",
            "cd ~/.kiro/crew && 'rm' -f crons.json",
            'cd ~/.kiro/crew && "rm" -f crons.json',
            "cd ~/.kiro/crew && /usr/bin/tee crons.json",
            "cd ~/.kiro/crew/agents && /bin/mkdir ab12cd34",
            # the round-24 journal allowance must not be reopened by a
            # path-qualified verb either
            "cd ~/.kiro/crew/agents/ab12 && /bin/rm -rf -- * && echo e >> JOURNAL.md",
        ],
    )
    def test_path_qualified_and_glued_verbs_are_caught(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # exact basename matching: scp is not cp, and naming a verb's path as
            # a READ argument is not a write
            "scp host:/a /tmp/b",
            "ls /usr/bin/rm",
            "cd ~/.kiro/crew && ls -la",
            "cd ~/.kiro/crew && grep -c . config.json",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md",
            "node_modules/.bin/vite build",
            "/bin/rm /tmp/scratch.txt",
        ],
    )
    def test_tokenization_does_not_overblock(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd


class TestJournalAllowanceConsultsWriteContext:
    """GPT round-26: the allowance asked only "no write VERB", so it missed the
    OTHER signal this module already counts as a write — an interpreter
    invocation (round 22). The allowance was wider than the module's own notion
    of a write, which is a drift bug rather than a missing pattern.

    It now strips redirects and asks _command_has_write_context about the
    remainder, so any future write-context signal is consulted automatically
    instead of having to be remembered in a second place.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            # script-file form: the leaf name never appears, which is exactly why
            # round 22 made the interpreter itself the signal
            "cd ~/.kiro/crew/agents/ab12 && python /tmp/wipe.py && echo e >> JOURNAL.md",
            "cd ~/.kiro/crew && python /tmp/w.py && echo e >> ~/.kiro/crew/agents/ab12/JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12 && node /tmp/wipe.js && echo e >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12 && perl /tmp/wipe.pl && echo e >> JOURNAL.md",
            # inline payload form
            "cd ~/.kiro/crew/agents/ab12 && python -c 'import os' && echo e >> JOURNAL.md",
            # an interpreter-wrapped append does not earn the allowance either:
            # once running it can do anything, so its redirect text proves nothing
            "cd ~/.kiro/crew/agents/ab12 && bash -lc 'echo x >> JOURNAL.md'",
        ],
    )
    def test_interpreter_defeats_the_journal_allowance(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> journal.md",
            "echo entry >> ~/.kiro/crew/agents/ab12cd34/JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && printf '%s\\n' x >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo entry >> JOUR''NAL.md",
        ],
    )
    def test_the_supported_append_forms_survive(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_allowance_is_derived_not_duplicated(self) -> None:
        """The allowance must consult the shared write-context helper, so a new
        signal added there cannot silently reopen it."""
        from kiro_crew import security

        with patch.object(security, "_command_has_write_context", return_value=True):
            assert security._is_journal_only_write("echo x >> JOURNAL.md") is False


class TestConditionalWriteVerbs:
    """GPT round-27: ``find . -name crons.json -delete`` was allowed. ``find``
    cannot join the unconditional verb set — it is overwhelmingly a READ, and
    making it write context would turn write-protection into read-blocking for
    ``find . -name '*.json'`` in the crew home, the one thing these conjunctions
    must never do. So the verb set gained a conditional half keyed on the flags
    that make a program mutate.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && find . -name crons.json -delete",
            "cd ~/.kiro/crew && find . -name x -fprintf crons.json '%p'",
            "cd ~/.kiro/crew && find . -name x -fls crons.json",
            # already caught via the inner verb, pinned so the conditional half
            # is not silently relied upon alone
            "cd ~/.kiro/crew && find . -name crons.json -exec rm {} ;",
            "cd ~/.kiro/crew && find . -name crons.json -execdir rm {} ;",
            "cd ~/.kiro/crew && find . -name crons.json | xargs rm",
            "cd ~/.kiro/crew/agents && find . -name LIFE.md -delete",
            "cd ~/.kiro/crew && /usr/bin/find . -name crons.json -delete",
        ],
    )
    def test_conditional_mutators_are_write_context(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # THE point of the conditional half: find without a mutating flag is
            # a read, even when it names a fenced leaf
            "cd ~/.kiro/crew && find . -name '*.json'",
            "cd ~/.kiro/crew && find . -name crons.json",
            "cd ~/.kiro/crew && find . -type f -newer config.json",
            "cd ~/.kiro/crew && find . -name crons.json -print",
            # and a mutating find outside the crew home is not this gate's business
            "find /tmp -name '*.log' -delete",
        ],
    )
    def test_plain_find_stays_a_read(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd


class TestJournalWritesAreOwnerScoped:
    """GPT round-27: the journal exemption was not owner-scoped, so agent A could
    write agent B's JOURNAL.md — and a journal is read back into its OWNER's next
    prompt, making that write a cross-agent prompt-injection channel. This is the
    WRITE side of the threat round 15 closed on the READ side (a symlinked
    <job.id> pulling a victim's LIFE.md into this job's prompt).

    Identity is available: both real transports pass session_key into
    hooks.on_tool_call, and a perpetual agent runs as ``cron:<job.id>`` whose life
    directory is ``agents/<job.id>``.
    """

    OWNER = "cron:job111"

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo e >> ~/.kiro/crew/agents/job111/JOURNAL.md",
            "cd ~/.kiro/crew/agents/job111 && echo e >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/job111 && echo e >> journal.md",
        ],
    )
    def test_owner_may_append_its_own_journal(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo pwned >> ~/.kiro/crew/agents/job999/JOURNAL.md",
            # the victim id appears only in the cd, never in the redirect target
            "cd ~/.kiro/crew/agents/job999 && echo pwned >> JOURNAL.md",
            "echo pwned > ~/.kiro/crew/agents/job999/JOURNAL.md",
            "cd ~/.kiro/crew/agents/job999 && echo pwned >> journal.md",
        ],
    )
    def test_another_agents_journal_is_refused(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is not None, cmd

    @pytest.mark.parametrize(
        "key", [None, "", "dashboard:main", "subagent:abc", "webhook:x", "cron:"]
    )
    def test_no_identity_means_no_exemption(self, key: str | None) -> None:
        """Positive form (the round-24 lesson): a caller that cannot prove it owns
        the journal does not get the exemption — rather than everyone getting it."""
        from kiro_crew.security import is_sensitive_bash_command

        cmd = "echo e >> ~/.kiro/crew/agents/job111/JOURNAL.md"
        assert is_sensitive_bash_command(cmd, session_key=key) is not None

    def test_edit_gate_is_owner_scoped_too(self) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        mine = _P.home() / ".kiro" / "crew" / "agents" / "job111" / "JOURNAL.md"
        theirs = _P.home() / ".kiro" / "crew" / "agents" / "job999" / "JOURNAL.md"
        assert is_sensitive_write_path(str(mine), session_key=self.OWNER) is False
        assert is_sensitive_write_path(str(theirs), session_key=self.OWNER) is True
        assert is_sensitive_write_path(str(mine)) is True

    def test_caller_agent_id_only_trusts_a_cron_key(self) -> None:
        from kiro_crew.security import _caller_agent_id

        assert _caller_agent_id("cron:job111") == "job111"
        # a per-run stateless suffix still identifies the same owner
        assert _caller_agent_id("cron:job111:deadbeef") == "job111"
        for key in [None, "", "cron:", "cron", "dashboard:job111", "subagent:job111"]:
            assert _caller_agent_id(key) is None, key


class TestOutputFlagsAreWriteContext:
    """GPT round-28: a fetcher with an output flag writes a file as surely as
    ``tee`` — ``curl -o crons.json file:///tmp/evil`` replaces the store from
    attacker-controlled bytes. Same conditional shape round 27 built for ``find``:
    the program alone is a read, the FLAG makes it a write.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && curl -o crons.json file:///tmp/evil.json",
            "cd ~/.kiro/crew && curl --output crons.json file:///tmp/evil.json",
            # --flag=value is one shell word; the tokenizer now emits the flag half
            "cd ~/.kiro/crew && curl --output=crons.json file:///tmp/evil.json",
            "cd ~/.kiro/crew && curl -O file:///tmp/crons.json",
            "cd ~/.kiro/crew && wget -O crons.json file:///tmp/evil.json",
            "cd ~/.kiro/crew && wget --output-document=crons.json http://x/y",
            "cd ~/.kiro/crew && openssl enc -d -in /tmp/e -out crons.json",
            "cd ~/.kiro/crew && gpg -o crons.json -d /tmp/evil.gpg",
            # not named in the report; found by probing the same shape
            "cd ~/.kiro/crew && sort -o crons.json /tmp/evil.json",
            # path-qualified, to prove the round-25 basename step still applies
            "cd ~/.kiro/crew && /usr/bin/curl -o crons.json file:///tmp/evil.json",
        ],
    )
    def test_output_flags_are_caught(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # the program without its output flag stays a read
            "cd ~/.kiro/crew && curl -s file:///tmp/x",
            "cd ~/.kiro/crew && curl -I https://example.com",
            # -o on a program NOT in the table is not an output flag
            "cd ~/.kiro/crew && grep -o pattern config.json",
            # and a real write outside the crew home is not this gate's business
            "curl -o /tmp/x.json https://example.com/y",
            "sort -o /tmp/out.txt /tmp/in.txt",
        ],
    )
    def test_flagless_and_outside_forms_stay_allowed(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd) is None, cmd

    def test_flag_value_split_does_not_leak_the_value_as_a_word(self) -> None:
        """The value half of ``--output=x`` must not become a word: a path that
        happens to equal a verb name would otherwise read as that verb."""
        from kiro_crew.security import _command_words

        words = _command_words("curl --output=rm https://x")
        assert "--output" in words
        assert "rm" not in words


class TestWriteVerbsAreDerivedNotCopied:
    """GPT round-30: chmod/chown/touch (plus gzip, cpio, patch) were in the
    _WRITE_CMDS regex and missing from the token set, so `chmod 000 crons.json`
    read as no write context and the store could be made unreadable. The set
    carried a comment asking the reader to keep it in sync by hand; three rounds
    each reported a verb it was missing. It is now DERIVED from the regex, so
    drift is not possible.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && chmod 000 crons.json",
            "cd ~/.kiro/crew && chown nobody crons.json",
            "cd ~/.kiro/crew && touch crons.json",
            "cd ~/.kiro/crew && gzip crons.json",
            "cd ~/.kiro/crew && patch crons.json /tmp/evil.patch",
            # NB: ``cpio -i < archive`` is deliberately NOT here. It extracts into
            # the cwd without naming the leaf, so it belongs to the target-never-
            # appears-in-text class, not to this verb-coverage fix.
            # the round-25 tokenizer still applies to the newly derived verbs
            "cd ~/.kiro/crew && /bin/chmod 000 crons.json",
            "cd ~/.kiro/crew&&chmod 000 crons.json",
            "cd ~/.kiro/crew/agents/ab12cd34 && chmod 000 LIFE.md",
        ],
    )
    def test_permission_and_archive_mutators_are_write_context(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd) is not None, cmd

    def test_token_set_covers_every_verb_in_the_authoritative_regex(self) -> None:
        """The invariant the old 'keep in sync' comment could only ask for."""
        from kiro_crew.security import (
            _NORMALIZER_WRITE_VERBS,
            _WRITE_CMDS,
            _verbs_from_write_cmds_regex,
        )

        assert _verbs_from_write_cmds_regex(_WRITE_CMDS) <= _NORMALIZER_WRITE_VERBS
        for verb in ("chmod", "chown", "touch", "rm", "mv", "tee", "sed", "patch"):
            assert verb in _NORMALIZER_WRITE_VERBS, verb

    def test_derivation_drops_nested_git_subcommands(self) -> None:
        """A bare ``git`` is not a write, and the subcommand words inside the
        nested group must not leak in as standalone verbs — tearing that group
        apart would admit ``clean``/``reset``/``apply`` as verbs of their own."""
        from kiro_crew.security import _NORMALIZER_WRITE_VERBS

        for leaked in ("git", "checkout", "restore", "reset", "apply", "clean", "stash"):
            assert leaked not in _NORMALIZER_WRITE_VERBS, leaked

    def test_token_only_verbs_are_still_present(self) -> None:
        """cp/unlink/shred are not in the regex and must survive the switch."""
        from kiro_crew.security import _NORMALIZER_WRITE_VERBS

        for verb in ("cp", "unlink", "shred"):
            assert verb in _NORMALIZER_WRITE_VERBS, verb


class TestAttachedRedirectsAreWriteContext:
    """GPT round-31: the redirect matcher required a whitespace/operator boundary
    BEFORE the operator, so `echo -n>crons.json` — glued to the preceding word —
    was not write context and the store could be truncated. The shell needs no
    separator there; same root cause as round 25's `&&rm`.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && echo -n>crons.json",
            "cd ~/.kiro/crew && echo x>crons.json",
            "cd ~/.kiro/crew && echo x>>crons.json",
            "cd ~/.kiro/crew && cat /tmp/evil>crons.json",
            "cd ~/.kiro/crew && :>crons.json",
            "cd ~/.kiro/crew && echo x>'crons.json'",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo x>LIFE.md",
        ],
    )
    def test_attached_redirects_are_caught(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None
        ), cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # fd duplication is not an output redirect
            "cd ~/.kiro/crew && cat config.json 2>&1",
            # NB: the interpreter form of this case deliberately does NOT name the
            # crew home. Round 37 refuses an interpreter whenever the crew home is
            # named, so keeping `cd ~/.kiro/crew` here would test that rule rather
            # than the `2>&1`-is-not-a-write rule this case exists for.
            "python -c 'print(1)' 2>&1",
            # a '>' inside QUOTED DATA is text, not an operator. Without the
            # quote-blanking step, dropping the boundary requirement would make
            # this a write and REFUSE A READ of a fenced leaf.
            "cd ~/.kiro/crew && grep 'a->b' crons.json",
            'cd ~/.kiro/crew && grep "x>y" crons.json',
            "cd ~/.kiro/crew && grep -c . crons.json",
        ],
    )
    def test_fd_dup_and_quoted_arrows_stay_reads(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_quote_blanking_preserves_length_and_outside_operators(self) -> None:
        from kiro_crew.security import _blank_quoted_spans

        src = "echo 'a>b' > crons.json"
        out = _blank_quoted_spans(src)
        assert len(out) == len(src)
        # the quoted arrow is gone, the real redirect survives
        assert "a>b" not in out
        assert "> crons.json" in out

    def test_owner_scoping_survives_the_attached_form(self) -> None:
        """The round-28 owner check must still apply when the redirect is glued."""
        from kiro_crew.security import is_sensitive_bash_command

        own = "cd ~/.kiro/crew/agents/job111 && echo x>>JOURNAL.md"
        other = "cd ~/.kiro/crew/agents/job999 && echo x>>JOURNAL.md"
        assert is_sensitive_bash_command(own, session_key="cron:job111") is None
        assert is_sensitive_bash_command(other, session_key="cron:job111") is not None
        # and an attached TRUNCATE of the agent's own goal file is still refused
        life = "cd ~/.kiro/crew/agents/job111 && echo x>LIFE.md"
        assert is_sensitive_bash_command(life, session_key="cron:job111") is not None


class TestJournalAllowanceRequiresCanonicalPaths:
    """GPT round-32: a DOT SEGMENT defeats an id comparison made on text.
    ``cd ~/.kiro/crew/agents/job111/../job999 && echo … >> JOURNAL.md`` matched the
    owner's own id first, kept the allowance, and landed in the victim's dir. The
    path level was never fooled (it uses realpath) but the chained-``cd`` form
    leaves a bare relative target the path level never sees.
    """

    OWNER = "cron:job111"

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew/agents/job111/../job999 && echo pwned >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/job111/./../job999 && echo pwned >> JOURNAL.md",
            "echo pwned >> ~/.kiro/crew/agents/job111/../job999/JOURNAL.md",
            # even landing back in the OWNER's own directory is refused: the
            # allowance requires canonical paths rather than trying to
            # canonicalise text, which is the losing game
            "cd ~/.kiro/crew/agents/./job111 && echo ok >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/job999/../job111 && echo ok >> JOURNAL.md",
        ],
    )
    def test_dot_segments_forfeit_the_allowance(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is not None, cmd

    def test_canonical_own_journal_still_allowed(self) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        for cmd in (
            "cd ~/.kiro/crew/agents/job111 && echo ok >> JOURNAL.md",
            "echo ok >> ~/.kiro/crew/agents/job111/JOURNAL.md",
        ):
            assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is None, cmd

    def test_path_level_resolves_traversal_independently(self) -> None:
        """Defence in depth: the resolved-path gate catches the same traversal."""
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        p = str(_P.home() / ".kiro/crew/agents/job111/../job999/JOURNAL.md")
        assert is_sensitive_write_path(p, session_key=self.OWNER) is True


class TestPerpetualRejectsNonModelJobs:
    """GPT round-32 (non-blocking finding): a command/script cron runs no model,
    so it can never call agent_sleep and never names its own deadline — the whole
    point of kind="self". Accepting it produced a job LABELLED perpetual that
    behaved as a plain fixed interval, while the §7 contract, life context and
    higher auto-pause threshold all applied to something that cannot use them.
    """

    def test_command_job_cannot_be_perpetual(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        with pytest.raises(ValueError, match="exclusive with command/script"):
            svc.add_job(
                name="x",
                message="m",
                every_secs=3600,
                perpetual=True,
                operator_session_key="dashboard:main",
                command="echo hi",
            )

    def test_script_job_cannot_be_perpetual(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        with pytest.raises(ValueError, match="exclusive with command/script"):
            svc.add_job(
                name="x",
                message="m",
                every_secs=3600,
                perpetual=True,
                operator_session_key="dashboard:main",
                script="~/.kiro/crew/crons/x.py:f",
            )

    def test_plain_perpetual_is_unaffected(self, tmp_path: Path) -> None:
        assert _add_self(_svc(tmp_path)).schedule.kind == "self"


class TestLifeContextWithoutDirFd:
    """Round 20 made the life-context reader FAIL CLOSED where ``dir_fd`` is
    unavailable, because the fallback could not refuse a symlinked component.
    Windows is that platform, so the content-asserting tests are skipped there —
    this class asserts the CONTRACT instead, so the platform is covered by an
    assertion rather than by an absence of tests.
    """

    def test_preamble_ships_without_life_context(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(os, "supports_dir_fd", set())
        svc = _svc(tmp_path)
        job = _add_self(svc)
        _key, msg = build_cron_session_context(job)
        # the contract and the task survive; the life context does not appear
        assert "[Perpetual agent contract]" in msg
        assert "pursue the goal" in msg
        assert "LIFE.md below" in msg  # the preamble's own words, not file content
        assert "[Your LIFE.md]" not in msg
        assert "[Your JOURNAL.md]" not in msg

    def test_loader_returns_nothing_without_dir_fd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew.cron import _load_life_context

        monkeypatch.setattr(os, "supports_dir_fd", set())
        job = _add_self(_svc(tmp_path))
        assert not _load_life_context(job)


class TestUnrecognizedExecutablesAreWriteCapable:
    """GPT round-33 ended the enumeration. Every earlier round listed things that
    WRITE (a verb set, then a conditional flag table) and each report was another
    spelling the list lacked. `cd ~/.kiro/crew && /tmp/rewrite crons.json` cannot
    be enumerated at all, so inside a command that already names a protected
    directory the question is INVERTED: write context is the default, and only a
    command whose every program is known-read counts as a read.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && /tmp/rewrite crons.json",
            "cd ~/.kiro/crew && ./rewrite crons.json",
            "cd ~/.kiro/crew && myhelper crons.json",
            "cd ~/.kiro/crew && /home/me/bin/tool crons.json",
            # a binary NAMED like a known read but living somewhere untrusted:
            # basenaming alone trusted the name, which probing caught
            "cd ~/.kiro/crew && /tmp/x/cat crons.json",
            "cd ~/.kiro/crew && ./cat crons.json",
            "cd ~/.kiro/crew/agents/ab12cd34 && /tmp/rewrite LIFE.md",
        ],
    )
    def test_unknown_or_untrusted_programs_are_write_context(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None
        ), cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # reads of a fenced leaf must STAY reads — the inversion must not turn
            # write-protection into read-blocking
            "cd ~/.kiro/crew && cat crons.json",
            "cd ~/.kiro/crew && /usr/bin/cat crons.json",
            "cd ~/.kiro/crew && grep -c . crons.json",
            "cd ~/.kiro/crew && cat crons.json 2>&1",
            "cd ~/.kiro/crew && head -5 crons.json | grep x",
            "cd ~/.kiro/crew && ls -la",
            "cd ~/.kiro/crew && git diff --stat",
            "cd ~/.kiro/crew && find . -name crons.json",
            "cat ~/.kiro/crew/config.json",
            "sqlite3 ~/.kiro/crew/sessions.db .tables",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo e >> JOURNAL.md",
        ],
    )
    def test_known_reads_stay_reads(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_program_extraction_shape(self) -> None:
        from kiro_crew.security import _program_words

        # only the first word of each segment is a program
        assert _program_words("cat a | grep b") == ["cat", "grep"]
        # env assignments and wrappers are stepped over
        assert _program_words("FOO=1 sudo /tmp/rewrite x") == ["rewrite@untrusted"]
        # a trusted system bin keeps its plain name
        assert _program_words("/usr/bin/cat x") == ["cat"]
        # fd duplication is not a program named "1"
        assert _program_words("cat x 2>&1") == ["cat"]
        # a redirect target is not a program
        assert _program_words("echo x > out.json") == ["echo"]

    def test_interpreters_are_not_in_the_read_set(self) -> None:
        """Round 22 made running an interpreter write context; the read set must
        not quietly re-admit one."""
        from kiro_crew.security import _KNOWN_READ_PROGRAMS

        for interp in ("python", "python3", "node", "perl", "ruby", "sh", "bash", "sed"):
            assert interp not in _KNOWN_READ_PROGRAMS, interp


class TestReadSetExcludesWritersAndExecutors:
    """GPT round-34 reported ``xxd -r``. Auditing the whole read set rather than
    that one entry found three more, one of which was a comment of mine the code
    never supported:

      * ``xargs`` and ``env`` EXECUTE another program, and program extraction only
        sees the first word of a segment — ``echo x | xargs /tmp/rewrite`` read as
        ``xargs``;
      * ``xxd in out`` / ``xxd -r`` and ``yq -i`` write without a redirect;
      * ``git checkout -- crons.json`` was allowed, because round 33's comment
        claimed the derived verb set covered git's mutating subcommands. It does
        not: round 30 drops the nested ``git (?:checkout|…)`` group whole, so those
        words are not verbs on their own. They are now in the conditional table.
      * ``tee`` was in BOTH the read set and the write-verb set. The verb half
        caught it so nothing leaked, but the contradiction was a latent bug.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && xxd -r /tmp/payload.hex crons.json",
            "cd ~/.kiro/crew && xxd /tmp/in crons.json",
            "cd ~/.kiro/crew && echo crons.json | xargs /tmp/rewrite",
            "cd ~/.kiro/crew && echo x | xargs tee crons.json",
            "cd ~/.kiro/crew && yq -i '.x=1' crons.json",
            "cd ~/.kiro/crew && env /tmp/rewrite crons.json",
            "cd ~/.kiro/crew && tee crons.json < /tmp/evil",
        ],
    )
    def test_writers_and_executors_are_write_context(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None
        ), cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && git checkout -- crons.json",
            "cd ~/.kiro/crew && git restore crons.json",
            "cd ~/.kiro/crew && git rm crons.json",
        ],
    )
    def test_git_mutating_subcommands_are_write_context(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None
        ), cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && git clean -fd",
            "cd ~/.kiro/crew && git reset --hard",
            "cd ~/.kiro/crew && git stash",
            "cd ~/.kiro/crew && git apply /tmp/evil.patch",
        ],
    )
    def test_git_forms_that_name_no_leaf_are_out_of_reach(self, cmd: str) -> None:
        """These DO mutate, and they are NOT refused — deliberately documented
        rather than papered over. The conjunction requires the command to name a
        fenced leaf, and these destroy files without naming any: the same
        target-never-appears-in-the-text class as a composed path. A text gate
        cannot reach them; a read-only mount over the store can. Asserting the
        real behaviour here keeps the gap visible instead of implying coverage.
        """
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && git log --oneline -5",
            "cd ~/.kiro/crew && git diff --stat",
            "cd ~/.kiro/crew && git status",
            "cd ~/.kiro/crew && git show HEAD",
        ],
    )
    def test_git_reads_stay_reads(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    def test_read_set_and_verb_set_do_not_overlap(self) -> None:
        """A program cannot be both a known read and a known write verb — that
        contradiction is what put ``tee`` in both."""
        from kiro_crew.security import _KNOWN_READ_PROGRAMS, _NORMALIZER_WRITE_VERBS

        assert not (_KNOWN_READ_PROGRAMS & _NORMALIZER_WRITE_VERBS)

    def test_read_set_excludes_program_executors(self) -> None:
        from kiro_crew.security import _KNOWN_READ_PROGRAMS

        for p in ("xargs", "env", "sudo", "nohup", "timeout", "xxd", "yq"):
            assert p not in _KNOWN_READ_PROGRAMS, p


class TestManualRunDoesNotEatAFutureWake:
    """GPT round-35: the consume guard was only ``is not None``, so a run that did
    NOT arrive from the agent-chosen deadline — a manual trigger — consumed a
    deadline still in the FUTURE. The agent's choice was discarded, and a manual
    run that then failed before calling agent_sleep fell back to the every_secs
    ceiling: the agent asked for 20 minutes and got hours.
    """

    def test_future_deadline_survives_a_manual_run(self, tmp_path: Path) -> None:
        import asyncio as _aio

        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 6 * 3600, "chose +6h", "")
        target = svc.list_jobs()[0]
        chosen = target.next_wake_ts
        assert chosen is not None and chosen > time.time()

        consumed = []
        svc._on_job = lambda _j: _aio.sleep(0)
        with patch.object(
            svc, "_consume_self_wake_locked", side_effect=lambda j: consumed.append(j.id)
        ):
            svc._job_run_meta[target.id] = (time.time(), "manual")
            svc._executing.add(target.id)
            _aio.run(svc._run_job_isolated(target))
        assert consumed == [], "a future deadline must not be consumed by a manual run"
        assert target.next_wake_ts == chosen

    def test_due_deadline_is_still_consumed(self, tmp_path: Path) -> None:
        import asyncio as _aio

        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "chose +10m", "")
        target = svc.list_jobs()[0]
        target.next_wake_ts = time.time() - 1  # due

        consumed = []
        svc._on_job = lambda _j: _aio.sleep(0)
        with patch.object(
            svc, "_consume_self_wake_locked", side_effect=lambda j: consumed.append(j.id)
        ):
            svc._job_run_meta[target.id] = (time.time(), "scheduled")
            svc._executing.add(target.id)
            _aio.run(svc._run_job_isolated(target))
        assert consumed == [target.id]


class TestRelativeAgentPathsAreAttributed:
    """GPT round-35: a RELATIVE target carries the victim id without the
    ``/agents/`` prefix the owner scan keys on, and a relative ``agents/`` segment
    reaches the subtree without the anchored spelling the subtree conjunction
    required. Both are the chained-relative shape, one directory down.
    """

    OWNER = "cron:job111"

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew/agents && echo injected >> job999/JOURNAL.md",
            # even the OWNER's own id via a relative subdirectory is refused: the
            # text cannot attribute it, so the allowance does not hold
            "cd ~/.kiro/crew/agents && echo x >> job111/JOURNAL.md",
            "cd ~/.kiro/crew && echo injected >> agents/job999/JOURNAL.md",
            "cd ~/.kiro/crew && echo injected > agents/job999/LIFE.md",
        ],
    )
    def test_relative_agent_targets_forfeit_the_allowance(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew/agents/job111 && echo ok >> JOURNAL.md",
            "echo ok >> ~/.kiro/crew/agents/job111/JOURNAL.md",
        ],
    )
    def test_the_supported_owner_forms_still_work(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is None, cmd


class TestSqlite3IsNotAKnownRead:
    """GPT round-35: round 33 kept sqlite3 in the read set and filed its write
    ability under the in-process/sandbox class. That was wrong — ``sqlite3 …
    '.output crons.json' …`` NAMES the target in the command text, so by the
    round-26 line it is a matching problem and gets fixed.
    """

    def test_output_redirection_via_sqlite3_is_write_context(self) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        for cmd in (
            "cd ~/.kiro/crew && sqlite3 /tmp/x '.output crons.json' 'select 1'",
            "cd ~/.kiro/crew && sqlite3 sessions.db '.output crons.json' 'select 1'",
        ):
            assert is_sensitive_bash_command(cmd) is not None, cmd

    def test_pinned_sessions_db_read_still_allowed(self) -> None:
        """Removing sqlite3 must not break the pinned everyday access: sessions.db
        is not a fenced bash leaf, so that command never reaches the conjunction."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command("sqlite3 ~/.kiro/crew/sessions.db .tables") is None
        assert is_sensitive_bash_command("sqlite3 ~/.kirocrew/sessions.db .tables") is None

    def test_sqlite3_writes_are_flag_conditional_not_excluded(self) -> None:
        """Round 35 removed sqlite3 from the read set outright. Round 37 showed
        that breaks test_normal_crew_access_not_overblocked once the crew-home
        branch stops requiring a resolvable leaf, so it is back in the read set
        with its WRITING dot-commands in the conditional table — the same
        mostly-read/flag-writes shape as find, curl and sort."""
        from kiro_crew.security import _CONDITIONAL_WRITE_VERBS, _KNOWN_READ_PROGRAMS

        assert "sqlite3" in _KNOWN_READ_PROGRAMS
        assert ".output" in _CONDITIONAL_WRITE_VERBS["sqlite3"]
        assert ".import" in _CONDITIONAL_WRITE_VERBS["sqlite3"]

    def test_default_writing_programs_stay_out_of_the_read_set(self) -> None:
        """wget saves to cwd, gunzip/xz replace their input — they WRITE by
        default, so unlike curl/openssl/gpg they must not be treated as reads."""
        from kiro_crew.security import _KNOWN_READ_PROGRAMS

        for p in ("wget", "gunzip", "xz", "tee", "xargs", "env", "xxd", "yq"):
            assert p not in _KNOWN_READ_PROGRAMS, p


class TestBareNamesUntrustedUnderResolutionControl:
    """GPT round-36: a bare program name is trusted because it resolves via PATH.
    Round 33's comment claimed PATH control was "a different threat this text gate
    cannot see" — false whenever the assignment is IN the command being judged.
    `PATH=/tmp:$PATH cat crons.json` stages /tmp/cat in plain sight. Same
    correction as the sqlite3 reversal: if the text names the mechanism, it is a
    matching problem, not an unreachable one.

    Probing found four spellings the report did not name: LD_PRELOAD,
    LD_LIBRARY_PATH, `env PATH=…`, and a `PATH=…;` statement ahead of the command.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && PATH=/tmp:$PATH cat crons.json",
            "cd ~/.kiro/crew && PATH=/tmp cat crons.json",
            "cd ~/.kiro/crew && export PATH=/tmp:$PATH; cat crons.json",
            "cd ~/.kiro/crew && LD_PRELOAD=/tmp/evil.so cat crons.json",
            "cd ~/.kiro/crew && LD_LIBRARY_PATH=/tmp cat crons.json",
            "cd ~/.kiro/crew && env PATH=/tmp cat crons.json",
            "PATH=/tmp:$PATH; cd ~/.kiro/crew && cat crons.json",
            "cd ~/.kiro/crew && IFS=x cat crons.json",
        ],
    )
    def test_resolution_control_forfeits_bare_name_trust(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None
        ), cmd

    def test_path_qualified_form_is_also_refused_deliberately(self) -> None:
        """`PATH=/tmp /usr/bin/cat` is refused too, and that is a chosen
        conservatism rather than an oversight: _program_words normalises
        /usr/bin/cat to `cat`, so a path-qualified program is indistinguishable
        from a bare one downstream. Threading a marker through to rescue a shape
        nobody writes is not worth the state. Asserted so the choice is explicit
        and a future reader does not "fix" it by accident."""
        from kiro_crew.security import _has_unrecognized_program

        assert (
            _has_unrecognized_program("cd ~/.kiro/crew && PATH=/tmp /usr/bin/cat crons.json")
            is True
        )

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && cat crons.json",
            "cd ~/.kiro/crew && /usr/bin/cat crons.json",
            "cd ~/.kiro/crew && grep -c . crons.json",
            "cat ~/.kiro/crew/config.json",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo e >> JOURNAL.md",
            # an ordinary env assignment that does NOT affect resolution
            "cd ~/.kiro/crew && FOO=1 cat crons.json",
        ],
    )
    def test_ordinary_reads_unaffected(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd


class TestComposedStoreWritesRefusedByCapability:
    """GPT round-37 closed the class I rebutted three times — by a mechanism I had
    not considered. My rebuttal was that a COMPOSED leaf name
    (`python -c 'open("cr"+"ons.json","w")'`) cannot be matched by text parsing,
    which is true and still true. GPT's fix does not match the name: inside a
    command that already NAMES the crew home, an interpreter or an unrecognized
    program can write anything, so the capability itself is refused whether or not
    a fenced basename appears.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && python -c 'open(\"cr\"+\"ons.json\",\"w\").write(\"{}\")'",
            "cd ~/.kiro/crew && perl -e 'open(F,\">cr\".\"ons.json\")'",
            "cd ~/.kiro/crew && python /tmp/rewrite.py",
            "cd ~/.kiro/crew && /tmp/rewrite",
            "cd ~/.kiro/crew && ./helper",
            "cd ~/.kirocrew && node /tmp/rewrite.js",
        ],
    )
    def test_capability_is_refused_without_a_resolvable_leaf(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None
        ), cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd ~/.kiro/crew && python --version",
            "cd ~/.kiro/crew && python -c 'print(1)'",
            "cd ~/.kiro/crew && kirocrew status",
            "cd ~/.kiro/crew && npm ls",
            "cd ~/.kiro/crew && ./scripts/report.sh",
        ],
    )
    def test_the_accepted_cost_is_pinned(self, cmd: str) -> None:
        """These are HARMLESS and are now refused. Pinned deliberately so the cost
        is visible in the test suite rather than discovered by a user: the crew home
        is Kiro Crew's data directory, not a workspace, and every legitimate CLI runs
        from any cwd — the workaround is not to cd into the store. If this trade is
        ever judged wrong, this test is where the decision is recorded."""
        from kiro_crew.security import is_sensitive_bash_command

        assert (
            is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is not None
        ), cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # THE narrowing: a named script FILE under the crew home is the
            # product's documented script-cron form and must stay allowed. My first
            # cut refused any interpreter whenever the crew home was NAMED, which
            # broke this and `touch <crew home>/sessions.db` — both pinned
            # elsewhere in the suite, which is how the over-block was caught.
            "python3 ~/.kiro/crew/crons/report.py",
            "PYTHONUNBUFFERED=1 python3 ~/.kiro/crew/crons/report.py",
            "touch ~/.kiro/crew/sessions.db",
            "ls ~/.kiro/crew/",
        ],
    )
    def test_named_script_files_and_non_interpreters_stay_allowed(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # reads inside the crew home must STILL be reads
            "cd ~/.kiro/crew && cat crons.json",
            "cd ~/.kiro/crew && ls -la",
            "cd ~/.kiro/crew && grep -c . crons.json",
            "cd ~/.kiro/crew && curl -s file:///tmp/x",
            "cd ~/.kiro/crew && curl -I https://example.com",
            "cd ~/.kiro/crew && git log --oneline -5",
            "cd ~/.kiro/crew && find . -name crons.json",
            "cat ~/.kiro/crew/config.json",
            "sqlite3 ~/.kiro/crew/sessions.db .tables",
            "cd ~/.kiro/crew/agents/ab12cd34 && echo e >> JOURNAL.md",
            # and an interpreter OUTSIDE the crew home is untouched
            "python -c 'print(1)'",
            "cd /tmp && python /tmp/rewrite.py",
        ],
    )
    def test_reads_and_outside_interpreters_unaffected(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=_OWNER_SESSION_KEY) is None, cmd


class TestConsumedSleepRecordNotLeftOnDisk:
    """GPT round-38: the deadline and the sleep record that produced it are ONE
    fact. Consuming cleared only the deadline, so a wake that died before calling
    agent_sleep again let the NEXT wake read a stale record and be told "this is
    your record from last wake" about a decision two wakes old.
    """

    def test_record_is_cleared_on_disk_when_the_deadline_is_consumed(
        self, tmp_path: Path
    ) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "ranked A", "")
        target = svc.list_jobs()[0]
        assert target.last_sleep_record

        target.next_wake_ts = time.time() - 1
        svc._consume_self_wake_locked(target)

        # the run being started still sees it — via the TRANSIENT attribute, which
        # round 42 introduced precisely so no save can carry it forward
        assert target.consumed_sleep_record, "the current run's prompt must keep it"
        assert target.last_sleep_record == "", "the persisted field must be empty"
        # a fresh reader (the next wake, or a restart) must not
        fresh = _svc(tmp_path).list_jobs()[0]
        assert fresh.next_wake_ts is None
        assert fresh.last_sleep_record == ""

    def test_a_newer_record_written_during_the_run_survives(self, tmp_path: Path) -> None:
        """The round-4 compare-and-clear guard must still hold: an agent_sleep
        landing DURING the run is a newer choice and must not be erased.

        Modelled with two service objects on one directory, because that is the
        real shape — the newer choice arrives on DISK while this run holds an
        older in-memory deadline. My first draft called record_agent_sleep on the
        same service, which mutates the very object consume reads `fired` from, so
        it tested nothing.
        """
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "ranked A", "")
        target = svc.list_jobs()[0]
        target.next_wake_ts = time.time() - 1  # the deadline this run fired on

        # a NEWER choice lands on disk from elsewhere
        other = _svc(tmp_path)
        other.record_agent_sleep(job.id, 1800, "ranked B", "")

        svc._consume_self_wake_locked(target)

        fresh = _svc(tmp_path).list_jobs()[0]
        assert fresh.next_wake_ts is not None, "newer deadline must survive"
        assert "ranked B" in fresh.last_sleep_record


class TestSleepRecordLifetimeEndsAtPromptAssembly:
    """GPT round-39: round 38 cleared the record on disk but RESTORED it on the
    in-memory job so the prompt could still show it. Any later save of that same
    object — last_run_ts, last_result, the auto-pause counters — wrote it back, so
    a wake that exited before calling agent_sleep still handed the next wake a
    two-wakes-old record. The record's lifetime ends at prompt assembly, which is
    the only point that needs it.
    """

    def test_the_runs_own_save_does_not_reinstate_the_record(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "ranked A", "")
        target = svc.list_jobs()[0]
        target.next_wake_ts = time.time() - 1

        svc._consume_self_wake_locked(target)
        # the prompt still carries it — that is what the in-memory value is for
        _key, msg = build_cron_session_context(target)
        assert "ranked A" in msg

        # the gateway clears it right after assembly (the round-39 step)
        if target.schedule.kind == "self" and target.last_sleep_record:
            target.last_sleep_record = ""

        # then the run's ordinary bookkeeping is persisted
        target.last_run_ts = time.time()
        target.last_result = "done"
        svc._save()

        fresh = _svc(tmp_path).list_jobs()[0]
        assert fresh.last_sleep_record == "", "a later save must not reinstate it"
        assert fresh.last_result == "done", "ordinary bookkeeping must still persist"

    def test_gateway_clears_the_record_after_assembly(self) -> None:
        """Round 42 superseded the gateway clear entirely. The invariant that
        matters is no longer "where is it cleared" but "it cannot be persisted at
        all": the consumed value lives on a TRANSIENT attribute and ``_save``
        serialises an explicit field list. Asserted against that list, because a
        future field added there would silently reopen rounds 38-42."""
        import inspect

        from kiro_crew import cron

        src = inspect.getsource(cron._save_locked if hasattr(cron, "_save_locked") else cron)
        assert '"last_sleep_record": j.last_sleep_record' in src
        assert "consumed_sleep_record" not in src.split('data = {')[-1].split("}")[0]


class TestModifiedParameterExpansionsAreAnchored:
    """GPT round-40: the brace alternative matched only the BARE
    ``${KIROCREW_HOME}``, so every MODIFIED parameter expansion named the same
    directory and slipped past. The shell has a whole grammar of modifiers here;
    the brace form now accepts any modifier text rather than enumerating them.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "cd /tmp && echo x > ${KIROCREW_HOME:0}/crons.json",
            "echo x > ${KIROCREW_HOME:-/tmp}/crons.json",
            "echo x > ${KIROCREW_HOME##*/}/crons.json",
            "echo x > ${KIROCREW_HOME%/}/crons.json",
            "echo x > ${KIROCREW_HOME/x/y}/crons.json",
            "echo x > ${KIROCREW_HOME:?err}/crons.json",
            # the bare forms that already worked must keep working
            "echo x > $KIROCREW_HOME/crons.json",
            "echo x > ${KIROCREW_HOME}/crons.json",
        ],
    )
    def test_modified_expansions_are_refused(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd) is not None, cmd

    def test_both_anchors_accept_modifiers(self) -> None:
        """Two regexes spell this idea; earlier rounds' lesson is that two
        spellings drift. Both must accept modifier text."""
        from kiro_crew.security import _build_sensitive_regex

        rx = _build_sensitive_regex()
        assert rx.search("echo x > ${KIROCREW_HOME:0}/crons.json")


class TestSleepRecordFieldsAreBoundedNotTruncated:
    """GPT round-40: a single 4,000-char cap on the JOINED record dropped
    ``next_intent`` whenever ``did`` alone filled the budget — the agent's
    statement of what it plans to do next vanished with no error and the next wake
    was never told. Fields are bounded separately and an oversized record is
    REFUSED rather than trimmed.
    """

    def test_oversized_did_is_refused_not_silently_trimmed(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        with pytest.raises(ValueError, match="limited to"):
            svc.record_agent_sleep(job.id, 600, "D" * 4000, "INTENT")

    def test_oversized_intent_is_refused(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        with pytest.raises(ValueError, match="limited to"):
            svc.record_agent_sleep(job.id, 600, "did", "I" * 4000)

    def test_both_fields_survive_at_the_cap(self, tmp_path: Path) -> None:
        from kiro_crew.cron import _SLEEP_FIELD_MAX

        svc = _svc(tmp_path)
        job = _add_self(svc)
        did = "D" * _SLEEP_FIELD_MAX
        intent = "I" * _SLEEP_FIELD_MAX
        svc.record_agent_sleep(job.id, 600, did, intent)
        rec = svc.list_jobs()[0].last_sleep_record
        assert did in rec, "did must survive intact"
        assert intent in rec, "next_intent must NOT be dropped"

    def test_ordinary_record_is_unchanged(self, tmp_path: Path) -> None:
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "ranked three PRs", "check CI at 09:00")
        rec = svc.list_jobs()[0].last_sleep_record
        assert "did: ranked three PRs" in rec
        assert "next: check CI at 09:00" in rec


class TestDataHomeItselfIsProtected:
    """GPT round-41: the data home ITSELF was unprotected — `mv ~/.kiro/crew
    ~/crew-stolen` and `rm -rf ~/.kiro/crew` were allowed. Relocating it defeats
    every fence in the module at once, because they all key on the canonical path:
    the moved tree holds the same credentials, governance policy and store, now
    outside every anchor.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "mv ~/.kiro/crew ~/crew-stolen",
            "mv ~/.kiro/crew /tmp/stolen",
            "rm -rf ~/.kiro/crew",
            "mv ~/.kirocrew ~/stolen",
            # copying the whole home out is refused too — see the cost note
            "cp -r ~/.kiro/crew /tmp/copy",
        ],
    )
    def test_moving_or_deleting_the_home_is_refused(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd) is not None, cmd

    def test_writes_to_children_are_unaffected(self) -> None:
        """Only the root ITSELF is added; a write naming a CHILD is unchanged, so
        the pinned everyday behaviour survives."""
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command("touch ~/.kiro/crew/sessions.db") is None
        assert is_sensitive_bash_command("ls ~/.kiro/crew/") is None
        assert is_sensitive_bash_command("cat ~/.kiro/crew/config.json") is None

    def test_path_level_protects_root_agents_and_below(self) -> None:
        from pathlib import Path as _P

        from kiro_crew.security import is_sensitive_write_path

        home = _P.home()
        assert is_sensitive_write_path(str(home / ".kiro/crew")) is True
        assert is_sensitive_write_path(str(home / ".kiro/crew/agents")) is True
        assert is_sensitive_write_path(str(home / ".kiro/crew/agents/x")) is True


class TestSleepRecordSurvivesDeniedDispatch:
    """GPT round-41, third placement of one clear. Round 38 cleared it on disk but
    restored it in memory (a later save wrote it back). Round 39 cleared it right
    after prompt assembly — which is BEFORE vet_job_at_fire_time and before the
    concurrent-execution guard, so a wake DENIED dispatch destroyed the record for
    the next permitted wake. Every pre-dispatch exit must leave it intact, which is
    only true if the clear sits after the prompt reaches the provider.
    """

    def test_clear_is_after_dispatch_not_after_assembly(self, tmp_path: Path) -> None:
        """Round 42 removed the need for any placement at all: after consumption the
        value lives on ``consumed_sleep_record``, which ``_save``'s explicit field
        list does not serialise. So a wake DENIED dispatch cannot destroy the record
        and a later merge cannot resurrect it. Asserted as a ROUND TRIP rather than
        by source position — rounds 39 and 41 could only check where a line sat."""
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "ranked A", "")
        target = svc.list_jobs()[0]
        target.next_wake_ts = time.time() - 1
        svc._consume_self_wake_locked(target)
        assert target.consumed_sleep_record, "the run keeps it in memory"

        # anything a later save writes must NOT carry the transient value
        target.last_run_ts = time.time()
        target.last_result = "done"
        svc._save()
        fresh = _svc(tmp_path).list_jobs()[0]
        assert fresh.consumed_sleep_record == "", "the transient value must not persist"
        assert fresh.last_sleep_record == ""
        assert fresh.last_result == "done"

    def test_assembly_region_does_not_clear(self) -> None:
        """Guards the specific regression: no clear between assembly and the vet."""
        import inspect

        from kiro_crew.slack import gateway

        src = inspect.getsource(gateway)
        assembly = src.index("build_cron_session_context, job)")
        vet = src.index("vet_job_at_fire_time,", assembly)
        between = src[assembly:vet]
        assert 'last_sleep_record = ""' not in between


class TestComposedDirectoryNamesAreFenced:
    """GPT round-43: the crew-home conjunction is pre-guarded on the literal
    substring ``crew``/``kirocrew`` for speed, so composing the DIRECTORY name from
    variables skipped it entirely — `d=cr;e=ew;printf '{}' > ~/.kiro/$d$e/…` never
    contains the word. Round 16 closed the composed LEAF; the same trick one level
    up was still open.
    """

    @pytest.mark.parametrize(
        "cmd",
        [
            "d=cr;e=ew;f=cr;g=ons.json;printf '{}' > ~/.kiro/$d$e/$f$g",
            "d=cr;e=ew;printf '{}' > ~/.kiro/$d$e/crons.json",
            "d=cr;e=ew;printf '{}' > $HOME/.kiro/$d$e/crons.json",
            # the composed-leaf form round 16 fixed must still be refused
            "f=cr;g=ons.json;printf '{}' > ~/.kiro/crew/$f$g",
        ],
    )
    def test_variable_derived_writes_under_the_kiro_root_are_refused(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd) is not None, cmd

    @pytest.mark.parametrize(
        "cmd",
        [
            # literal reads and writes outside the fence are unchanged
            "cat ~/.kiro/crew/config.json",
            "ls ~/.kiro",
            "echo hi > /tmp/out.txt",
            "f=notes.md; echo x > /tmp/$f",
        ],
    )
    def test_literal_and_outside_forms_unaffected(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd) is None, cmd


class TestConsumedRecordClearedAfterDispatch:
    """GPT round-43, FIFTH round on one value — and this one was my own regression.
    Round 42 moved the consumed record onto a transient field to stop it being
    PERSISTED, and I deleted round 41's post-dispatch clear as "redundant". It was
    not: persistence and in-memory reuse are two different leaks. The service CACHES
    CronJob objects, so a dispatched turn that omitted agent_sleep left the value on
    the cached job and the next fallback wake was told it was "your record from last
    wake".

    The clear sits AFTER dispatch, not at assembly: a wake denied dispatch must keep
    it, because consume already cleared the disk copy and that wake never showed the
    record to anyone.
    """

    def test_both_dispatch_paths_clear_the_transient(self) -> None:
        import inspect

        from kiro_crew.slack import gateway

        src = inspect.getsource(gateway)
        # both build_message call sites in the cron callback must be followed by a
        # clear; count them rather than asserting one position
        assert src.count('job.consumed_sleep_record = ""') >= 2, (
            "each dispatch path must clear the transient record"
        )

    def test_clear_follows_dispatch_in_the_sequential_path(self) -> None:
        import inspect

        from kiro_crew.slack import gateway

        src = inspect.getsource(gateway)
        vet = src.index("vet_job_at_fire_time,")
        clear = src.index('job.consumed_sleep_record = ""', vet)
        assert clear > vet, "a denied wake must keep the record"

    def test_transient_still_cannot_be_persisted(self, tmp_path: Path) -> None:
        """Round 42's guarantee must survive round 43's change."""
        svc = _svc(tmp_path)
        job = _add_self(svc)
        svc.record_agent_sleep(job.id, 600, "ranked A", "")
        target = svc.list_jobs()[0]
        target.next_wake_ts = time.time() - 1
        svc._consume_self_wake_locked(target)
        svc._save()
        assert _svc(tmp_path).list_jobs()[0].consumed_sleep_record == ""


class TestWindowsSeparatorsInAgentPaths:
    """GPT round-44: the owner-scoping regexes were written with ``/`` only, so on
    Windows — where the shell separator is ``\\`` — a foreign agent id
    (``agents\\job999``) and a traversal (``job111\\..\\job999``) were invisible.
    The platform difference is not a reason for a second pattern: one separator
    class covers both.
    """

    OWNER = "cron:job111"

    @pytest.mark.parametrize(
        "cmd",
        [
            r"cd $HOME\.kiro\crew\agents\job999; echo pwned >> JOURNAL.md",
            r"cd %USERPROFILE%\.kiro\crew\agents\job999 && echo pwned >> JOURNAL.md",
            r"echo pwned >> $HOME\.kiro\crew\agents\job999\JOURNAL.md",
            r"cd $HOME\.kiro\crew\agents\job111\..\job999 && echo pwned >> JOURNAL.md",
            # the posix forms must stay refused
            "cd ~/.kiro/crew/agents/job999 && echo pwned >> JOURNAL.md",
            "cd ~/.kiro/crew/agents/job111/../job999 && echo pwned >> JOURNAL.md",
        ],
    )
    def test_foreign_ids_and_traversals_refused_on_both_separators(self, cmd: str) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is not None, cmd

    def test_owner_forms_still_work(self) -> None:
        from kiro_crew.security import is_sensitive_bash_command

        for cmd in (
            "cd ~/.kiro/crew/agents/job111 && echo ok >> JOURNAL.md",
            "echo ok >> ~/.kiro/crew/agents/job111/JOURNAL.md",
        ):
            assert is_sensitive_bash_command(cmd, session_key=self.OWNER) is None, cmd

    def test_both_regexes_accept_either_separator(self) -> None:
        from kiro_crew.security import _AGENTS_ID_IN_PATH_RE, _DOT_SEGMENT_RE

        assert _DOT_SEGMENT_RE.search("a/../b")
        assert _DOT_SEGMENT_RE.search(r"a\..\b")
        assert _AGENTS_ID_IN_PATH_RE.search("/agents/job1")
        assert _AGENTS_ID_IN_PATH_RE.search(r"\agents\job1")


class TestRecordClearedOnlyAfterProviderAccepts:
    """GPT round-44, SIXTH round on one value. Round 43 cleared the transient right
    after ``build_message`` — which only ASSEMBLES the prompt. A provider outage in
    ``stream_and_collect`` then destroyed the record before any turn had run with
    it. The record is spent only once a turn actually ran, so both clears now sit
    after a successful return.
    """

    def test_both_clears_follow_stream_and_collect(self) -> None:
        import inspect

        from kiro_crew.slack import gateway

        src = inspect.getsource(gateway)
        # the two cron-callback dispatch sites, in order
        first = src.index("result_text = await stream_and_collect(")
        second = src.index("result_text = await stream_and_collect(", first + 1)
        clear1 = src.index('job.consumed_sleep_record = ""', first)
        clear2 = src.index('job.consumed_sleep_record = ""', second)
        assert clear1 > first, "sequential path: clear must follow the provider call"
        assert clear2 > second, "single-agent path: clear must follow the provider call"

    def test_no_clear_between_assembly_and_dispatch(self) -> None:
        """The specific regression: a clear before the provider call would destroy
        the record on an outage that never ran a turn."""
        import inspect

        from kiro_crew.slack import gateway

        src = inspect.getsource(gateway)
        assembly = src.index("build_cron_session_context, job)")
        first_call = src.index("result_text = await stream_and_collect(", assembly)
        assert 'consumed_sleep_record = ""' not in src[assembly:first_call]
