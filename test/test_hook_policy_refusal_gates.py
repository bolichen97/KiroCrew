"""A hook the shell deny-list refused is skipped by every PreToolUse gate, not a block.

``run_script_hook`` refuses a deny-listed hook command before it spawns and
answers ``policy_refused=True`` with exit 0 (see ``ScriptHookResult.policy_refused``).
The refusal is the policy's verdict on the HOOK, so the gates that read hook
results must let the tool through with a warning; before this, the refusal came
back as exit 2 and one refused telemetry hook blocked every tool call of every
agent that carried it. A hook that RAN and exited 2 still blocks, and a
governance exit 2 now names its source instead of logging a bare "exit 2".
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from kiro_crew.hook_runtime.hook_dispatch import permission_pre_tool_block
from kiro_crew.hook_runtime.script_hooks import ScriptHookResult


def _refused() -> ScriptHookResult:
    return ScriptHookResult(
        hook_id="h1",
        hook_name="telemetry",
        event="PreToolUse",
        error="Blocked by security policy: (?:[~/$][\\w./$-]*\\.midway\\b|\\.midway/)",
        exit_code=0,
        policy_refused=True,
    )


class _Store:
    def __init__(self, results: list[ScriptHookResult]) -> None:
        self._results = results

    async def fire(self, *_a: Any, **_k: Any) -> list[ScriptHookResult]:
        return list(self._results)


async def _gate(results: list[ScriptHookResult]) -> str | None:
    return await permission_pre_tool_block(_Store(results), [], None, "Read File")  # type: ignore[arg-type]


class TestPermissionGate:
    @pytest.mark.asyncio
    async def test_a_refused_hook_does_not_block_and_is_logged(self, caplog):
        caplog.set_level(logging.WARNING)
        assert await _gate([_refused()]) is None
        assert any(
            "telemetry" in r.getMessage() and "refused by the shell deny-list" in r.getMessage()
            for r in caplog.records
        )

    @pytest.mark.asyncio
    async def test_a_refused_hook_does_not_mask_a_real_block_after_it(self):
        ran_and_denied = ScriptHookResult(
            hook_id="h2", hook_name="guard", event="PreToolUse", stderr="no", exit_code=2
        )
        assert await _gate([_refused(), ran_and_denied]) == "guard: no"

    @pytest.mark.asyncio
    async def test_a_hook_that_ran_and_exited_2_still_blocks(self):
        r = ScriptHookResult(
            hook_id="h2", hook_name="guard", event="PreToolUse", stderr="nope", exit_code=2
        )
        assert await _gate([r]) == "guard: nope"

    @pytest.mark.asyncio
    async def test_a_governance_exit_2_names_its_source(self):
        r = ScriptHookResult(
            hook_id="h3",
            hook_name="g",
            event="PreToolUse",
            error="Blocked by governance policy: script hooks are off",
            exit_code=2,
        )
        reason = await _gate([r])
        assert reason == "g: governance: Blocked by governance policy: script hooks are off"

    @pytest.mark.asyncio
    async def test_a_crash_still_fails_closed(self):
        r = ScriptHookResult(hook_id="h4", hook_name="c", event="PreToolUse", exit_code=1)
        assert await _gate([r]) == "c: exited with code 1"


class TestResultShape:
    def test_a_refusal_is_neither_a_block_nor_a_success(self):
        r = _refused()
        assert not r.blocked
        assert not r.succeeded
