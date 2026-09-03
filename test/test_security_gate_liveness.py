"""Liveness tests for the shell-command sensitive-path gate.

``is_sensitive_bash_command`` runs synchronously on the gateway's event loop,
under a loop-stall watchdog that hard-exits the process after 25 s of silence
(``dashboard.loop_stall_exit_after_secs``). A field crash (a cron whose agent
emitted a ~9 KB command full of ``https://`` URLs) traced to the gate: the
doubled separator in every URL sent the command through the separator-collapsed
re-scan, and the pattern tier was quadratic in the command. Three constructs
were each quadratic on their own and their costs multiply, so each has its own
pin here, plus the two trigger paths the crash dumps showed:

* Pass 1b -- ~10 KB with doubled separators (the URL / ``//`` shape);
* Pass 1  -- one 24 000-backslash run, which never reaches the loop at all.

Verdict pins are the cases where the rewritten construct was the ONLY branch
that matched, captured from the pre-rewrite gate on this tree and on the tree
before the anchor rewrite (#7941); a 381 474-command generated differential
corpus produced zero differences against both. Timing tests assert a doubling
RATIO where the code has no structure to observe, with the input well inside
the region where the old shape was already seconds, so a regression overshoots
by 4x while noise moves the linear result by a fraction.
"""

from __future__ import annotations

import inspect
import json
import time

import pytest

from kiro_crew import security
from kiro_crew.security import (
    MAX_SCANNABLE_COMMAND_CHARS,
    _sensitive_pattern_hit,
    _verb_anchored_sensitive_hit,
    is_sensitive_bash_command,
)

# ─────────────────────────────────────────────────────────────────────────────
# Shapes
# ─────────────────────────────────────────────────────────────────────────────

_SEG = "a" * 60


def _double_separator_command(n: int) -> str:
    """n path operands, each with a doubled ``//`` so Pass 1 misses and the
    separator-collapsed re-scan (Pass 1b) runs -- the crash shape."""
    return "ls " + " ".join(f"/opt//{_SEG}" for _ in range(n))


def _url_payload_command(n: int) -> str:
    """The field shape: a JSON body of ``https://`` URLs handed to curl."""
    urls = [f"https://tasks.example.test/T{100000 + i}?view=full&x={_SEG[:20]}" for i in range(n)]
    return "curl -s -X POST -d " + json.dumps({"items": urls})


def _backslash_run_command(n: int) -> str:
    """One separator run of n backslashes: the Pass 1 path, no re-scan."""
    return "echo " + "\\" * n


def _unc_chain_command(n: int) -> str:
    """One UNC token carrying n canonical no-op hops (``\\X\\..``)."""
    return "type \\\\srv\\share" + "".join(f"\\{_SEG}\\.." for _ in range(n))


def _verb_dense_command(n: int) -> str:
    return " ".join(f"cat {_SEG}" for _ in range(n))


# ─────────────────────────────────────────────────────────────────────────────
# Verdict pins: the rewritten constructs accept the same language
# ─────────────────────────────────────────────────────────────────────────────

# Every path here is preceded by a character that is NOT in the token anchor
# class, so the verb-independent branch cannot be what matches: these were
# matched by the verb-anchored regex branch alone, and must still be denied.
VERB_ANCHORED_ONLY: list[str] = [
    "cat $(echo x)/home/user/.aws/credentials",
    "tee foo/home/user/.aws/credentials",
    "CAT foo/home/user/.aws/credentials",
    "git checkout -- x)/home/user/.ssh/id_rsa",
    "cat ./..//home/user/.aws/credentials",
    "sed -i s/a/b/ x}/Users/bob/.gnupg/secring.gpg",
    "echo a; cat b; ls x/home/user/.aws/credentials",
    'python -c "open(prefix/home/user/.aws/credentials)"',
    'PYTHON3 -c "open (x/home/user/.aws/credentials)"',
    "perl -e 'open(F, x/home/user/.ssh/id_rsa)'",
    "cat a\ncat x/home/user/.aws/credentials",
    "cat x/home/user/.aws/credentials\necho done",
    "cat x/home/user/.aws/credentials\r\necho done",
]

# The same shapes with the ordering or the line broken: the old branch did not
# match these (``.*`` never crosses a newline; ``open(`` must FOLLOW the
# interpreter), and neither may the rewrite.
VERB_ANCHORED_NEGATIVE: list[str] = [
    "cat foo\nx/home/user/.aws/credentials",
    "echo x/home/user/.aws/credentials",
    'python -c "print(x/home/user/.aws/credentials)"',
    "open(x/home/user/.aws/credentials) python -c 1",
    "python -c 1\nopen(x/home/user/.aws/credentials)",
    "concatenate x/home/user/.aws/credentials",
    "cat x/home/user/.awsx/credentials",
    # the path BEFORE the verb on the same line: the old branch required the
    # verb first, so the search from the verb's end must not look backwards
    "echo x/home/user/.aws/credentials; cat foo",
    "ls x/home/user/.aws/credentials && tee out",
    "print(open(x/home/user/.aws/credentials)); python -c 1",
]

REDIRECT_FORM: list[tuple[str, bool]] = [
    (">~/.aws/credentials", True),
    ("2>/home/user/.aws/credentials", True),
    ("echo x|~/.ssh/id_rsa", True),
    ("echo x >   $HOME/.aws/credentials", True),
    # a redirect somewhere earlier does not make a mid-token path a hit
    ("echo x >x/home/user/.aws/credentials", False),
]

UNC_FORM: list[tuple[str, bool]] = [
    (r"type \\server\share\.aws\credentials", True),
    (r"type \\server\share\sub\dir\.ssh\id_rsa", True),
    (r"type \\server\share\a\..\b\..\.kiro\crew\security_policy.json", True),
    (r"type \\server\share\.\.aws\credentials", True),
    (r"type \\server\.aws\credentials", True),
    (r"echo forged > \\server\share\.kiro\crew\connections-tool-aliases.json", True),
    (r"type \\server\share\.kiro\crew\%F%", True),
    (r"type \\server\share\.kiro\agents\x.json", True),
    (r"type \\server\share\\.aws\credentials", True),
    (r"type \\server\share\notes.txt", False),
    (r"type \\srv\x", False),
]


@pytest.mark.parametrize("command", VERB_ANCHORED_ONLY)
def test_verb_anchored_form_still_denies(command: str) -> None:
    assert is_sensitive_bash_command(command) is not None
    # And it is the verb-anchored half that carries it: the compiled
    # alternation alone does not match (the path is mid-token).
    assert _verb_anchored_sensitive_hit(command) is True
    assert security._get_sensitive_re().search(command) is None


@pytest.mark.parametrize("command", VERB_ANCHORED_NEGATIVE)
def test_verb_anchored_form_stays_allowed_when_order_or_line_breaks(command: str) -> None:
    assert is_sensitive_bash_command(command) is None
    assert _verb_anchored_sensitive_hit(command) is False


@pytest.mark.parametrize(("command", "expected"), REDIRECT_FORM)
def test_redirect_form_verdicts_unchanged(command: str, expected: bool) -> None:
    assert bool(is_sensitive_bash_command(command)) is expected


@pytest.mark.parametrize(("command", "expected"), UNC_FORM)
def test_unc_anchor_verdicts_unchanged(command: str, expected: bool) -> None:
    assert bool(is_sensitive_bash_command(command)) is expected


def test_pattern_tier_is_the_union_of_both_halves() -> None:
    """A verb-anchored-only hit and an anchor-only hit each flip the tier on
    their own, so dropping either half from ``_sensitive_pattern_hit`` fails."""
    assert _sensitive_pattern_hit("cat $(echo x)/home/user/.aws/credentials") is True
    assert _sensitive_pattern_hit("FOO=~/.aws/credentials") is True
    assert _verb_anchored_sensitive_hit("FOO=~/.aws/credentials") is False
    assert _sensitive_pattern_hit("ls -la") is False


# ─────────────────────────────────────────────────────────────────────────────
# Source guards: the quadratic spellings must not come back
# ─────────────────────────────────────────────────────────────────────────────


def test_compiled_alternation_carries_no_verb_or_redirect_wildcard() -> None:
    source = inspect.getsource(security._build_sensitive_regex)
    # Code spellings only (``rf"`` prefix), so the explanatory comment that quotes
    # the old form in prose is not counted.
    assert 'rf"(?:(?:' not in source, "the verb/redirect group is back in the regex"
    assert r'rf"(?:[<>|]\s*{sensitive_path}' in source
    for verbs in ("{_READ_CMDS}.*", "{_WRITE_CMDS}.*", "{_SCRIPT_OPEN}.*"):
        assert verbs not in source, f"the verb-anchored branch is back in the regex: {verbs}"
    # The UNC anchor takes a plain separator, never the generalized one.
    assert "{unc_prefix}{win_sep}" in source
    assert "{unc_prefix}{win_gsep}" not in source
    assert "|{unc_prefix}|" not in source, "unc_prefix is back inside win_home_alts"


# ─────────────────────────────────────────────────────────────────────────────
# Size ceiling: refused, not scanned, not skipped
# ─────────────────────────────────────────────────────────────────────────────


def test_oversized_command_is_refused_with_a_reason() -> None:
    cmd = "echo " + "x" * MAX_SCANNABLE_COMMAND_CHARS
    reason = is_sensitive_bash_command(cmd)
    assert reason is not None
    assert "too large to security-scan" in reason
    assert str(len(cmd)) in reason


def test_command_at_the_ceiling_is_scanned_not_refused() -> None:
    body = "x" * (MAX_SCANNABLE_COMMAND_CHARS - len("echo "))
    assert is_sensitive_bash_command("echo " + body) is None
    # And a sensitive path at the very end of a ceiling-sized command is found.
    tail = " ~/.aws/credentials"
    cmd = "echo " + "x" * (MAX_SCANNABLE_COMMAND_CHARS - len("echo ") - len(tail)) + tail
    assert len(cmd) == MAX_SCANNABLE_COMMAND_CHARS
    assert is_sensitive_bash_command(cmd) == "Blocked: command accesses sensitive credential path"


def test_ceiling_matches_the_tool_input_tier() -> None:
    """The two tiers refuse at the same size, so a command cannot be too long
    for one and scanned by the other."""
    from kiro_crew import llm_helpers

    assert llm_helpers._MAX_SCANNABLE_TOOL_INPUT_CHARS == MAX_SCANNABLE_COMMAND_CHARS


# ─────────────────────────────────────────────────────────────────────────────
# Complexity: both trigger paths, and each construct on its own
# ─────────────────────────────────────────────────────────────────────────────


def _gate_seconds(command: str) -> float:
    started = time.perf_counter()
    is_sensitive_bash_command(command)
    return time.perf_counter() - started


def test_pass1b_double_separator_10kb_is_fast() -> None:
    """The crash shape, at the crash size. 15 s on the shipped build, ~70 ms
    after the rewrite; the ceiling clears the fixed path by ~30x and the old
    one overshoots by ~7x."""
    cmd = _double_separator_command(160)
    assert 10_000 < len(cmd) <= MAX_SCANNABLE_COMMAND_CHARS
    assert security._separator_collapsed_variants(cmd), "shape must enter Pass 1b"
    assert _gate_seconds(cmd) < 2.0


def test_url_payload_12kb_is_fast() -> None:
    cmd = _url_payload_command(160)
    assert 10_000 < len(cmd) <= MAX_SCANNABLE_COMMAND_CHARS
    assert security._separator_collapsed_variants(cmd), "URLs must enter Pass 1b"
    assert _gate_seconds(cmd) < 2.0


def test_pass1_backslash_run_is_linear(monkeypatch: pytest.MonkeyPatch) -> None:
    """The run never reaches the collapsed loop; the cost was Pass 1 alone.
    Doubling ratio well under 4 (quadratic) with the input sized so the old
    form was already 1.5 s at the smaller size."""
    monkeypatch.setattr(security, "MAX_SCANNABLE_COMMAND_CHARS", 10**9)
    small = _gate_seconds(_backslash_run_command(24_000))
    large = _gate_seconds(_backslash_run_command(96_000))
    assert large < 3.0
    assert large / max(small, 0.005) < 9.0, f"{small:.3f}s -> {large:.3f}s over x4 input"


@pytest.mark.parametrize(
    "make",
    [_double_separator_command, _url_payload_command, _unc_chain_command, _verb_dense_command],
    ids=["double-separator", "url-payload", "unc-chain", "verb-dense"],
)
def test_each_construct_is_linear_in_the_command(
    make, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    """One shape per rewritten construct, ceiling lifted so the input can be
    large enough for the ratio to be about the algorithm and not the noise. A
    quadratic term makes x4 input cost x16; linear costs x4."""
    monkeypatch.setattr(security, "MAX_SCANNABLE_COMMAND_CHARS", 10**9)
    small = _gate_seconds(make(320))
    large = _gate_seconds(make(1280))
    assert large < 3.0, f"{large:.2f}s on an 80-100 KB command"
    assert large / max(small, 0.02) < 9.0, f"{small:.3f}s -> {large:.3f}s over x4 input"
