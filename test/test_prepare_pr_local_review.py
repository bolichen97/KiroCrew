"""Tests for local_review.py - local/server reviewer CONTRACT PARITY.

The prepare-pr skill's Phase-2 local review is only a real gate if it judges a
commit against the same contract the server reviewers use. ``local_review.py``
gets that by EXTRACTING the contract from the reviewer workflows instead of
restating it, so these tests hold two properties:

  * **Parity** - what the extractor returns is the live workflow's own text
    (sentinel sections present, lifted verbatim, expressions substituted, model
    pins agreeing with the bundled profile, auxiliary inputs staged the way the
    workflow stages them).
  * **Loud failure** - if a workflow is restructured so the extraction no longer
    finds the contract, the script FAILS instead of degrading into a stale
    paraphrase. Silently emitting a paraphrase is the exact drift the script
    exists to prevent, so the mutation tests below matter more than the happy
    path: they run the extractor against deliberately broken workflow copies.

The scripts live under the packaged builtin skill and are NOT importable as a
package, so we load them by path with importlib - same convention as
test_prepare_pr_profiles.py. Everything here is stdlib and hermetic: the
synthetic repos are real local git repos (as in test_push_guard.py) and every
``gh`` call is forced to fail so no test touches the network.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "src" / "kiro_crew" / "builtin_skills" / "kirocrew-dev" / "prepare-pr"
SCRIPTS_DIR = SKILL_DIR / "scripts"
PROFILES_DIR = SKILL_DIR / "profiles"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
PROMPTS_DIR = REPO_ROOT / ".github" / "review-prompts"

GPT_WORKFLOW = WORKFLOWS_DIR / "codex-review.yml"
OPUS_WORKFLOW = WORKFLOWS_DIR / "claude-review.yml"


def _load(module_name, filename):
    path = SCRIPTS_DIR / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


local_review = _load("_pp_local_review", "local_review.py")

KIROCREW_PROFILE = json.loads((PROFILES_DIR / "kirocrew.json").read_text(encoding="utf-8"))
PROFILE_MODELS = {r["name"]: r for r in KIROCREW_PROFILE["reviewers"]}

# Local values for the GitHub event expressions the workflows interpolate.
FAKE_VALUES = {
    "github.event.pull_request.base.sha": "a" * 40,
    "github.event.pull_request.head.sha": "b" * 40,
    "github.event.pull_request.base.ref": "main",
    "github.event.pull_request.number": "(local run - no PR yet)",
    "github.repository": "kirodotdev/KiroCrew",
    "runner.temp": "/tmp/stage",
}


def _git(cwd, *args):
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


def _gpt_text():
    return GPT_WORKFLOW.read_text(encoding="utf-8")


def _opus_text():
    return OPUS_WORKFLOW.read_text(encoding="utf-8")


def _gpt_prompt(values=None, stage="/tmp/stage"):
    """The GPT lane's prompt, extracted from the live workflow."""
    text = _gpt_text()
    scalars = local_review.block_scalars(text)
    target = local_review._heredoc_target(text)
    block = local_review._run_block_with(scalars, "cat > {} <<".format(target), "gpt")
    prompt = local_review.extract_heredoc(block, target)
    if values is None:
        return prompt
    return local_review.remap_staged_paths(
        local_review.substitute_expressions(prompt, values), stage
    )


@pytest.fixture
def no_gh(monkeypatch):
    """Force every ``gh`` call to fail so tests exercise the offline fallbacks."""
    real = local_review.run

    def fake(args, cwd=None):
        if args and args[0] == "gh":
            return 127, "", "gh: not found"
        return real(args, cwd=cwd)

    monkeypatch.setattr(local_review, "run", fake)
    return fake


@pytest.fixture
def parity_repo(tmp_path):
    """A synthetic repo that resolve_profile.py recognises as KiroCrew.

    Carries real copies of both reviewer workflows and both base-ref prompt
    files, a backend AUTOSDE.yaml, and deliberately NO website/AUTOSDE.yaml so
    the absent-file fallback path is exercised. One base commit on ``main`` plus
    one feature commit, so BASE...HEAD is non-empty.
    """
    root = tmp_path / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "review-prompts").mkdir(parents=True)
    shutil.copy(GPT_WORKFLOW, root / ".github" / "workflows" / GPT_WORKFLOW.name)
    shutil.copy(OPUS_WORKFLOW, root / ".github" / "workflows" / OPUS_WORKFLOW.name)
    for prompt in sorted(PROMPTS_DIR.glob("*.md")):
        shutil.copy(prompt, root / ".github" / "review-prompts" / prompt.name)
    (root / "AUTOSDE.yaml").write_text("rules: []\n", encoding="utf-8")

    _git(root, "init")
    _git(root, "checkout", "-b", "main")
    _git(root, "config", "user.email", "parity@example.invalid")
    _git(root, "config", "user.name", "Parity Test")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "base")
    _git(root, "checkout", "-b", "feature")
    (root / "changed.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "feat(thing): add VALUE\n\nA body line for intent.")
    return root


# --------------------------------------------------------------------------
# Parity: the extracted prompt IS the workflow's prompt
# --------------------------------------------------------------------------
def test_gpt_prompt_carries_the_contract_sentinels():
    prompt = _gpt_prompt()
    for sentinel in (
        "SYSTEM RULES",
        "REPO CONTEXT",
        "DIVISION OF LABOUR",
        "FINDING BAR",
        "WHAT BLOCKS",
        "OUTPUT STYLE",
        "OUTPUT MARKERS",
    ):
        assert sentinel in prompt, "{} missing from the extracted GPT contract".format(sentinel)
    # A truncated lift would still pass the sentinel checks above.
    assert len(prompt) > 5000


def test_gpt_prompt_is_lifted_verbatim_not_paraphrased():
    """Every extracted line must exist in the workflow file, byte for byte.

    This is the property the whole script rests on: the local brief is the
    server's own text, only dedented by the YAML block indent.
    """
    prompt = _gpt_prompt()
    raw = _gpt_text()
    indent = " " * 10  # the `run: |` body indent in the reviewer workflows
    missing = [line for line in prompt.splitlines() if line.strip() and indent + line not in raw]
    assert not missing, "extracted lines absent from the workflow: {}".format(missing[:3])


def test_gpt_two_passes_and_blocking_budget_come_from_the_workflow():
    text = _gpt_text()
    scalars = local_review.block_scalars(text)
    block = local_review._run_block_with(scalars, "DISCOVERY PASS", "gpt")
    literals = local_review.quoted_literals(block)
    discovery = local_review.literals_between(
        literals, "DISCOVERY PASS", "DISCOVERY PASS", "discovery"
    )
    falsification = local_review.literals_between(
        literals, "FALSIFICATION PASS", "UNTRUSTED EVIDENCE", "falsification"
    )
    assert len(discovery) == 1
    assert "candidate generation" in discovery[0]
    assert len(falsification) >= 2
    assert "AUTHORITATIVE" in falsification[0]
    assert any("UNTRUSTED EVIDENCE" in item for item in falsification)
    budget = re.search(r"BUDGET:\s*at most\s*(\d+)\s*BLOCKING", _gpt_prompt())
    assert budget is not None, "the blocking budget must be extracted, not assumed"
    assert int(budget.group(1)) >= 1


def test_quoted_literals_drops_shell_plumbing():
    block = "\n".join(
        [
            'PROMPT="$BASE_PROMPT"',
            'printf "%s\\n" "DISCOVERY PASS: a real instruction with several words"',
            'echo "$discovery_one"',
            'x="short"',
        ]
    )
    literals = local_review.quoted_literals(block)
    assert literals == ["DISCOVERY PASS: a real instruction with several words"]


def test_block_scalars_never_reads_prompt_text_as_structure():
    """A `name:`-looking line inside a prompt must not rename the owning step."""
    scalars = local_review.block_scalars(_gpt_text())
    steps = {s.step for s in scalars}
    assert "Write review prompt" in steps
    assert any(s.key == "run" and "SYSTEM RULES" in s.text for s in scalars)


def test_opus_contract_comes_from_base_ref_prompt_files():
    specs = local_review.extract_prompt_file_specs(_opus_text())
    sources = [s.src for s in specs]
    assert sources, "the Opus lane's contract files must be discovered from the workflow"
    assert all(src.startswith(".github/review-prompts/") for src in sources)
    assert all(s.fallback is None for s in specs), "a missing contract file must be fatal"
    for src in sources:
        assert (REPO_ROOT / src).is_file(), "{} named by the workflow does not exist".format(src)


def test_opus_wrapper_prompts_extracted_for_every_stage():
    scalars = local_review.block_scalars(_opus_text())
    wrappers = [s for s in scalars if s.key == "prompt"]
    assert len(wrappers) >= 2, "the Opus lane runs discovery then validation"
    for wrapper in wrappers:
        assert "review-prompts" in wrapper.text
        assert "pr.diff" in wrapper.text


def test_gpt_lane_has_no_prompt_files_and_opus_lane_has_no_heredoc():
    """The two shapes are distinguishable, so lane dispatch cannot cross wires."""
    assert local_review._heredoc_target(_gpt_text()) is not None
    assert local_review.extract_prompt_file_specs(_gpt_text()) == []
    assert local_review._heredoc_target(_opus_text()) is None
    assert local_review.extract_prompt_file_specs(_opus_text()) != []


# --------------------------------------------------------------------------
# Parity: expressions and paths
# --------------------------------------------------------------------------
def test_no_unsubstituted_expression_survives():
    prompt = _gpt_prompt(FAKE_VALUES)
    assert "${{" not in prompt
    assert FAKE_VALUES["github.event.pull_request.base.sha"] in prompt
    assert FAKE_VALUES["github.event.pull_request.head.sha"] in prompt


def test_opus_wrapper_expressions_all_substitute():
    scalars = local_review.block_scalars(_opus_text())
    for wrapper in [s for s in scalars if s.key == "prompt"]:
        out = local_review.substitute_expressions(wrapper.text, FAKE_VALUES)
        assert "${{" not in out


def test_unknown_expression_is_a_parity_failure():
    with pytest.raises(local_review.ParityError) as exc:
        local_review.substitute_expressions("head is ${{ github.event.brand_new }}", FAKE_VALUES)
    assert "github.event.brand_new" in str(exc.value)


def test_staged_paths_are_remapped_out_of_the_worktree():
    prompt = _gpt_prompt(FAKE_VALUES, stage="/tmp/stage")
    assert "/tmp/stage/.review-base-rules/AUTOSDE.yaml" in prompt
    # No bare workspace-relative reference may survive, or the reviewer would
    # look for rule snapshots inside the worktree (where we never write).
    stripped = prompt.replace("/tmp/stage/.review-", "")
    assert ".review-" not in stripped


def test_remap_preserves_trailing_punctuation():
    out = local_review.remap_staged_paths("see `.review-prompts/opus-validate.md`.", "/s")
    assert "/s/.review-prompts/opus-validate.md" in out
    assert "opus-validate.md." not in out.replace("opus-validate.md`.", "")


# --------------------------------------------------------------------------
# Parity: model pins
# --------------------------------------------------------------------------
def test_model_pins_agree_with_the_bundled_profile():
    gpt_scalars = local_review.block_scalars(_gpt_text())
    opus_scalars = local_review.block_scalars(_opus_text())
    gpt_ci = local_review._extract_ci_model(_gpt_text(), gpt_scalars)
    opus_ci = local_review._extract_ci_model(_opus_text(), opus_scalars)
    assert local_review._model_note(gpt_ci, PROFILE_MODELS["gpt"]["model"]) == []
    assert local_review._model_note(opus_ci, PROFILE_MODELS["opus"]["model"]) == []


def test_model_drift_is_reported_not_swallowed():
    notes = local_review._model_note("openai.gpt-9.9-nova", "gpt-5.6-sol")
    assert notes and "MODEL DRIFT" in notes[0]


def test_model_pin_is_read_from_config_not_from_prose():
    """`--model` appears in a workflow COMMENT too; a prose match would win."""
    scalars = local_review.block_scalars(_opus_text())
    model = local_review._extract_ci_model(_opus_text(), scalars)
    assert model != "below"
    assert "claude" in model


# --------------------------------------------------------------------------
# Auxiliary input staging
# --------------------------------------------------------------------------
def test_base_rule_staging_produces_both_files_including_the_fallback(parity_repo, tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    specs = local_review.extract_base_rule_specs(_gpt_text())
    assert len(specs) == 2
    base_sha = _git(parity_repo, "rev-parse", "main")
    written = local_review.stage_files(str(parity_repo), base_sha, str(stage), specs)
    assert len(written) == 2
    backend = stage / ".review-base-rules" / "AUTOSDE.yaml"
    frontend = stage / ".review-base-rules" / "website-AUTOSDE.yaml"
    assert backend.read_text(encoding="utf-8").strip() == "rules: []"
    # website/AUTOSDE.yaml is absent on base -> the workflow's own fallback text.
    fallback = next(s.fallback for s in specs if "website" in s.src)
    assert frontend.read_text(encoding="utf-8").strip() == fallback


def test_base_rules_are_read_from_base_not_head(parity_repo, tmp_path):
    """A PR cannot weaken the rules that govern it - same property as CI."""
    (parity_repo / "AUTOSDE.yaml").write_text("rules: [weakened]\n", encoding="utf-8")
    _git(parity_repo, "add", "-A")
    _git(parity_repo, "commit", "-m", "weaken the rules")
    stage = tmp_path / "stage"
    stage.mkdir()
    base_sha = _git(parity_repo, "rev-parse", "main")
    local_review.stage_files(
        str(parity_repo), base_sha, str(stage), local_review.extract_base_rule_specs(_gpt_text())
    )
    staged = (stage / ".review-base-rules" / "AUTOSDE.yaml").read_text(encoding="utf-8")
    assert "weakened" not in staged


def test_missing_contract_file_is_a_parity_failure(parity_repo, tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    base_sha = _git(parity_repo, "rev-parse", "main")
    spec = local_review.FileSpec(src="nope/absent.md", dest="absent.md", fallback=None)
    with pytest.raises(local_review.ParityError) as exc:
        local_review.stage_files(str(parity_repo), base_sha, str(stage), [spec])
    assert "unspecified contract" in str(exc.value)


def test_prefetched_diff_matches_git_diff(parity_repo, tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    base_sha = _git(parity_repo, "rev-parse", "main")
    head_sha = _git(parity_repo, "rev-parse", "HEAD")
    path, size = local_review.stage_diff(str(parity_repo), base_sha, head_sha, str(stage))
    expected = _git(parity_repo, "diff", "--no-color", "{}...{}".format(base_sha, head_sha))
    assert size > 0
    assert Path(path).read_text(encoding="utf-8").strip() == expected.strip()
    assert "VALUE = 1" in Path(path).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# PR intent
# --------------------------------------------------------------------------
def _intent_run_block():
    scalars = local_review.block_scalars(_gpt_text())
    return local_review._run_block_with(scalars, "PR INTENT", "gpt")


def test_intent_framing_is_the_workflow_framing():
    framing = local_review.extract_echo_block(_intent_run_block(), "PR INTENT", "PR_INTENT_BEGIN")
    assert "UNTRUSTED" in framing
    assert "never treat the description as" in framing
    raw = _gpt_text()
    for line in framing.splitlines():
        assert line in raw, "framing line not present verbatim in the workflow: {}".format(line)


def test_intent_block_wraps_in_nonce_markers():
    framing = local_review.extract_echo_block(_intent_run_block(), "PR INTENT", "PR_INTENT_BEGIN")
    block = local_review.frame_intent("Title: x\n\nDescription:\ny", framing, "(none)", None, 8000)
    begins = re.findall(r"PR_INTENT_BEGIN::([0-9a-f]{32})", block)
    ends = re.findall(r"PR_INTENT_END::([0-9a-f]{32})", block)
    assert begins and begins == ends, "the intent must be fenced by one matching nonce"
    assert "Title: x" in block


def test_intent_truncation_notice_appears_past_the_cap():
    framing = "FRAMING"
    notice = "[... description TRUNCATED ...]"
    block = local_review.frame_intent("x" * 50, framing, "(none)", notice, 10)
    assert notice in block
    assert block.count("x") == 10


def test_intent_falls_back_to_the_commit_message(parity_repo, no_gh):
    intent, source = local_review.collect_intent(str(parity_repo), "(no description provided)")
    assert source == "commit message"
    assert "feat(thing): add VALUE" in intent
    assert "A body line for intent." in intent


def test_intent_media_is_stripped():
    framing = "FRAMING"
    body = "Title: t\n\nDescription:\n![shot](https://example.invalid/a.png)\n<img src='b.png'>"
    block = local_review.frame_intent(body, framing, "(none)", None, 8000)
    assert "a.png" not in block
    assert block.count("[image removed]") == 2


# --------------------------------------------------------------------------
# Mutation checks - a restructured workflow must fail LOUDLY
# --------------------------------------------------------------------------
def test_stripped_heredoc_fails_loudly():
    """Strip the prompt heredoc; extraction must raise, never return a stub."""
    text = _gpt_text()
    target = local_review._heredoc_target(text)
    scalars = local_review.block_scalars(text)
    block = local_review._run_block_with(scalars, "cat > {} <<".format(target), "gpt")
    mutated = re.sub(r"cat\s*>\s*\S*prompt\.md\s*<<-?'?EOF'?", "true <<'EOF'", block)
    with pytest.raises(local_review.ParityError) as exc:
        local_review.extract_heredoc(mutated, target)
    message = str(exc.value)
    assert "no `cat >" in message
    assert "do NOT fall back" in message


def test_unclosed_heredoc_fails_loudly():
    with pytest.raises(local_review.ParityError) as exc:
        local_review.extract_heredoc("cat > /tmp/p.md <<'EOF'\nbody\n", "/tmp/p.md")
    assert "never closed" in str(exc.value)


def test_removed_base_rule_snapshot_fails_loudly():
    mutated = "\n".join(
        line for line in _gpt_text().splitlines() if 'git show "$BASE_SHA:' not in line
    )
    with pytest.raises(local_review.ParityError) as exc:
        local_review.extract_base_rule_specs(mutated)
    assert "base-ref rule snapshot" in str(exc.value)


def test_removed_model_pin_fails_loudly():
    mutated = _opus_text().replace("--model ", "--modelx ")
    scalars = local_review.block_scalars(mutated)
    with pytest.raises(local_review.ParityError) as exc:
        local_review._extract_ci_model(mutated, scalars)
    assert "model parity" in str(exc.value)


def test_missing_run_block_fails_loudly():
    with pytest.raises(local_review.ParityError) as exc:
        local_review._run_block_with([], "DISCOVERY PASS", "wf.yml")
    assert "restructured" in str(exc.value)


def test_missing_echo_framing_fails_loudly():
    with pytest.raises(local_review.ParityError):
        local_review.extract_echo_block("echo hello\n", "PR INTENT", "PR_INTENT_BEGIN")


def test_cli_exits_40_when_the_prompt_heredoc_is_gone(parity_repo, tmp_path):
    """End-to-end mutation check: a restructured workflow exits 40, writes no brief."""
    workflow = parity_repo / ".github" / "workflows" / GPT_WORKFLOW.name
    text = workflow.read_text(encoding="utf-8")
    workflow.write_text(
        text.replace("cat > /tmp/codex-prompt.md <<'EOF'", "true <<'EOF'"), encoding="utf-8"
    )
    _git(parity_repo, "add", "-A")
    _git(parity_repo, "commit", "-m", "restructure the reviewer workflow")
    out_dir = tmp_path / "out"
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "local_review.py"),
            "--worktree",
            str(parity_repo),
            "--base",
            "main",
            "--out-dir",
            str(out_dir),
            "--stage-dir",
            str(tmp_path / "stage"),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": os.environ.get("PATH", "")},
    )
    assert proc.returncode == local_review.EXIT_PARITY, proc.stderr
    assert "PARITY FAILURE" in proc.stderr
    assert not list(out_dir.glob("local-review-*.md"))


# --------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------
def test_assemble_writes_one_brief_per_reviewer(parity_repo, tmp_path, no_gh):
    out_dir = tmp_path / "out"
    stage_dir = tmp_path / "stage"
    summary = local_review.assemble(str(parity_repo), "main", str(out_dir), str(stage_dir))

    assert sorted(summary["tasks"]) == ["gpt", "opus"]
    lanes = {lane["name"]: lane for lane in summary["lanes"]}
    assert lanes["gpt"]["shape"] == "heredoc"
    assert lanes["opus"]["shape"] == "prompt-files"
    assert lanes["gpt"]["blocking_budget"] >= 1
    assert lanes["gpt"]["local_model"] == PROFILE_MODELS["gpt"]["model"]
    assert lanes["opus"]["local_model"] == PROFILE_MODELS["opus"]["model"]
    assert not lanes["gpt"]["warnings"], lanes["gpt"]["warnings"]
    assert not lanes["opus"]["warnings"], lanes["opus"]["warnings"]

    gpt_brief = Path(summary["tasks"]["gpt"]).read_text(encoding="utf-8")
    assert "DIVISION OF LABOUR" in gpt_brief
    assert "PASS 1 - DISCOVERY" in gpt_brief
    assert "PASS 2 - FALSIFICATION" in gpt_brief
    assert summary["head_sha"] in gpt_brief
    assert str(parity_repo) in gpt_brief
    assert "READ-ONLY" in gpt_brief
    assert "${{" not in gpt_brief
    assert "feat(thing): add VALUE" in gpt_brief  # PR intent, from the commit

    opus_brief = Path(summary["tasks"]["opus"]).read_text(encoding="utf-8")
    assert "STAGE 1 of 2" in opus_brief
    assert "STAGE 2 of 2" in opus_brief
    assert "${{" not in opus_brief
    assert str(stage_dir) in opus_brief

    # Every staged input exists, and NOTHING was written inside the worktree.
    assert Path(summary["diff"]["path"]).is_file()
    for path in summary["rule_snapshots"]:
        assert Path(path).is_file()
    assert _git(parity_repo, "status", "--porcelain") == ""


def test_assemble_refuses_an_empty_diff(parity_repo, tmp_path, no_gh):
    _git(parity_repo, "checkout", "main")
    with pytest.raises(OSError) as exc:
        local_review.assemble(
            str(parity_repo), "main", str(tmp_path / "out"), str(tmp_path / "stage")
        )
    assert "nothing to review" in str(exc.value)


def test_assemble_needs_a_contract_backed_reviewer(tmp_path, no_gh):
    root = tmp_path / "plain"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    _git(root, "init")
    _git(root, "checkout", "-b", "main")
    _git(root, "config", "user.email", "p@example.invalid")
    _git(root, "config", "user.name", "P")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "base")
    with pytest.raises(OSError) as exc:
        local_review.assemble(str(root), "main", str(tmp_path / "out"), str(tmp_path / "stage"))
    assert "no contract-backed reviewers" in str(exc.value)


def test_cli_json_summary_is_machine_readable(parity_repo, tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "local_review.py"),
            "--worktree",
            str(parity_repo),
            "--base",
            "main",
            "--out-dir",
            str(tmp_path / "out"),
            "--stage-dir",
            str(tmp_path / "stage"),
            "--json",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == local_review.EXIT_OK, proc.stderr
    payload = json.loads(proc.stdout)
    assert sorted(payload["tasks"]) == ["gpt", "opus"]
    assert payload["base_sha"] and payload["head_sha"]


# --------------------------------------------------------------------------
# The skill file must not re-introduce a hand-written charter as the default
# --------------------------------------------------------------------------
def test_skill_dispatches_reviewers_from_the_extractor():
    skill = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    assert "local_review.py" in skill
    assert "fallback" in skill.lower()
