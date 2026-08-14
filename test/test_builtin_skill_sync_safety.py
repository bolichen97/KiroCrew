"""Builtin-skill sync safety invariants (issue #3433).

``_ensure_builtin_skills`` may only destroy a destination directory it can
PROVE it installed and that has not changed since: a full-tree fingerprint
recorded in a ``.builtin-skill-provenance`` dotfile, verified after the
directory is atomically claimed. Everything else is user data: on update it
moves aside to a non-clobbering ``<name>.user-backup`` quarantine (with its
``SKILL.md`` deactivated so the backup never shadows the live skill), and the
stale-cleanup pass leaves it alone entirely.

The invariants under test: a name collision with a builtin never deletes a
user-authored tree, an in-place edit or user-added file marks a destination
diverged, a user skill named after a stale-cleanup entry survives startup,
legitimate updates of untouched builtins still happen, quarantines never
clobber each other, and verification can never hang or read unbounded bytes
on the startup path.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from kiro_crew import skills as skills_mod
from kiro_crew.skills import (
    _PROVENANCE_MARKER,
    _ensure_builtin_skills,
    _record_builtin_provenance,
    _skill_tree_fingerprint,
)


def _make_skill(root: Path, name: str, body: str, extra: dict[str, str] | None = None) -> Path:
    """Create a skill directory ``root/name`` with a SKILL.md and extra files."""
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {body}\n---\n{body}\n", encoding="utf-8"
    )
    for rel, content in (extra or {}).items():
        target = skill_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return skill_dir


def _bump_mtime(path: Path, seconds: float = 60.0) -> None:
    """Make *path* strictly newer than any file written so far."""
    future = time.time() + seconds
    os.utime(path, (future, future))


def _backup_skill_md(backup: Path) -> Path:
    """The deactivated SKILL.md inside a quarantine directory."""
    return backup / "SKILL.md.user-backup"


@pytest.fixture()
def builtin_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated fake packaged-builtin source root wired into the module."""
    root = tmp_path / "packaged-builtins"
    root.mkdir()
    monkeypatch.setattr(skills_mod, "_BUILTIN_SKILLS_DIR", root)
    return root


@pytest.fixture()
def base(tmp_path: Path) -> Path:
    """The user's installed-skills base the sync writes into."""
    dest = tmp_path / "skills"
    dest.mkdir()
    return dest


class TestNameCollisionPreservation:
    """A destination the sync cannot prove it owns is preserved, never deleted."""

    def test_user_skill_colliding_with_new_builtin_survives(
        self, builtin_root: Path, base: Path
    ) -> None:
        # A user-authored `deploy` collides with a bundled skill of the same
        # name whose packaged SKILL.md is newer: the packaged version must
        # install, and the user's whole tree must survive in quarantine.
        _make_skill(base, "deploy", "USER original", {"scripts/run.sh": "echo user"})
        src = _make_skill(builtin_root, "deploy", "packaged builtin")
        # Filesystem mtime granularity can tie the two writes; make the
        # packaged copy deterministically newer so the update gate fires.
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        installed = base / "deploy" / "SKILL.md"
        assert "packaged builtin" in installed.read_text(encoding="utf-8")
        assert (base / "deploy" / _PROVENANCE_MARKER).is_file()
        backup = base / "deploy.user-backup"
        assert "USER original" in _backup_skill_md(backup).read_text(encoding="utf-8")
        assert (backup / "scripts" / "run.sh").read_text(encoding="utf-8") == "echo user"

    def test_in_place_edited_builtin_not_destroyed_on_update(
        self, builtin_root: Path, base: Path
    ) -> None:
        src = _make_skill(builtin_root, "helper", "v1")
        _ensure_builtin_skills(base)  # clean install, provenance recorded

        # A user edit to the installed copy makes it user data; the packaged
        # v2 must still install, with the edit preserved in quarantine.
        dest_md = base / "helper" / "SKILL.md"
        dest_md.write_text(dest_md.read_text(encoding="utf-8") + "\nMY EDIT\n", encoding="utf-8")
        (src / "SKILL.md").write_text("---\nname: helper\n---\nv2\n", encoding="utf-8")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        assert "v2" in dest_md.read_text(encoding="utf-8")
        preserved = _backup_skill_md(base / "helper.user-backup")
        assert "MY EDIT" in preserved.read_text(encoding="utf-8")

    def test_extra_auxiliary_file_marks_dest_diverged(
        self, builtin_root: Path, base: Path
    ) -> None:
        # SKILL.md is byte-identical; the ONLY divergence is a user-added
        # note. A SKILL.md-only comparison calls this unchanged and deletes
        # the note with the rest of the tree; the full-tree fingerprint must
        # treat it as diverged.
        src = _make_skill(builtin_root, "notes", "v1")
        _ensure_builtin_skills(base)
        (base / "notes" / "my-notes.txt").write_text("precious", encoding="utf-8")
        _bump_mtime(src / "SKILL.md")  # trigger the update gate, same content

        _ensure_builtin_skills(base)

        backup = base / "notes.user-backup"
        assert (backup / "my-notes.txt").read_text(encoding="utf-8") == "precious"
        assert (base / "notes" / "SKILL.md").is_file()

    def test_quarantine_never_clobbers_prior_quarantine(
        self, builtin_root: Path, base: Path
    ) -> None:
        src = _make_skill(builtin_root, "deploy", "packaged v1")
        _make_skill(base, "deploy", "USER first")
        _bump_mtime(src / "SKILL.md")
        _ensure_builtin_skills(base)
        first = _backup_skill_md(base / "deploy.user-backup")
        assert "USER first" in first.read_text(encoding="utf-8")

        # A second colliding copy appears (restore from a user's own backup,
        # rollback, ...) and the package ships an update: the next quarantine
        # must take a numbered name, not overwrite the first.
        dest_md = base / "deploy" / "SKILL.md"
        dest_md.write_text("USER second", encoding="utf-8")
        (src / "SKILL.md").write_text("packaged v2", encoding="utf-8")
        _bump_mtime(src / "SKILL.md", 120.0)

        _ensure_builtin_skills(base)

        assert "USER first" in first.read_text(encoding="utf-8")
        second = _backup_skill_md(base / "deploy.user-backup.2")
        assert "USER second" in second.read_text(encoding="utf-8")

    def test_dangling_symlink_at_backup_name_is_not_overwritten(
        self, builtin_root: Path, base: Path
    ) -> None:
        # ``Path.exists()`` reports False for a dangling symlink; the
        # quarantine namer must probe with ``lexists`` so it steps over the
        # occupied name instead of replacing the link.
        _make_skill(base, "deploy", "USER original")
        src = _make_skill(builtin_root, "deploy", "packaged builtin")
        _bump_mtime(src / "SKILL.md")
        os.symlink(base / "no-such-target", base / "deploy.user-backup")

        _ensure_builtin_skills(base)

        assert os.path.islink(base / "deploy.user-backup")
        preserved = _backup_skill_md(base / "deploy.user-backup.2")
        assert "USER original" in preserved.read_text(encoding="utf-8")

    def test_failed_claim_never_falls_through_to_destroy(
        self, builtin_root: Path, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # When the atomic claim rename fails, the sync must leave the
        # destination untouched — a failed preserve must never degrade into
        # the deletion it guards against.
        _make_skill(base, "deploy", "USER original")
        src = _make_skill(builtin_root, "deploy", "packaged builtin")
        _bump_mtime(src / "SKILL.md")

        def _refuse(_src: object, _dst: object) -> None:
            raise OSError("simulated rename failure")

        monkeypatch.setattr(skills_mod.os, "replace", _refuse)
        _ensure_builtin_skills(base)

        assert "USER original" in (base / "deploy" / "SKILL.md").read_text(encoding="utf-8")
        assert not os.path.lexists(base / "deploy.user-backup")

    def test_backup_is_not_discovered_as_a_live_skill(
        self, builtin_root: Path, base: Path
    ) -> None:
        # The quarantine directory is a sibling (not dot-prefixed), so its
        # SKILL.md must be deactivated or the backup shadows the builtin that
        # replaced it in trigger matching, once per numbered copy.
        _make_skill(base, "deploy", "USER original")
        src = _make_skill(builtin_root, "deploy", "packaged builtin")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        discovered = {name for name, _ in skills_mod._iter_skill_files(base)}
        assert "deploy" in discovered
        assert "deploy.user-backup" not in discovered

    def test_empty_placeholder_dir_is_not_quarantined(
        self, builtin_root: Path, base: Path
    ) -> None:
        # App registration leaves an empty ``skills/<name>/`` placeholder
        # behind; there is nothing in it to preserve, so quarantining it would
        # mint a junk backup on every update cycle.
        (base / "deploy").mkdir()
        src = _make_skill(builtin_root, "deploy", "packaged builtin")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        assert "packaged builtin" in (base / "deploy" / "SKILL.md").read_text(encoding="utf-8")
        assert not os.path.lexists(base / "deploy.user-backup")


class TestStaleCleanupGuard:
    """The by-name stale sweep may only delete verifiable sync-installed copies."""

    def test_user_skill_named_cron_survives_startup(
        self, builtin_root: Path, base: Path
    ) -> None:
        # `cron` is in the stale-cleanup set; deletion by name alone is the
        # exact data-loss path this guard closes.
        _make_skill(base, "cron", "my own cron skill")

        _ensure_builtin_skills(base)

        assert "my own cron skill" in (base / "cron" / "SKILL.md").read_text(encoding="utf-8")

    def test_unchanged_sync_installed_stale_copy_is_still_removed(
        self, builtin_root: Path, base: Path
    ) -> None:
        # The guard must not disable the cleanup itself: a copy the sync
        # verifiably installed and that nobody touched is still swept.
        _make_skill(base, "subagent", "old builtin")
        _record_builtin_provenance(base / "subagent")

        _ensure_builtin_skills(base)

        assert not (base / "subagent").exists()

    def test_user_edited_stale_copy_is_left_alone(
        self, builtin_root: Path, base: Path
    ) -> None:
        # A marker whose fingerprint no longer matches means the user edited
        # the copy after install: it is user data and stays at its own name.
        _make_skill(base, "learn", "old builtin")
        _record_builtin_provenance(base / "learn")
        (base / "learn" / "SKILL.md").write_text("USER EDIT", encoding="utf-8")

        _ensure_builtin_skills(base)

        assert (base / "learn" / "SKILL.md").read_text(encoding="utf-8") == "USER EDIT"


class TestLegitimateUpdatesStillHappen:
    """The guard must never freeze normal package updates."""

    def test_unmodified_builtin_is_updated_when_package_ships_newer(
        self, builtin_root: Path, base: Path
    ) -> None:
        src = _make_skill(builtin_root, "helper", "v1", {"scripts/tool.py": "# v1"})
        _ensure_builtin_skills(base)

        (src / "SKILL.md").write_text("---\nname: helper\n---\nv2\n", encoding="utf-8")
        (src / "scripts" / "tool.py").write_text("# v2", encoding="utf-8")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        assert "v2" in (base / "helper" / "SKILL.md").read_text(encoding="utf-8")
        assert (base / "helper" / "scripts" / "tool.py").read_text(encoding="utf-8") == "# v2"
        # Updated cleanly in place: no quarantine involved.
        assert not os.path.lexists(base / "helper.user-backup")

    def test_clean_install_records_provenance(self, builtin_root: Path, base: Path) -> None:
        _make_skill(builtin_root, "helper", "v1")

        _ensure_builtin_skills(base)

        marker = base / "helper" / _PROVENANCE_MARKER
        recorded = marker.read_text(encoding="utf-8").strip()
        assert recorded == _skill_tree_fingerprint(base / "helper")

    def test_pre_provenance_install_is_adopted_then_updated(
        self, builtin_root: Path, base: Path
    ) -> None:
        # First-install migration: an existing install has no marker. When it
        # matches the packaged tree exactly it is adopted as builtin-owned (so
        # builtins are not frozen forever), and a later package update then
        # replaces it without quarantine noise.
        src = _make_skill(builtin_root, "helper", "v1")
        dest = base / "helper"
        import shutil as _shutil

        _shutil.copytree(src, dest)  # a pre-provenance install: no marker

        _ensure_builtin_skills(base)  # adoption pass — no update due
        assert (dest / _PROVENANCE_MARKER).is_file()

        (src / "SKILL.md").write_text("---\nname: helper\n---\nv2\n", encoding="utf-8")
        _bump_mtime(src / "SKILL.md")
        _ensure_builtin_skills(base)

        assert "v2" in (dest / "SKILL.md").read_text(encoding="utf-8")
        assert not os.path.lexists(base / "helper.user-backup")

    def test_diverged_unmarked_dest_is_not_adopted(
        self, builtin_root: Path, base: Path
    ) -> None:
        # A colliding user skill whose SKILL.md is NEWER than the packaged one
        # never becomes update-due; the adoption pass must refuse to bless it
        # (stat manifests differ, so no content is even read).
        src = _make_skill(builtin_root, "deploy", "packaged")
        user = _make_skill(base, "deploy", "USER own", {"notes.txt": "mine"})
        _bump_mtime(user / "SKILL.md")
        assert (user / "SKILL.md").stat().st_mtime > (src / "SKILL.md").stat().st_mtime

        _ensure_builtin_skills(base)

        assert not (user / _PROVENANCE_MARKER).exists()
        assert "USER own" in (user / "SKILL.md").read_text(encoding="utf-8")


class TestFingerprint:
    """The fingerprint covers the full tree, excludes only the marker, and can
    neither hang nor read unbounded bytes on the startup path."""

    def test_identical_trees_match(self, tmp_path: Path) -> None:
        a = _make_skill(tmp_path, "a", "same", {"scripts/x.py": "print(1)"})
        b = _make_skill(tmp_path, "b", "same", {"scripts/x.py": "print(1)"})
        # Same file NAMES and content; names of the roots don't participate.
        (a / "SKILL.md").write_text("body", encoding="utf-8")
        (b / "SKILL.md").write_text("body", encoding="utf-8")
        assert _skill_tree_fingerprint(a) == _skill_tree_fingerprint(b)

    def test_extra_file_changes_fingerprint(self, tmp_path: Path) -> None:
        a = _make_skill(tmp_path, "a", "same")
        before = _skill_tree_fingerprint(a)
        (a / "extra.txt").write_text("x", encoding="utf-8")
        assert _skill_tree_fingerprint(a) != before

    def test_extra_empty_directory_changes_fingerprint(self, tmp_path: Path) -> None:
        a = _make_skill(tmp_path, "a", "same")
        before = _skill_tree_fingerprint(a)
        (a / "assets").mkdir()
        assert _skill_tree_fingerprint(a) != before

    def test_marker_itself_is_excluded(self, tmp_path: Path) -> None:
        a = _make_skill(tmp_path, "a", "same")
        before = _skill_tree_fingerprint(a)
        _record_builtin_provenance(a)
        assert _skill_tree_fingerprint(a) == before

    def test_symlink_target_participates(self, tmp_path: Path) -> None:
        # A symlink is hashed by its target TEXT, never followed: retargeting
        # it diverges the tree, and outside file content can't leak into the
        # fingerprint through a link.
        a = _make_skill(tmp_path, "a", "same")
        os.symlink("target-one", a / "link")
        one = _skill_tree_fingerprint(a)
        os.remove(a / "link")
        os.symlink("target-two", a / "link")
        assert _skill_tree_fingerprint(a) != one

    def test_symlink_and_regular_file_with_same_bytes_differ(self, tmp_path: Path) -> None:
        a = _make_skill(tmp_path, "a", "same")
        b = _make_skill(tmp_path, "b", "same")
        (a / "entry").write_text("payload", encoding="utf-8")
        os.symlink("payload", b / "entry")
        assert _skill_tree_fingerprint(a) != _skill_tree_fingerprint(b)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
    def test_fifo_is_never_opened(self, tmp_path: Path) -> None:
        # Opening a FIFO for reading blocks until a writer appears; on the
        # gateway startup path that is a permanent hang. Special files are
        # classified by lstat and never opened.
        a = _make_skill(tmp_path, "a", "same")
        os.mkfifo(a / "pipe")
        fingerprint = _skill_tree_fingerprint(a)  # must return, not hang
        assert fingerprint is not None

    def test_oversized_tree_is_unprovable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A tree over the read ceiling returns None ("cannot prove"), which
        # matches nothing — the caller then preserves rather than deletes, and
        # startup never reads more than the ceiling from any one tree.
        a = _make_skill(tmp_path, "a", "same")
        (a / "big.bin").write_text("x" * 4096, encoding="utf-8")
        monkeypatch.setattr(skills_mod, "_FINGERPRINT_MAX_BYTES", 1024)
        assert _skill_tree_fingerprint(a) is None

    def test_unreadable_file_is_unprovable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Unprovable, not sentinel-hashed: two unreadable files must never
        # fingerprint as equal, or a diverged tree could be blessed as an
        # exact packaged copy.
        a = _make_skill(tmp_path, "a", "same")
        (a / "hidden.txt").write_text("secret", encoding="utf-8")
        real_open = os.open

        def _deny(path: object, flags: int, *args: object) -> int:
            if "hidden.txt" in str(path):
                raise PermissionError("denied")
            return real_open(path, flags, *args)  # type: ignore[arg-type]

        monkeypatch.setattr(skills_mod.os, "open", _deny)
        assert _skill_tree_fingerprint(a) is None


class TestMarkerHardening:
    """The provenance marker is data the sync wrote, never a path to follow."""

    def test_marker_symlink_is_not_followed_on_write(
        self, builtin_root: Path, base: Path, tmp_path: Path
    ) -> None:
        # A symlink planted at the marker path must not redirect the write
        # outside the skill directory: the atomic write renames a temp file
        # over the link, replacing it.
        victim = tmp_path / "victim.txt"
        victim.write_text("do not touch", encoding="utf-8")
        user = _make_skill(base, "deploy", "USER own")
        os.symlink(victim, user / _PROVENANCE_MARKER)
        src = _make_skill(builtin_root, "deploy", "packaged")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        assert victim.read_text(encoding="utf-8") == "do not touch"

    def test_marker_symlink_reads_as_no_provenance(self, tmp_path: Path) -> None:
        # A symlink at the marker path is not a marker: the directory counts
        # as user-authored ("no provenance") instead of trusting content read
        # through a link.
        a = _make_skill(tmp_path, "a", "own")
        real = tmp_path / "real-marker"
        real.write_text("deadbeef\n", encoding="utf-8")
        os.symlink(real, a / _PROVENANCE_MARKER)
        assert skills_mod._recorded_fingerprint(a) is None


class TestVerificationBounds:
    """Verification stays bounded and crash-free on the startup path."""

    def test_entry_count_over_ceiling_is_unprovable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _make_skill(tmp_path, "a", "same")
        for i in range(8):
            (a / f"f{i}.txt").write_text("x", encoding="utf-8")
        monkeypatch.setattr(skills_mod, "_FINGERPRINT_MAX_ENTRIES", 4)
        assert _skill_tree_fingerprint(a) is None
        assert skills_mod._trees_stat_equal(a, a) is False

    @pytest.mark.skipif(os.name == "nt", reason="hardlink semantics differ")
    def test_hardlinked_file_is_unprovable(self, tmp_path: Path) -> None:
        # A hardlink planted at a walked name aliases an inode that may live
        # anywhere (e.g. a credential file); the descriptor-pinned reader
        # rejects st_nlink > 1, so the tree reads as unprovable instead of
        # hashing the linked bytes.
        a = _make_skill(tmp_path, "a", "same")
        outside = tmp_path / "outside-secret"
        outside.write_text("credential bytes", encoding="utf-8")
        os.link(outside, a / "innocuous.txt")
        assert _skill_tree_fingerprint(a) is None

    def test_link_root_is_unprovable(self, tmp_path: Path) -> None:
        real = _make_skill(tmp_path, "real", "content")
        link = tmp_path / "linked"
        os.symlink(real, link)
        assert _skill_tree_fingerprint(link) is None

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
    def test_unlistable_subdir_makes_collision_preserve_not_crash(
        self, builtin_root: Path, base: Path, request: pytest.FixtureRequest
    ) -> None:
        # A colliding destination with an unlistable subdirectory must read as
        # "has content, unprovable" — quarantined whole — never as empty (which
        # deletes it) and never as a startup crash.
        user = _make_skill(base, "deploy", "USER original")
        locked = user / "locked"
        locked.mkdir()
        (locked / "data.txt").write_text("hidden", encoding="utf-8")
        os.chmod(locked, 0)
        request.addfinalizer(lambda: _restore_locked(base, "deploy"))
        src = _make_skill(builtin_root, "deploy", "packaged")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        assert "packaged" in (base / "deploy" / "SKILL.md").read_text(encoding="utf-8")
        backup = base / "deploy.user-backup"
        assert backup.is_dir()
        assert "USER original" in _backup_skill_md(backup).read_text(encoding="utf-8")

    def test_failed_rmtree_of_verified_copy_restores_dest(
        self, builtin_root: Path, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # When deleting a verified copy fails partway, the remains go back to
        # their own name (retried next run) instead of crashing startup or
        # staying hidden at the claim path.
        src = _make_skill(builtin_root, "helper", "v1")
        _ensure_builtin_skills(base)
        (src / "SKILL.md").write_text("---\nname: helper\n---\nv2\n", encoding="utf-8")
        _bump_mtime(src / "SKILL.md")

        def _refuse(_path: object, **_kw: object) -> None:
            raise OSError("simulated rmtree failure")

        monkeypatch.setattr(skills_mod.shutil, "rmtree", _refuse)
        _ensure_builtin_skills(base)  # must not raise

        assert "v1" in (base / "helper" / "SKILL.md").read_text(encoding="utf-8")
        assert not os.path.lexists(base / ".helper.sync-claim")

    def test_linked_dest_is_quarantined_without_following(
        self, builtin_root: Path, base: Path, tmp_path: Path
    ) -> None:
        # A destination that is a symlink must be moved aside AS a link, to a
        # dot-prefixed name: entering it to deactivate SKILL.md would rename a
        # file inside the link's TARGET tree, outside the skills directory.
        target = _make_skill(tmp_path, "elsewhere", "USER tree behind a link")
        os.symlink(target, base / "deploy")
        src = _make_skill(builtin_root, "deploy", "packaged")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        assert "packaged" in (base / "deploy" / "SKILL.md").read_text(encoding="utf-8")
        # The target tree is untouched, SKILL.md still at its own name.
        assert "USER tree behind a link" in (target / "SKILL.md").read_text(encoding="utf-8")
        moved = base / ".deploy.user-backup"
        assert os.path.islink(moved)

    def test_install_records_packaged_fingerprint_not_dest_state(
        self, builtin_root: Path, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A user write landing in the destination during installation must not
        # be blessed as sync-owned: the marker records the PACKAGED tree, so
        # the raced-in file diverges the destination and is preserved later.
        src = _make_skill(builtin_root, "helper", "v1")
        real_copytree = skills_mod.shutil.copytree

        def _race(src_arg: object, dst_arg: object, **kw: object) -> object:
            result = real_copytree(str(src_arg), str(dst_arg), **kw)
            (Path(str(dst_arg)) / "raced-in.txt").write_text("user", encoding="utf-8")
            return result

        monkeypatch.setattr(skills_mod.shutil, "copytree", _race)
        _ensure_builtin_skills(base)

        recorded = (base / "helper" / skills_mod._PROVENANCE_MARKER).read_text(
            encoding="utf-8"
        ).strip()
        assert recorded == _skill_tree_fingerprint(src)
        assert recorded != _skill_tree_fingerprint(base / "helper")

    def test_project_skill_named_cron_is_not_swept(
        self, builtin_root: Path, base: Path, tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A project source can legitimately ship a skill named after a
        # stale-cleanup entry; a name a source still ships is not stale, so
        # the sweep must not delete what the sync just installed.
        proj = tmp_path / "project-skills"
        proj.mkdir()
        _make_skill(proj, "cron", "project cron skill")
        monkeypatch.setattr(skills_mod, "_project_skills_dir", lambda: proj)

        _ensure_builtin_skills(base)

        installed = base / "cron" / "SKILL.md"
        assert "project cron skill" in installed.read_text(encoding="utf-8")


def _restore_locked(base: Path, name: str) -> None:
    """Re-open permission-locked test dirs so pytest can clean tmp_path."""
    for candidate in base.parent.rglob("locked"):
        try:
            os.chmod(candidate, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        except OSError:
            pass


class TestConcurrentSync:
    """Two processes syncing the same home must not crash each other."""

    def test_concurrent_install_race_keeps_the_winner(
        self, builtin_root: Path, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Another process recreates the destination between our claim and our
        # copytree: losing the race keeps the winner's copy and moves on.
        _make_skill(base, "deploy", "USER original")
        src = _make_skill(builtin_root, "deploy", "packaged")
        _bump_mtime(src / "SKILL.md")
        real_copytree = skills_mod.shutil.copytree

        def _race(src_arg: object, dst_arg: object, **kw: object) -> object:
            real_copytree(str(src_arg), str(dst_arg), **kw)  # winner lands first
            raise FileExistsError(str(dst_arg))

        monkeypatch.setattr(skills_mod.shutil, "copytree", _race)
        _ensure_builtin_skills(base)  # must not raise

        assert "packaged" in (base / "deploy" / "SKILL.md").read_text(encoding="utf-8")
        assert "USER original" in _backup_skill_md(base / "deploy.user-backup").read_text(
            encoding="utf-8"
        )


class TestEventLoopGuard:
    """Loader construction on a running event loop must not run the sync."""

    def test_sync_skipped_on_running_loop(
        self, builtin_root: Path, base: Path
    ) -> None:
        import asyncio

        _make_skill(builtin_root, "deploy", "packaged")

        async def _build() -> None:
            skills_mod.SkillsLoader(skills_path=base)

        asyncio.run(_build())
        assert not (base / "deploy").exists()

    def test_sync_runs_off_loop(self, builtin_root: Path, base: Path) -> None:
        _make_skill(builtin_root, "deploy", "packaged")
        skills_mod.SkillsLoader(skills_path=base)
        assert (base / "deploy" / "SKILL.md").is_file()


class TestQuarantineDeactivationFallback:
    """A quarantine whose SKILL.md cannot be renamed is hidden whole."""

    def test_failed_deactivation_hides_the_backup(
        self, builtin_root: Path, base: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_skill(base, "deploy", "USER original")
        src = _make_skill(builtin_root, "deploy", "packaged")
        _bump_mtime(src / "SKILL.md")
        real_replace = os.replace

        def _deny_skill_md(src_arg: object, dst_arg: object) -> None:
            if str(dst_arg).endswith("SKILL.md.user-backup"):
                raise OSError("simulated deactivation failure")
            real_replace(src_arg, dst_arg)  # type: ignore[arg-type]

        monkeypatch.setattr(skills_mod.os, "replace", _deny_skill_md)
        _ensure_builtin_skills(base)

        hidden = base / ".deploy.user-backup"
        assert hidden.is_dir()
        assert "USER original" in (hidden / "SKILL.md").read_text(encoding="utf-8")
        discovered = {name for name, _ in skills_mod._iter_skill_files(base)}
        assert not any("user-backup" in n for n in discovered)

    def test_sync_builtins_seam_syncs_explicitly(
        self, builtin_root: Path, base: Path
    ) -> None:
        # The explicit seam works regardless of construction context: a loader
        # built without syncing (as the gateway does before its socket binds)
        # syncs when told to, from the worker-thread background task.
        _make_skill(builtin_root, "deploy", "packaged")
        loader = skills_mod.SkillsLoader(skills_path=base, install_builtins=False)
        assert not (base / "deploy").exists()
        loader.sync_builtins()
        assert (base / "deploy" / "SKILL.md").is_file()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
    def test_mode_change_diverges_fingerprint(self, tmp_path: Path) -> None:
        # A mode-only customization (chmod +x on a script) is a user edit:
        # it must diverge the tree so an update preserves it instead of
        # silently resetting the mode.
        a = _make_skill(tmp_path, "a", "same", {"scripts/run.sh": "echo hi"})
        before = _skill_tree_fingerprint(a)
        os.chmod(a / "scripts" / "run.sh", 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        assert _skill_tree_fingerprint(a) != before

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
    def test_fifo_skill_md_in_backup_is_deactivated(
        self, builtin_root: Path, base: Path
    ) -> None:
        # Whatever occupies the SKILL.md name in a quarantined tree must stop
        # being discoverable — a FIFO left live there would block the first
        # reader that opens it.
        user = base / "deploy"
        user.mkdir()
        os.mkfifo(user / "SKILL.md")
        src = _make_skill(builtin_root, "deploy", "packaged")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        backup = base / "deploy.user-backup"
        assert backup.is_dir()
        assert not os.path.lexists(backup / "SKILL.md")
        assert os.path.lexists(backup / "SKILL.md.user-backup")

    def test_nested_empty_directory_structure_is_preserved(
        self, builtin_root: Path, base: Path
    ) -> None:
        # A colliding tree holding only empty subdirectories is still
        # user-made structure: it must be quarantined, not deleted. Only a
        # zero-entry directory counts as content-free.
        (base / "deploy" / "layouts" / "drafts").mkdir(parents=True)
        src = _make_skill(builtin_root, "deploy", "packaged")
        _bump_mtime(src / "SKILL.md")

        _ensure_builtin_skills(base)

        assert (base / "deploy.user-backup" / "layouts" / "drafts").is_dir()
        assert "packaged" in (base / "deploy" / "SKILL.md").read_text(encoding="utf-8")
