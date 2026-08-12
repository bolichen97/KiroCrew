"""A table the pass cannot read fails CLOSED, and validation matches what readers need.

Both are the same mistake in different places: a branch that could not do its job chose to
continue rather than refuse. The redaction pass exists to keep credentials off the wire, so
"could not inspect this table" cannot mean "ship it".
"""

from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path

import pytest

from kiro_crew import snapshot as snap
from kiro_crew import snapshot_redact as redact

TOKEN = "8412345678:AAH9xSECRETtokenvalue_here12345"


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr(snap, "_mc_dir", lambda: h)
    monkeypatch.setattr(snap, "_is_gateway_running", lambda: False)
    return h


class TestATableThatCannotBeInspectedDropsTheDatabase:
    def test_a_without_rowid_table_is_not_silently_skipped(self, tmp_path):
        """`WITHOUT ROWID` has no rowid handle -- the database must go, not the table."""
        db = tmp_path / "memory.db"
        conn = redact.sqlite3.connect(str(db))
        conn.execute("CREATE TABLE norowid (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
        conn.execute("INSERT INTO norowid VALUES (?, ?)", ("aws", f"token {TOKEN}"))
        conn.commit()
        conn.close()

        stage = tmp_path / "stage"
        stage.mkdir()
        (db).replace(stage / "memory.db")
        (stage / "MANIFEST.json").write_text(
            json.dumps({"version": 3, "components": {"memory": "unresolved"}}),
            encoding="utf-8",
        )

        report = redact.redact_bundle_for_egress(stage)
        assert not (stage / "memory.db").exists(), (
            "a database with an uninspectable table was left in the outbound copy"
        )
        assert "memory.db" in report.dropped, report.dropped
        assert any("memory.db" in s for s in report.skipped_unreadable), (
            report.skipped_unreadable
        )

    def test_an_ordinary_table_is_still_redacted_in_place(self, tmp_path):
        """The refusal must not swallow the normal path."""
        db = tmp_path / "memory.db"
        conn = redact.sqlite3.connect(str(db))
        conn.execute("CREATE TABLE ok (k, v)")
        conn.execute("INSERT INTO ok VALUES (?, ?)", ("aws", f"token {TOKEN}"))
        conn.commit()
        conn.close()

        stage = tmp_path / "stage"
        stage.mkdir()
        db.replace(stage / "memory.db")
        report = redact.redact_bundle_for_egress(stage)

        assert (stage / "memory.db").is_file(), "an inspectable database was dropped"
        assert report.replacements.get("memory.db"), report.replacements
        conn = redact.sqlite3.connect(str(stage / "memory.db"))
        assert conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        assert TOKEN not in conn.execute("SELECT v FROM ok").fetchone()[0]
        conn.close()

    def test_no_branch_skips_a_table_it_could_not_read(self):
        """A table that cannot be read must refuse; a DERIVED one may be skipped.

        Pinned as two properties rather than a ban on `continue`, because the FTS shadow
        tables are legitimately skipped -- they are regenerated from the content table, so
        skipping them is part of redacting rather than a hole in it. What must never come
        back is turning an unreadable table into a silent pass.
        """
        import inspect

        src = inspect.getsource(redact._redact_database)
        assert "except sqlite3.DatabaseError:\n                    continue" not in src, (
            "an unreadable table is skipped instead of refusing the database"
        )
        assert src.count("_TableNotInspectable(") == 3, (
            "every state this pass cannot prove clean must refuse: a table with no rowid, "
            "a table with no columns, and a database that never settles because a trigger "
            "keeps reintroducing values"
        )
        assert "if table in skip_tables:" in src, (
            "only positively-identified derived tables may be skipped"
        )

    def test_an_fts_database_survives_and_loses_the_credential(self, tmp_path):
        """The fail-closed rule must not delete the Knowledge Library.

        FTS5 keeps two `WITHOUT ROWID` shadow tables, so refusing on that basis would drop
        every knowledge database from the outbound copy. Redacting the content and
        rebuilding the index is what removes the term: the inverted index holds it as
        index structure, so a redacted content table with a stale index still answers a
        search for the credential.
        """
        key = "ghp_" + "C" * 36
        stage = tmp_path / "stage"
        (stage / "workspace" / "knowledge").mkdir(parents=True)
        db = stage / "workspace" / "knowledge" / "knowledge.db"

        conn = redact.sqlite3.connect(str(db))
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, title, content)")
        conn.execute("CREATE VIRTUAL TABLE items_fts USING fts5(title, content)")
        conn.execute(
            "INSERT INTO items (title, content) VALUES (?, ?)", ("n", f"key {key} here")
        )
        conn.execute(
            "INSERT INTO items_fts (rowid, title, content) VALUES (?, ?, ?)",
            (1, "n", f"key {key} here"),
        )
        conn.commit()
        conn.close()

        assert key.encode() in db.read_bytes(), "premise: the key is in the file"
        report = redact.redact_bundle_for_egress(stage)

        assert db.is_file(), f"the knowledge database was deleted: {report.dropped}"
        assert key.encode() not in db.read_bytes(), (
            "the credential survived in the file, most likely in the inverted index"
        )

        conn = redact.sqlite3.connect(str(db))
        assert conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        assert conn.execute("SELECT count(*) FROM items").fetchone()[0] == 1
        assert conn.execute(
            "SELECT count(*) FROM items_fts WHERE items_fts MATCH ?", (key,)
        ).fetchone()[0] == 0, "the index still matches the redacted credential"
        assert conn.execute(
            "SELECT count(*) FROM items_fts WHERE items_fts MATCH ?", ("here",)
        ).fetchone()[0] == 1, "redaction broke ordinary search"
        conn.close()

    def test_an_external_content_fts_database_is_redacted_and_kept(self, tmp_path):
        """The shape this product actually uses: `content=items, content_rowid=id`.

        With external content there is no `_content` shadow table and the virtual table is
        READ-ONLY for content, so the term can only leave the index by rebuilding it from
        the redacted base table. A fixture using a standard fts5 table passes without the
        rebuild for the wrong reason -- writing through the virtual table happens to fix
        both halves there -- which is why this case is pinned separately.
        """
        key = "ghp_" + "E" * 36
        stage = tmp_path / "stage"
        stage.mkdir()
        db = stage / "knowledge.db"

        conn = redact.sqlite3.connect(str(db))
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, title, content, tags)")
        conn.execute(
            "CREATE VIRTUAL TABLE items_fts USING fts5("
            "title, content, tags, content=items, content_rowid=id)"
        )
        conn.execute(
            "INSERT INTO items (title, content, tags) VALUES (?, ?, ?)",
            ("n", f"k {key} z", "t"),
        )
        conn.execute("INSERT INTO items_fts(items_fts) VALUES('rebuild')")
        conn.commit()
        assert conn.execute(
            "SELECT count(*) FROM items_fts WHERE items_fts MATCH ?", (key,)
        ).fetchone()[0] == 1, "premise: the index matches the key"
        conn.close()

        report = redact.redact_bundle_for_egress(stage)
        assert db.is_file(), f"the knowledge database was deleted: {report.dropped}"
        assert key.encode() not in db.read_bytes(), (
            "the credential survived in the index -- the rebuild did not run"
        )

        conn = redact.sqlite3.connect(str(db))
        assert conn.execute("PRAGMA integrity_check;").fetchone()[0] == "ok"
        assert conn.execute(
            "SELECT count(*) FROM items_fts WHERE items_fts MATCH ?", (key,)
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT count(*) FROM items_fts WHERE items_fts MATCH ?", ("z",)
        ).fetchone()[0] == 1, "redaction broke ordinary search"
        conn.close()

    def test_an_unrecognised_rowidless_table_still_refuses(self, tmp_path):
        """The exemption is for identified FTS shadow storage, not for rowid-less tables."""
        stage = tmp_path / "stage"
        stage.mkdir()
        db = stage / "memory.db"
        conn = redact.sqlite3.connect(str(db))
        conn.execute("CREATE TABLE odd (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
        conn.execute("INSERT INTO odd VALUES ('a', 'b')")
        conn.commit()
        conn.close()

        report = redact.redact_bundle_for_egress(stage)
        assert not db.exists(), "a rowid-less table outside FTS was silently skipped"
        assert "memory.db" in report.dropped, report.dropped


class TestCronValidationMatchesWhatTheReaderNeeds:
    def test_a_jobs_list_of_strings_is_refused(self, home, tmp_path):
        """`{"jobs": ["x"]}` is a valid object whose reader calls `.get` on a str."""
        payload = tmp_path / "kirocrew-snapshot-20260101T000000Z"
        payload.mkdir(parents=True)
        (payload / "crons.json").write_text('{"jobs": ["x"]}', encoding="utf-8")

        with pytest.raises(snap.SourceComponentUnsound) as e:
            snap._refuse_corrupt_source_databases(payload, ["crons"], mc_for_merge=home)
        assert "jobs[0]" in str(e.value), str(e.value)

    def test_a_jobs_value_that_is_not_a_list_is_refused(self, home, tmp_path):
        payload = tmp_path / "kirocrew-snapshot-20260101T000000Z"
        payload.mkdir(parents=True)
        (payload / "crons.json").write_text('{"jobs": {"a": 1}}', encoding="utf-8")

        with pytest.raises(snap.SourceComponentUnsound) as e:
            snap._refuse_corrupt_source_databases(payload, ["crons"], mc_for_merge=home)
        assert "not a list" in str(e.value), str(e.value)

    def test_a_well_formed_crons_file_still_passes(self, home, tmp_path):
        payload = tmp_path / "kirocrew-snapshot-20260101T000000Z"
        payload.mkdir(parents=True)
        (payload / "crons.json").write_text(
            '{"jobs": [{"name": "a"}, {"name": "b"}]}', encoding="utf-8"
        )
        snap._refuse_corrupt_source_databases(payload, ["crons"], mc_for_merge=home)

    def test_an_absent_jobs_key_is_not_invented(self, home, tmp_path):
        payload = tmp_path / "kirocrew-snapshot-20260101T000000Z"
        payload.mkdir(parents=True)
        (payload / "crons.json").write_text('{"other": 1}', encoding="utf-8")
        snap._refuse_corrupt_source_databases(payload, ["crons"], mc_for_merge=home)

    def test_the_merge_reader_never_sees_a_bad_entry(self, home, tmp_path, capsys):
        """End to end: the refusal lands before `_merge_crons` touches live state."""
        (home / "crons.json").write_text('{"jobs": [{"name": "mine"}]}', encoding="utf-8")
        payload = tmp_path / "kirocrew-snapshot-20260101T000000Z"
        payload.mkdir(parents=True)
        (payload / "crons.json").write_text('{"jobs": ["x"]}', encoding="utf-8")
        (payload / "MANIFEST.json").write_text(
            json.dumps({"version": 3, "components": {"crons": "unresolved"}}),
            encoding="utf-8",
        )
        bundle = tmp_path / "b.tar.gz"
        with tarfile.open(bundle, "w:gz") as tf:
            tf.add(str(payload), arcname=payload.name)

        rc = snap.restore_main(
            [str(bundle), "--mode", "merge", "--force", "--components", "crons"]
        )
        out = capsys.readouterr().out
        assert rc == 1, out
        assert "Traceback" not in out
        assert '{"jobs": [{"name": "mine"}]}' == (
            home / "crons.json"
        ).read_text(encoding="utf-8"), "live crons were modified before the refusal"


class TestTheConfigImportIsAtModuleScope:
    def test_the_upload_path_does_not_import_it_locally(self):
        import inspect

        src = inspect.getsource(snap._redacted_upload_copy)
        assert "from kiro_crew.config.loader import" not in src, (
            "the config import came back inside the function"
        )
        assert callable(snap.KiroCrewConfig.load)

    def test_the_schema_query_uses_the_current_table_name(self):
        """The codebase already queries `sqlite_schema`; this module matches it."""
        source = Path(redact.__file__).read_text(encoding="utf-8")
        assert "sqlite_schema" in source, source[:0]
        assert argparse  # namespace kept meaningful for the upload-path callers above
