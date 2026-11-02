"""Journal history and restoring a specific past state (recovery path)."""

import contextlib
import io
import json
import os
import unittest

from helpers import TempDirCase, sample_app, write

from surreal import cli, patcher
from surreal.util import sha256_file


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class HistoryCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.app = write(self.path("app.exe"), sample_app())
        self.patched = write(self.path("new.exe"), sample_app(patch=True))
        self.bundle = self.path("one.morph")
        self.second = self.path("two.morph")
        run("diff", self.app, self.patched, "-o", self.bundle, "--id", "org.test.one")
        run("diff", self.app, self.patched, "-o", self.second, "--id", "org.test.two")
        run("init", "--accept-policy")
        self.pristine = sha256_file(self.app)
        self.patched_sha = sha256_file(self.patched)

    def apply(self, bundle=None):
        code, _out, err = run("apply", bundle or self.bundle, "--target", self.app,
                              "-y", "--keep-backups", "0")
        self.assertEqual(code, 0, err)


class TestHistory(HistoryCase):
    def test_empty_history(self):
        code, out, _ = run("history", self.app)
        self.assertEqual(code, 0)
        self.assertIn("nothing has been patched here yet", out)

    def test_lists_states_newest_first(self):
        self.apply(self.bundle)
        run("undo", self.app)
        self.apply(self.second)
        items = patcher.history(self.app)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["index"], 1)
        self.assertEqual(items[0]["bundle_id"], "org.test.two")
        self.assertEqual(items[1]["bundle_id"], "org.test.one")
        self.assertTrue(all(item["restorable"] for item in items))

    def test_text_output_shows_a_restore_command(self):
        self.apply()
        code, out, _ = run("history", self.app)
        self.assertEqual(code, 0)
        self.assertIn("org.test.one", out)
        self.assertIn("--from 1", out)

    def test_json_is_scriptable(self):
        self.apply()
        code, out, _ = run("history", self.app, "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(data["states"][0]["index"], 1)
        self.assertTrue(os.path.isfile(data["states"][0]["backup"]))
        self.assertEqual(data["states"][0]["sha256_before"], self.pristine)

    def test_untouched_files_are_not_mixed_in(self):
        other = write(self.path("other.exe"), sample_app())
        self.apply()
        items = patcher.history(other)
        self.assertEqual(items, [])


class TestRestore(HistoryCase):
    def test_restores_the_newest_state(self):
        self.apply()
        self.assertEqual(run("restore", self.app)[0], 0)
        self.assertEqual(sha256_file(self.app), self.pristine)

    def test_restores_an_older_state(self):
        self.apply(self.bundle)
        run("undo", self.app)
        self.apply(self.second)
        # state 2 is the "before the second patch" snapshot, i.e. pristine again
        code, out, err = run("restore", self.app, "--from", "2")
        self.assertEqual(code, 0, err)
        self.assertIn("state 2", out)
        self.assertEqual(sha256_file(self.app), self.pristine)

    def test_out_of_range_is_a_usage_error(self):
        self.apply()
        code, _out, err = run("restore", self.app, "--from", "7")
        self.assertEqual(code, 2)
        self.assertIn("out of range", err)

    def test_zero_is_refused(self):
        self.apply()
        code, _out, err = run("restore", self.app, "--from", "0")
        self.assertEqual(code, 2)
        self.assertIn("counts from 1", err)

    def test_no_history_is_a_mismatch(self):
        code, _out, err = run("restore", self.app)
        self.assertEqual(code, 3)
        self.assertIn("nothing to restore", err)

    def test_missing_target(self):
        code, _out, err = run("restore", self.path("ghost.exe"))
        self.assertEqual(code, 5)
        self.assertIn("target not found", err)

    def test_refuses_when_the_file_changed_meanwhile(self):
        self.apply()
        os.remove(self.app)
        write(self.app, b"something else entirely")
        code, _out, err = run("restore", self.app)
        self.assertEqual(code, 3)
        self.assertIn("has changed since", err)
        # ... unless the user insists
        code, _out, err = run("restore", self.app, "--force")
        self.assertEqual(code, 0, err)
        self.assertEqual(sha256_file(self.app), self.pristine)

    def test_a_deleted_backup_is_reported_not_guessed(self):
        self.apply()
        backup = patcher.history(self.app)[0]["backup"]
        os.remove(backup)
        code, _out, err = run("restore", self.app)
        self.assertEqual(code, 5)
        self.assertIn("backup", err)
        # and history says so rather than offering it
        items = patcher.history(self.app)
        self.assertFalse(items[0]["restorable"])
        self.assertFalse(items[0]["backup_exists"])

    def test_a_tampered_backup_is_refused(self):
        self.apply()
        backup = patcher.history(self.app)[0]["backup"]
        write(backup, b"\0" * os.path.getsize(backup))
        code, _out, err = run("restore", self.app)
        self.assertEqual(code, 3)
        self.assertIn("no longer matches", err)

    def test_restore_records_itself(self):
        self.apply()
        run("restore", self.app)
        actions = [e["action"] for e in
                   __import__("surreal.journal", fromlist=["Journal"]).Journal(
                       self.app).entries]
        self.assertEqual(actions[-1], "restore")

    def test_undo_after_restore_is_a_friendly_no_op(self):
        self.apply()
        self.assertEqual(run("restore", self.app)[0], 0)
        code, _out, err = run("undo", self.app)
        self.assertEqual(code, 0)
        self.assertIn("already has its original bytes", err)
        self.assertEqual(sha256_file(self.app), self.pristine)

    def test_restore_needs_the_policy(self):
        self.apply()
        run("init", "--revoke")          # revoke *after* patching
        code, _out, err = run("restore", self.app)
        self.assertEqual(code, 4)
        self.assertIn("policy", err.lower())
        self.assertEqual(sha256_file(self.app), self.patched_sha)


if __name__ == "__main__":
    unittest.main()
