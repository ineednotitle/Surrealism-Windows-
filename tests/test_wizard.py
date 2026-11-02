"""Easy mode, doctor and undo: the paths a first-time user actually walks."""

import contextlib
import io
import json
import os
import unittest
import unittest.mock

from helpers import TempDirCase, sample_app, write

from surreal import cli, policy, wizard
from surreal.util import sha256_file


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def answers(*lines):
    """Feed canned answers to the wizard's prompt (EOF after the last one)."""
    queue = list(lines)

    def fake(_prompt=""):
        if not queue:
            raise EOFError
        return queue.pop(0)

    return unittest.mock.patch.object(wizard, "_ask", fake)


class WizardCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self._cwd = os.getcwd()
        self.dir = self.path("app")
        os.makedirs(self.dir, exist_ok=True)
        self.app = write(os.path.join(self.dir, "demo.exe"), sample_app())
        self.patched = write(os.path.join(self.dir, "fixed.exe"),
                             sample_app(patch=True))
        self.bundle = os.path.join(self.dir, "tweak.morph")
        code, _out, err = run("diff", self.app, self.patched, "-o", self.bundle,
                              "--id", "org.test.wizard", "--name", "Wizard tweak")
        self.assertEqual(code, 0, err)

    def tearDown(self):
        os.chdir(self._cwd)
        super().tearDown()

    def make_bundle(self, name, app, patched, bundle_id):
        path = os.path.join(self.dir, name)
        code, _out, err = run("diff", app, patched, "-o", path, "--id", bundle_id,
                              "--name", bundle_id)
        self.assertEqual(code, 0, err)
        return path


# --------------------------------------------------------------------------- #
# routing and discovery
# --------------------------------------------------------------------------- #
class TestRouting(WizardCase):
    def test_dropped_file_is_routed_to_easy(self):
        argv = cli._redirect_dropped_file([self.app])
        self.assertEqual(argv[0], "easy")
        self.assertEqual(argv[1], self.app)

    def test_known_commands_are_left_alone(self):
        for first in ("inspect", "apply", "collection", "doctor"):
            self.assertEqual(cli._redirect_dropped_file([first, "x"])[0], first)

    def test_flags_are_left_alone(self):
        self.assertEqual(cli._redirect_dropped_file(["--json", "inspect"]),
                         ["--json", "inspect"])

    def test_path_lookalikes(self):
        self.assertTrue(wizard.looks_like_path("C:/Temp/app.exe"))
        self.assertTrue(wizard.looks_like_path("./patch.morph"))
        self.assertTrue(wizard.looks_like_path("not-there.exe"))
        self.assertFalse(wizard.looks_like_path("--json"))
        self.assertFalse(wizard.looks_like_path("frobnicate"))

    def test_no_arguments_without_a_terminal_prints_help(self):
        code, out, _ = run()
        self.assertEqual(code, 0)
        self.assertIn("usage", out.lower())

    def test_finds_bundles_next_to_the_target(self):
        found = wizard.find_patches(self.app)
        self.assertIn(os.path.abspath(self.bundle), found)

    def test_finds_bundles_in_a_patches_subfolder(self):
        sub = os.path.join(self.dir, "patches")
        os.makedirs(sub, exist_ok=True)
        moved = os.path.join(sub, "moved.morph")
        os.replace(self.bundle, moved)
        self.assertIn(os.path.abspath(moved), wizard.find_patches(self.app))

    def test_finds_bundles_via_environment(self):
        elsewhere = self.path("shared")
        os.makedirs(elsewhere, exist_ok=True)
        moved = os.path.join(elsewhere, "shared.morph")
        os.replace(self.bundle, moved)
        with unittest.mock.patch.dict(os.environ, {wizard.PATCH_ENV: elsewhere}):
            self.assertIn(os.path.abspath(moved), wizard.find_patches(self.app))

    def test_explicit_patch_folder_wins_the_search_order(self):
        extra = self.path("downloads")
        os.makedirs(extra, exist_ok=True)
        dirs = wizard.search_dirs(self.app, [extra])
        self.assertEqual(dirs[0], os.path.abspath(extra))


# --------------------------------------------------------------------------- #
# verdicts
# --------------------------------------------------------------------------- #
class TestVerdicts(WizardCase):
    def test_bundle_that_matches_this_build(self):
        verdicts = wizard.evaluate(self.app)
        self.assertEqual(len(verdicts), 1)
        self.assertTrue(verdicts[0].usable)
        self.assertEqual(verdicts[0].reason, "works with this build")

    def test_bundle_for_another_build_is_explained_not_applied(self):
        other = write(os.path.join(self.dir, "other.exe"), sample_app(patch=True))
        verdicts = wizard.evaluate(other)
        self.assertEqual(len(verdicts), 1)
        self.assertFalse(verdicts[0].applies)
        self.assertIn("different", verdicts[0].reason)

    def test_tiny_build_says_the_sizes(self):
        # a size mismatch should quote both sizes so the user can tell versions apart
        small = write(os.path.join(self.dir, "small.exe"), sample_app()[:-0x200])
        verdicts = wizard.evaluate(small)
        self.assertFalse(verdicts[0].applies)
        self.assertIn("bytes", verdicts[0].reason)

    def test_non_pe_target_is_refused_with_advice(self):
        fake = write(self.path("setup.exe"), b"this is really a zip")
        with self.assertRaises(wizard.WizardError) as ctx:
            wizard.resolve_target(None, fake)
        self.assertIn("does not look like a Windows program", str(ctx.exception))

    def test_empty_file_says_so(self):
        empty = write(self.path("empty.exe"), b"")
        with self.assertRaises(wizard.WizardError) as ctx:
            wizard.resolve_target(None, empty)
        self.assertIn("empty", str(ctx.exception))

    def test_quoted_drag_and_drop_path_is_accepted(self):
        path, is_dir = wizard.resolve_target(None, '  "%s"  ' % self.app)
        self.assertEqual(path, os.path.abspath(self.app))
        self.assertFalse(is_dir)

    def test_missing_path_is_a_usage_error(self):
        with self.assertRaises(wizard.WizardError) as ctx:
            wizard.resolve_target(None, self.path("nope.exe"))
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("Drag the file", str(ctx.exception))


# --------------------------------------------------------------------------- #
# the flow
# --------------------------------------------------------------------------- #
class TestEasyFlow(WizardCase):
    def test_applies_everything_with_yes(self):
        before = sha256_file(self.app)
        code, out, err = run("easy", self.app, "--yes")
        self.assertEqual(code, 0, err)
        self.assertIn("is patched", out)
        self.assertNotEqual(sha256_file(self.app), before)
        self.assertIn("surreal undo", out)

    def test_undo_puts_the_original_back(self):
        before = sha256_file(self.app)
        self.assertEqual(run("easy", self.app, "--yes")[0], 0)
        code, out, err = run("undo", self.app)
        self.assertEqual(code, 0, err)
        self.assertIn("restored", out)
        self.assertEqual(sha256_file(self.app), before)

    def test_undo_on_an_untouched_file_is_not_an_error(self):
        code, out, err = run("undo", self.app)
        self.assertEqual(code, 0)
        self.assertIn("already looks original", out + err)

    def test_policy_declined_writes_nothing(self):
        before = sha256_file(self.app)
        with answers("n"):
            code, out, _ = run("easy", self.app)
        self.assertEqual(code, 4)
        self.assertIn("Nothing was changed", out)
        self.assertEqual(sha256_file(self.app), before)
        self.assertFalse(policy.policy_accepted())

    def test_piped_answers_drive_the_whole_flow(self):
        before = sha256_file(self.app)
        with answers("y", "a", "y"):
            code, out, err = run("easy", self.app)
        self.assertEqual(code, 0, err)
        self.assertTrue(policy.policy_accepted())
        self.assertIn("is patched", out)
        self.assertNotEqual(sha256_file(self.app), before)

    def test_quit_at_the_choice_writes_nothing(self):
        run("init", "--accept-policy")
        before = sha256_file(self.app)
        with answers("q"):
            code, out, err = run("easy", self.app)
        self.assertEqual(code, 0)
        self.assertIn("nothing was changed", (out + err).lower())
        self.assertEqual(sha256_file(self.app), before)

    def test_no_matching_patch_explains_how_to_make_one(self):
        run("init", "--accept-policy")
        other = write(os.path.join(self.dir, "different.exe"), sample_app(patch=True))
        code, out, err = run("easy", other, "--yes")
        self.assertEqual(code, 3)
        self.assertIn("surreal diff", out + err)
        self.assertIn("doctor", out + err)

    def test_no_patches_at_all_lists_where_it_looked(self):
        lonely = self.path("lonely")
        os.makedirs(lonely, exist_ok=True)
        app = write(os.path.join(lonely, "app.exe"), sample_app())
        os.chdir(lonely)
        try:
            code, out, err = run("easy", app, "--yes")
        finally:
            os.chdir(self._cwd)
        self.assertEqual(code, 3)
        self.assertIn("no patch files", out + err)
        self.assertIn("I looked in", out + err)

    def test_signed_bundle_is_labelled(self):
        run("init", "--accept-policy")
        key = self.path("k.key")
        self.assertEqual(run("keys", "--generate", key, "--label", "me")[0], 0)
        self.assertEqual(run("sign", self.bundle, "--key", key)[0], 0)
        code, out, _ = run("easy", self.app, "--yes")
        self.assertEqual(code, 0)
        self.assertIn("signed by", out)

    def test_failure_of_a_later_patch_rolls_the_earlier_one_back(self):
        run("init", "--accept-policy")
        pristine = sha256_file(self.app)
        # a second bundle that claims to target this file but cannot apply
        broken_path = self.make_bundle("broken.morph", self.app, self.patched,
                                       "org.test.broken")
        from surreal.patchfile import Bundle

        broken = Bundle.load(broken_path)
        broken.hunks[0].replace = bytearray(broken.hunks[0].replace)
        broken.hunks[0].expect = bytearray(broken.hunks[0].replace)
        broken.hunks[0].expect[0] = (broken.hunks[0].expect[0] + 1) % 256
        broken.save(broken_path)
        code, out, err = run("easy", self.app, "--yes")
        self.assertEqual(code, 3, err)
        self.assertIn("rolled back", out)
        self.assertEqual(sha256_file(self.app), pristine)

    def test_folder_without_a_patch_set_says_what_to_do(self):
        code, out, err = run("easy", self.dir, "--yes")
        self.assertEqual(code, 2)
        self.assertIn("no patch set", out + err)

    def test_folder_with_a_patch_set_patches_as_one_transaction(self):
        run("init", "--accept-policy")
        manifest = os.path.join(self.dir, "surreal-collection.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"format": "surreal.collection", "format_version": 1,
                       "name": "Folder set",
                       "patches": [{"bundle": "tweak.morph",
                                    "target": "demo.exe", "order": 10}]}, fh)
        before = sha256_file(self.app)
        code, out, err = run("easy", self.dir, "--yes")
        self.assertEqual(code, 0, err)
        self.assertIn("one transaction", out)
        self.assertNotEqual(sha256_file(self.app), before)
        self.assertEqual(run("undo", self.app)[0], 0)
        self.assertEqual(sha256_file(self.app), before)


# --------------------------------------------------------------------------- #
# JSON mode
# --------------------------------------------------------------------------- #
class TestEasyJson(WizardCase):
    def test_dry_run_lists_patches(self):
        code, out, _ = run("--json", "easy", self.app)
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertTrue(data["dry_run"])
        self.assertEqual(data["patches"][0]["id"], "org.test.wizard")
        self.assertTrue(data["patches"][0]["applies"])
        self.assertEqual(data["applied"], [])

    def test_apply_needs_explicit_yes(self):
        run("init", "--accept-policy")
        code, out, _ = run("--json", "easy", self.app, "-y")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertFalse(data["dry_run"])
        self.assertEqual(data["applied"][0]["id"], "org.test.wizard")
        self.assertTrue(os.path.isfile(data["applied"][0]["backup"]))

    def test_apply_without_policy_reports_exit_4(self):
        code, out, _ = run("--json", "easy", self.app, "-y")
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(out)["exit_code"], 4)

    def test_mismatch_is_json_too(self):
        other = write(os.path.join(self.dir, "diff.exe"), sample_app(patch=True))
        code, out, _ = run("--json", "easy", other)
        self.assertEqual(code, 3)
        data = json.loads(out)
        self.assertFalse(data["ok"])
        self.assertFalse(data["patches"][0]["applies"])

    def test_missing_argument_is_a_usage_error(self):
        code, out, _ = run("--json", "easy")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["exit_code"], 2)


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
class TestDoctor(WizardCase):
    def test_clean_machine_and_file(self):
        run("init", "--accept-policy")
        code, out, err = run("doctor", self.app)
        self.assertEqual(code, 0, err)
        self.assertIn("PE image", out)
        self.assertIn("works with this build", out)
        self.assertIn("ready to patch", out)

    def test_policy_not_accepted_is_only_a_note(self):
        code, out, _ = run("doctor", self.app)
        self.assertEqual(code, 0)
        self.assertIn("not accepted yet", out)

    def test_missing_target_is_reported(self):
        code, out, err = run("doctor", self.path("ghost.exe"))
        self.assertEqual(code, 3)
        self.assertIn("nothing at", out + err)

    def test_no_patches_is_reported_with_the_search_path(self):
        lonely = self.path("lonely")
        os.makedirs(lonely, exist_ok=True)
        app = write(os.path.join(lonely, "app.exe"), sample_app())
        os.chdir(lonely)
        try:
            code, out, err = run("doctor", app)
        finally:
            os.chdir(self._cwd)
        self.assertEqual(code, 0)
        self.assertIn("no .morph patch files found", out + err)

    def test_folder_manifest_is_simulated(self):
        manifest = os.path.join(self.dir, "surreal-collection.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"format": "surreal.collection", "format_version": 1,
                       "name": "Folder set",
                       "patches": [{"bundle": "tweak.morph",
                                    "target": "demo.exe", "order": 10}]}, fh)
        code, out, _ = run("doctor", self.dir)
        self.assertEqual(code, 0)
        self.assertIn("simulate cleanly", out)

    def test_doctor_json_mode_stays_parseable(self):
        code, out, _ = run("doctor", self.app, "--json")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["ok"])


if __name__ == "__main__":
    unittest.main()
