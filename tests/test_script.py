"""Declarative conditions: bundle-level ``requires`` and per-hunk ``when``."""

import json
import os
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import cli, patcher, script
from surreal.patchfile import Bundle, BundleError
from surreal.util import sha256_file

TEXT = 0x60000020
RDATA = 0x40000040


def bundle_dict(**over):
    """A minimal valid in-place bundle for ``sample_app()`` hunks at 0x251."""
    base = {
        "format": "surreal.morph",
        "format_version": 1,
        "id": "org.test.cond",
        "name": "Conditions",
        "target": {"filename": "app.exe", "size": len(sample_app())},
        "hunks": [{"offset": 0x251, "expect": "7F", "replace": "EB",
                   "comment": "flip the branch"}],
    }
    base.update(over)
    return base


class ScriptExpressions(unittest.TestCase):
    def setUp(self):
        self.data = sample_app()

    def result(self, cond, data=None, pe=None):
        return script.check([cond], data if data is not None else self.data, pe)[0]

    def test_machine(self):
        self.assertTrue(self.result({"machine": "x64"})["holds"])
        self.assertFalse(self.result({"machine": "x86"})["holds"])
        self.assertTrue(self.result({"machine": ["x86", "x64"]})["holds"])

    def test_case_insensitive_machine_names(self):
        self.assertTrue(self.result({"machine": "X64"})["holds"])

    def test_sections(self):
        self.assertTrue(self.result({"section": ".text"})["holds"])
        self.assertFalse(self.result({"section": ".nope"})["holds"])
        self.assertTrue(self.result({"section": ".nope", "exists": False})["holds"])

    def test_strings_ascii_and_utf16(self):
        self.assertTrue(self.result({"string": "settings.ini"})["holds"])
        self.assertFalse(self.result({"string": "not-in-this-binary"})["holds"])
        utf16 = "settings.ini".encode("utf-16-le")
        self.assertTrue(self.result({"utf16": "settings.ini"},
                                   self.data + utf16)["holds"])

    def test_patterns_with_wildcards(self):
        self.assertTrue(self.result({"pattern": "4D 5A ?? ??"})["holds"])
        self.assertFalse(self.result({"pattern": "DE AD BE EF"})["holds"])

    def test_sizes(self):
        size = len(self.data)
        self.assertTrue(self.result({"size_at_least": size})["holds"])
        self.assertFalse(self.result({"size_at_least": size + 1})["holds"])
        self.assertTrue(self.result({"size_at_most": size})["holds"])

    def test_logic(self):
        self.assertTrue(self.result({"all": [{"machine": "x64"},
                                             {"section": ".text"}]})["holds"])
        self.assertFalse(self.result({"all": [{"machine": "x64"},
                                              {"section": ".nope"}]})["holds"])
        self.assertTrue(self.result({"any": [{"machine": "x86"},
                                             {"string": "settings.ini"}]})["holds"])
        self.assertTrue(self.result({"not": {"machine": "x86"}})["holds"])

    def test_failure_explains_itself(self):
        item = self.result({"all": [{"machine": "x64"},
                                    {"string": "definitely-not-here"}]})
        self.assertFalse(item["holds"])
        self.assertIn("definitely-not-here", item["detail"])

    def test_comment_is_kept(self):
        item = self.result({"machine": "x64", "comment": "64-bit only"})
        self.assertEqual(item["comment"], "64-bit only")


class ScriptValidation(unittest.TestCase):
    def bad(self, cond, needle=""):
        with self.assertRaises(script.ScriptError) as ctx:
            script.validate(cond)
        if needle:
            self.assertIn(needle, str(ctx.exception))

    def test_unknown_key(self):
        self.bad({"machines": "x64"}, "unknown keys")

    def test_empty(self):
        self.bad({}, "empty")

    def test_mixing_logic_and_atom(self):
        self.bad({"all": [{"machine": "x64"}], "machine": "x64"}, "nest them")

    def test_bad_machine(self):
        self.bad({"machine": "sparc"}, "unknown value")

    def test_bad_types(self):
        self.bad({"is_dotnet": "yes"}, "true or false")
        self.bad({"size_at_least": -1}, "non-negative")
        self.bad({"section": ""}, "section name")
        self.bad({"string": 5}, "non-empty string")

    def test_exists_needs_a_section(self):
        self.bad({"exists": False}, "only makes sense")

    def test_bad_pattern(self):
        with self.assertRaises(script.ScriptError):
            script.check([{"pattern": "zz"}], b"\0" * 8)

    def test_depth_is_bounded(self):
        deep = {"machine": "x64"}
        for _ in range(12):
            deep = {"not": {"not": deep}}
        self.bad(deep, "too big")

    def test_long_string_is_refused(self):
        self.bad({"string": "x" * (script.MAX_TEXT + 1)}, "longer than")

    def test_validate_all_accepts_none(self):
        self.assertEqual(script.validate_all(None), [])


class BundleFixture:
    """Shared fixture (not a TestCase, so it is not collected on its own)."""

    def setUp(self):
        super().setUp()
        self.app = write(self.path("app.exe"), sample_app())

    def load(self, **over):
        return Bundle.from_dict(bundle_dict(**over))

    # -- format ------------------------------------------------------------ #
    def test_requires_round_trips(self):
        cond = {"machine": "x64", "comment": "64-bit"}
        bundle = self.load(requires=[cond])
        self.assertEqual(bundle.requires, [cond])
        again = Bundle.from_dict(bundle.to_dict())
        self.assertEqual(again.requires, [cond])

    def test_hunk_when_round_trips(self):
        cond = {"string": "settings.ini"}
        raw = bundle_dict()
        raw["hunks"][0]["when"] = cond
        bundle = Bundle.from_dict(raw)
        self.assertEqual(bundle.hunks[0].when, cond)
        self.assertEqual(Bundle.from_dict(bundle.to_dict()).hunks[0].when, cond)

    def test_invalid_condition_is_a_bundle_error(self):
        with self.assertRaises(BundleError) as ctx:
            self.load(requires=[{"machine": "sparc"}])
        self.assertIn("requires[0]", str(ctx.exception))

    def test_invalid_hunk_condition_names_the_hunk(self):
        raw = bundle_dict()
        raw["hunks"][0]["when"] = {"bogus": 1}
        with self.assertRaises(BundleError) as ctx:
            Bundle.from_dict(raw)
        self.assertIn("hunk 0 when", str(ctx.exception))

    # -- application ------------------------------------------------------- #
    def test_requires_mismatch_refuses_before_writing(self):
        before = sha256_file(self.app)
        bundle = self.load(requires=[{"machine": "x86"}])
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.apply_bundle(bundle, self.app)
        self.assertIn("does not fit this build", str(ctx.exception))
        self.assertEqual(sha256_file(self.app), before)

    def test_requires_match_applies(self):
        bundle = self.load(requires=[{"machine": "x64"},
                                     {"section": ".text"},
                                     {"string": "settings.ini"}])
        result = patcher.apply_bundle(bundle, self.app)
        self.assertEqual(result["hunks"], 1)

    def test_plan_reports_the_conditions_it_checked(self):
        bundle = self.load(requires=[{"machine": "x64"}])
        plan = patcher.build_plan(bundle, self.app)
        self.assertEqual(len(plan.requires), 1)
        self.assertTrue(plan.requires[0]["holds"])
        self.assertTrue(any("requires:" in n for n in plan.notes))

    def test_when_false_skips_the_hunk(self):
        raw = bundle_dict()
        raw["hunks"] = [
            {"offset": 0x251, "expect": "7F", "replace": "EB",
             "when": {"string": "settings.ini"}},
            {"offset": 0x449, "expect": "54", "replace": "55",
             "when": {"string": "not-in-this-binary"}},
        ]
        bundle = Bundle.from_dict(raw)
        plan = patcher.build_plan(bundle, self.app)
        self.assertEqual(len(plan.resolved), 1)
        self.assertEqual(plan.skipped_hunks[0]["index"], 1)
        self.assertIn("not-in-this-binary", plan.skipped_hunks[0]["detail"])

    def test_all_hunks_skipped_is_an_error_not_a_silent_no_op(self):
        raw = bundle_dict()
        raw["hunks"][0]["when"] = {"machine": "x86"}
        bundle = Bundle.from_dict(raw)
        before = sha256_file(self.app)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.apply_bundle(bundle, self.app)
        self.assertIn("none of", str(ctx.exception))
        self.assertIn("machine is x86", str(ctx.exception))
        self.assertEqual(sha256_file(self.app), before)

    def test_disabled_and_conditional_compose(self):
        raw = bundle_dict()
        raw["hunks"][0]["enabled"] = False
        raw["hunks"][0]["when"] = {"machine": "x64"}
        bundle = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError):
            # disabled wins: nothing is left to do
            patcher.build_plan(bundle, self.app)

    def test_conditions_are_not_ignored_on_raw_targets(self):
        # a non-PE blob only gets raw offsets — and a "machine is x64" condition
        # cannot be proven there, so it must fail closed rather than skip
        raw = bundle_dict(requires=[{"machine": "x64"}])
        raw["target"] = {"filename": "blob.bin"}
        bundle = Bundle.from_dict(raw)
        blob = write(self.path("blob.bin"), b"\x00" * 4096)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(bundle, blob, accept_drift=True)
        self.assertIn("does not fit this build", str(ctx.exception))


class ConditionedBundles(BundleFixture, TempDirCase):
    pass


class CliSurface(BundleFixture, TempDirCase):
    def write_bundle(self, **over):
        raw = bundle_dict(**over)
        raw["target"] = {"filename": "app.exe", "size": len(sample_app()),
                         "sha256": sha256_file(self.app)}
        path = self.path("cond.morph")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        return path

    def cli_run(self, *argv):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_info_shows_preconditions_and_hunk_conditions(self):
        raw = bundle_dict(requires=[{"machine": "x64", "comment": "64-bit only"}])
        raw["hunks"][0]["when"] = {"string": "settings.ini"}
        bundle = Bundle.from_dict(raw)
        path = self.path("shown.morph")
        bundle.save(path)
        code, out, _ = self.cli_run("info", path)
        self.assertEqual(code, 0)
        self.assertIn("preconditions (1)", out)
        self.assertIn("machine is x64", out)
        self.assertIn("64-bit only", out)
        self.assertIn('only if the text "settings.ini" is present', out)

    def test_check_reports_a_failed_precondition(self):
        path = self.write_bundle(requires=[{"machine": "x86"}])
        code, _out, err = self.cli_run("check", path, "--target", self.app)
        self.assertEqual(code, 3)
        self.assertIn("does not fit this build", err)

    def test_check_json_includes_conditions(self):
        path = self.write_bundle(requires=[{"machine": "x64"}])
        code, out, _ = self.cli_run("check", path, "--target", self.app, "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        plan = data.get("plan") or data
        self.assertTrue(plan["requires"][0]["holds"])

    def test_apply_with_a_satisfied_precondition(self):
        self.cli_run("init", "--accept-policy")
        path = self.write_bundle(requires=[{"machine": "x64"}])
        code, _out, err = self.cli_run("apply", path, "--target", self.app, "-y")
        self.assertEqual(code, 0, err)

    def test_diff_can_author_preconditions(self):
        new = write(self.path("new.exe"), sample_app(patch=True))
        out_path = self.path("authored.morph")
        code, out, err = self.cli_run("diff", self.app, new, "-o", out_path,
                                  "--id", "org.test.auto",
                                  "--requires-machine",
                                  "--requires-section", ".text",
                                  "--requires-string", "settings.ini")
        self.assertEqual(code, 0, err)
        bundle = Bundle.load(out_path)
        self.assertEqual(bundle.requires[0], {"machine": "x64",
                                              "comment": "authored against x64"})
        self.assertEqual(bundle.requires[1], {"section": ".text"})
        self.assertEqual(bundle.requires[2], {"string": "settings.ini"})
        self.assertIn("preconditions", out)
        # and the authored bundle applies to the build it was made from
        self.cli_run("init", "--accept-policy")
        code, _out, err = self.cli_run("apply", out_path, "--target", self.app, "-y")
        self.assertEqual(code, 0, err)

    def test_authored_precondition_protects_other_builds(self):
        new = write(self.path("new.exe"), sample_app(patch=True))
        out_path = self.path("pinned.morph")
        self.cli_run("diff", self.app, new, "-o", out_path, "--id", "org.test.pinned",
                 "--requires-machine")
        # a 32-bit build of the same program must be refused, not patched wrongly
        x86 = build_pe([(".text", b"\x90" * 0x200, TEXT)], machine=0x14C)
        other = write(self.path("x86.exe"), x86)
        code, _out, err = self.cli_run("check", out_path, "--target", other,
                                   "--accept-drift")
        self.assertEqual(code, 3)
        self.assertIn("does not fit this build", err)


if __name__ == "__main__":
    unittest.main()
