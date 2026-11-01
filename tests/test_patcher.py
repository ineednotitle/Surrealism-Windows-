import json
import os
import shutil
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import patcher
from surreal.diffgen import build_bundle
from surreal.journal import Journal
from surreal.patchfile import Bundle, BundleError, Hunk, Policy
from surreal.pe import PE
from surreal.util import sha256_file


class PatchCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.old = write(self.path("app.exe"), sample_app())
        self.new = write(self.path("app_new.exe"), sample_app(patch=True))
        b, _ = build_bundle(self.old, self.new, "org.test.patch", "Test patch")
        self.bundle_path = self.path("patch.morph")
        b.save(self.bundle_path)
        self.bundle = Bundle.load(self.bundle_path)
        self.sha_before = sha256_file(self.old)

    @staticmethod
    def read_bytes(path: str) -> bytes:
        with open(path, "rb") as fh:
            return fh.read()

    def assertUntouched(self):
        self.assertEqual(sha256_file(self.old), self.sha_before)


class TestApply(PatchCase):
    def test_dry_run_writes_nothing(self):
        res = patcher.apply_bundle(self.bundle, self.old, dry_run=True)
        self.assertTrue(res["dry_run"])
        self.assertUntouched()
        self.assertFalse(os.path.exists(self.path(".surreal")))

    def test_apply_matches_reference(self):
        res = patcher.apply_bundle(self.bundle, self.old)
        self.assertEqual(sha256_file(self.old), sha256_file(self.new))
        self.assertEqual(res["sha256_after"], sha256_file(self.new))
        self.assertTrue(os.path.isfile(res["backup"]))
        with PE.open(self.old) as pe:
            self.assertTrue(pe.checksum_valid())

    def test_predicted_checksum_matches_written_checksum(self):
        plan = patcher.build_plan(self.bundle, self.old)
        patcher.apply_bundle(self.bundle, self.old)
        with PE.open(self.old) as pe:
            self.assertEqual(pe.compute_checksum(), plan.new_checksum)

    def test_no_checksum_flag(self):
        patcher.apply_bundle(self.bundle, self.old, no_checksum=True)
        with PE.open(self.old) as pe:
            self.assertFalse(pe.checksum_valid())

    def test_no_backup_flag(self):
        res = patcher.apply_bundle(self.bundle, self.old, no_backup=True)
        self.assertIsNone(res["backup"])

    def test_revert_roundtrip(self):
        patcher.apply_bundle(self.bundle, self.old)
        res = patcher.revert(self.old)
        self.assertUntouched()
        self.assertEqual(res["restored_sha256"], self.sha_before)

    def test_double_revert_refused(self):
        patcher.apply_bundle(self.bundle, self.old)
        patcher.revert(self.old)
        with self.assertRaises(patcher.PatchError):
            patcher.revert(self.old)

    def test_revert_without_journal(self):
        with self.assertRaises(patcher.PatchError):
            patcher.revert(self.old)

    def test_revert_after_external_change_refused(self):
        patcher.apply_bundle(self.bundle, self.old)
        data = bytearray(self.read_bytes(self.old))
        data[0x300] ^= 0xFF
        write(self.old, bytes(data))
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.revert(self.old)
        self.assertIn("changed since", str(ctx.exception))

    def test_second_apply_is_refused(self):
        patcher.apply_bundle(self.bundle, self.old)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.apply_bundle(self.bundle, self.old)
        self.assertIn("expect", str(ctx.exception).lower())

    def test_wrong_build_refused_without_drift(self):
        other = write(self.path("other.exe"), sample_app(is_64=False))
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(self.bundle, other)
        self.assertEqual(ctx.exception.code, 3)

    def test_backup_pruning(self):
        for _ in range(4):
            patcher.revert(self.old) if Journal(self.old).entries and \
                Journal(self.old).entries[-1]["action"] == "apply" else None
            patcher.apply_bundle(self.bundle, self.old, keep_backups=2)
        bdir = self.path(os.path.join(".surreal", "backups"))
        existing = [f for f in os.listdir(bdir) if f.endswith(".bak")]
        self.assertLessEqual(len(existing), 2)
        self.assertGreaterEqual(len(existing), 1)

    def test_journal_is_json(self):
        patcher.apply_bundle(self.bundle, self.old)
        journal = self.path(os.path.join(".surreal", "journal.json"))
        with open(journal, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["entries"][0]["action"], "apply")
        self.assertEqual(data["entries"][0]["bundle_id"], "org.test.patch")


class TestWindowsLocks(PatchCase):
    """The swap is where Windows says no: the app is running or AV holds a handle."""

    def test_locked_target_gives_an_actionable_error(self):
        import unittest.mock as mock

        real_replace = os.replace

        def fake_replace(src, dst):
            if dst == self.old:
                raise PermissionError(13, "Access is denied")
            return real_replace(src, dst)

        with mock.patch.object(patcher.os, "replace", side_effect=fake_replace):
            with self.assertRaises(patcher.PatchError) as ctx:
                patcher.apply_bundle(self.bundle, self.old)
        self.assertEqual(ctx.exception.code, 5)
        message = str(ctx.exception)
        self.assertIn("cannot replace", message)
        self.assertIn("close the application", message)
        self.assertUntouched()

    def test_no_temp_files_left_behind(self):
        import unittest.mock as mock

        def fake_replace(src, dst):
            raise PermissionError(13, "Access is denied")

        with mock.patch.object(patcher.os, "replace", side_effect=fake_replace):
            with self.assertRaises(patcher.PatchError):
                patcher.apply_bundle(self.bundle, self.old)
        leftovers = [f for f in os.listdir(os.path.dirname(self.old))
                     if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])


class TestGuards(PatchCase):
    def make_bundle(self, **overrides) -> Bundle:
        raw = json.loads(json.dumps(self.bundle.to_dict()))
        raw.update(overrides)
        b = Bundle.from_dict(raw)
        b.path = self.bundle_path
        return b

    def test_ambiguous_anchor_refused(self):
        raw = self.bundle.to_dict()
        # 2-byte pattern "00 00" occurs everywhere in the fixture
        raw["anchors"][0]["pattern"] = "00 00"
        raw["anchors"][0]["unique"] = True
        b = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(b, self.old)
        self.assertIn("matches", str(ctx.exception))

    def test_expect_mismatch_refused(self):
        raw = self.bundle.to_dict()
        first = raw["hunks"][0]
        first["expect"] = " ".join("00" for _ in range(len(first["replace"].split())))
        b = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(b, self.old)
        self.assertIn("does not contain the expected", str(ctx.exception))

    def test_disagreeing_locators_refused(self):
        raw = self.bundle.to_dict()
        raw["hunks"][0]["offset"] = (raw["hunks"][0].get("offset") or 0) + 1
        b = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(b, self.old)
        self.assertIn("disagree", str(ctx.exception))

    def test_overlapping_hunks_refused(self):
        raw = self.bundle.to_dict()
        h = dict(raw["hunks"][0])
        h["offset"] = raw["hunks"][0]["offset"]
        h["anchor"] = None
        h["delta"] = 0
        h["section"] = None
        h["rva"] = None
        raw["hunks"] = [raw["hunks"][0], h]
        b = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(b, self.old)
        self.assertIn("overlap", str(ctx.exception))

    def test_out_of_file_hunk_refused(self):
        raw = self.bundle.to_dict()
        raw["hunks"][0]["offset"] = 10 ** 9
        raw["hunks"][0]["anchor"] = None
        raw["hunks"][0]["section"] = None
        raw["hunks"][0]["rva"] = None
        b = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError):
            patcher.build_plan(b, self.old)

    def test_policy_blocked_bundle_refused(self):
        raw = self.bundle.to_dict()
        raw["policy"] = {"requires_rights_attestation": True,
                         "forbidden_categories": ["license-bypass"]}
        b = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.apply_bundle(b, self.old)
        self.assertEqual(ctx.exception.code, 4)
        self.assertUntouched()

    def test_keygen_wording_blocked(self):
        raw = self.bundle.to_dict()
        raw["description"] = "Full crack and keygen for the app"
        b = Bundle.from_dict(raw)
        self.assertIsNotNone(b.is_policy_blocked())

    def test_signed_target_warns(self):
        raw = self.bundle.to_dict()
        b = Bundle.from_dict(raw)
        # mark the fixture as signed
        import struct

        data = bytearray(self.read_bytes(self.old))
        pe = PE.open(self.old)
        try:
            dirs_off = pe.optional_offset + (112 if pe.is_64 else 96) + 4 * 8
            pe.close()
        finally:
            pass
        struct.pack_into("<II", data, dirs_off, len(data) - 4, 4)
        write(self.old, bytes(data))
        b.target["sha256"] = sha256_file(self.old)
        plan = patcher.build_plan(b, self.old)
        self.assertTrue(any("Authenticode" in w for w in plan.warnings))

    def test_missing_target(self):
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.apply_bundle(self.bundle, self.path("nope.exe"))
        self.assertEqual(ctx.exception.code, 5)

    def test_non_pe_target(self):
        bad = write(self.path("bad.exe"), b"not a pe" * 100)
        with self.assertRaises(patcher.PatchError):
            patcher.build_plan(self.bundle, bad)

    def test_drift_accepted_with_flag(self):
        data = bytearray(self.read_bytes(self.old))
        # change a byte *outside* every hunk: timestamp field
        data[0x88] ^= 0x01
        write(self.old, bytes(data))
        with self.assertRaises(patcher.PatchError):
            patcher.build_plan(self.bundle, self.old)
        plan = patcher.build_plan(self.bundle, self.old, accept_drift=True)
        self.assertGreaterEqual(len(plan.resolved), 1)
        self.assertTrue(any("drift accepted" in w for w in plan.warnings))


class TestPayloadGuards(unittest.TestCase):
    def test_wildcard_expect_is_allowed(self):
        h = Hunk(expect=[0x90, None, 0x90], replace=b"\x90\x00\x90", offset=0)
        self.assertEqual(h.length, 3)

    def test_empty_replace_rejected(self):
        with self.assertRaises(BundleError):
            Bundle.from_dict({"format": "surreal.morph", "format_version": 1, "id": "x",
                              "target": {"filename": "a.exe"},
                              "hunks": [{"replace": "", "expect": ""}]})


if __name__ == "__main__":
    unittest.main()
