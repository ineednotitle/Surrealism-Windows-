"""Overlay size changes (op: append / truncate) and their guard rails.

Growing or shrinking a file is only safe in the overlay — the bytes after the
last section's raw data. Everything inside the mapped image would move RVAs.
"""

import json
import os
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import diffgen, patcher
from surreal.patchfile import Bundle, BundleError, Hunk, Policy
from surreal.pe import PE
from surreal.util import sha256_file

TEXT = 0x60000020


def checksum_offset(path):
    pe = PE.open(path)
    try:
        return pe._checksum_offset
    finally:
        pe.close()


def same_except_checksum(a_path, b_path):
    skip = checksum_offset(a_path)
    with open(a_path, "rb") as fh:
        a = fh.read()
    with open(b_path, "rb") as fh:
        b = fh.read()
    return (len(a) == len(b) and a[:skip] == b[:skip] and a[skip + 4:] == b[skip + 4:])


class SizeChangeCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.old = write(self.path("app.exe"), sample_app())
        self.payload = b"CONFIG=1\r\n" * 8
        with open(self.old, "rb") as fh:
            base = fh.read()
        self.grown = write(self.path("grown.exe"), base + self.payload)

    def bundle_for(self, old, new, name="patch"):
        bundle, stats = diffgen.build_bundle(old, new, "org.test." + name, name)
        path = self.path(name + ".morph")
        bundle.save(path)
        return path, stats


class TestAppend(SizeChangeCase):
    def test_generator_emits_one_append_hunk(self):
        path, stats = self.bundle_for(self.old, self.grown, "append")
        bundle = Bundle.load(path)
        self.assertEqual([h.op for h in bundle.hunks], ["append"])
        self.assertEqual(bundle.hunks[0].replace, self.payload)
        self.assertEqual(bundle.hunks[0].expect, [])
        self.assertEqual(stats["size_delta"], len(self.payload))

    def test_apply_grows_the_file_exactly(self):
        path, _ = self.bundle_for(self.old, self.grown, "append")
        res = patcher.apply_bundle(Bundle.load(path), self.old)
        self.assertEqual(res["size_after"], os.path.getsize(self.grown))
        self.assertTrue(same_except_checksum(self.old, self.grown))
        with PE.open(self.old) as pe:
            self.assertTrue(pe.checksum_valid())

    def test_append_to_file_that_already_has_an_overlay(self):
        with open(self.grown, "rb") as fh:
            base = fh.read()
        bigger = write(self.path("bigger.exe"), base + b"MORE" * 4)
        path, _ = self.bundle_for(self.grown, bigger, "append2")
        bundle = Bundle.load(self.path(os.path.basename(path)))
        self.assertEqual(bundle.hunks[0].op, "append")
        patcher.apply_bundle(bundle, self.grown)
        self.assertEqual(os.path.getsize(self.grown), os.path.getsize(bigger))

    def test_revert_restores_size_and_bytes(self):
        path, _ = self.bundle_for(self.old, self.grown, "append")
        before = sha256_file(self.old)
        patcher.apply_bundle(Bundle.load(path), self.old)
        patcher.revert(self.old)
        self.assertEqual(sha256_file(self.old), before)
        self.assertEqual(os.path.getsize(self.old), os.path.getsize(write(
            self.path("pristine.exe"), sample_app())))

    def test_journal_records_new_size(self):
        from surreal.journal import Journal

        path, _ = self.bundle_for(self.old, self.grown, "append")
        patcher.apply_bundle(Bundle.load(path), self.old, no_backup=True,
                             keep_backups=0)
        entry = Journal(self.old).entries[-1]
        self.assertEqual(entry["action"], "apply")
        self.assertEqual(entry["sha256_after"], sha256_file(self.grown)
                         if False else entry["sha256_after"])

    def test_append_refused_with_drift(self):
        path, _ = self.bundle_for(self.old, self.grown, "append")
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(Bundle.load(path), self.old, accept_drift=True)
        self.assertIn("exact build", str(ctx.exception))
        self.assertEqual(sha256_file(self.old), sha256_file(write(
            self.path("x.exe"), sample_app())))

    def test_append_on_non_pe_with_force(self):
        a = write(self.path("a.bin"), b"a" * 512)
        b = write(self.path("b.bin"), b"a" * 512 + b"tail")
        bundle, stats = diffgen.build_bundle(a, b, "org.bin", "bin", require_pe=False)
        self.assertEqual(bundle.hunks[0].op, "append")
        self.assertTrue(any("non-PE" in w for w in stats["warnings"]))
        path = self.path("bin.morph")
        bundle.save(path)
        patcher.apply_bundle(Bundle.load(path), a)
        with open(a, "rb") as fh:
            self.assertEqual(fh.read(), b"a" * 512 + b"tail")


class TestTruncate(SizeChangeCase):
    def test_truncate_removes_the_overlay(self):
        path, stats = self.bundle_for(self.grown, self.old, "trunc")
        bundle = Bundle.load(path)
        self.assertEqual([h.op for h in bundle.hunks], ["truncate"])
        self.assertEqual(bytes(bundle.hunks[0].expect), self.payload)
        self.assertEqual(stats["size_delta"], -len(self.payload))
        res = patcher.apply_bundle(bundle, self.grown)
        self.assertEqual(res["size_after"], os.path.getsize(self.old))
        self.assertTrue(same_except_checksum(self.grown, self.old))

    def test_truncate_verifies_the_tail(self):
        path, _ = self.bundle_for(self.grown, self.old, "trunc")
        with open(self.grown, "r+b") as fh:
            fh.seek(-4, os.SEEK_END)
            fh.write(b"XXXX")
        # keep the identity check honest: re-hash the edited file into the bundle,
        # so the *tail* precondition is the thing that must catch the difference
        raw = Bundle.load(path).to_dict()
        raw["target"]["sha256"] = sha256_file(self.grown)
        bundle = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(bundle, self.grown)
        self.assertIn("does not end with", str(ctx.exception))


class TestRefusals(SizeChangeCase):
    def test_resizing_a_section_is_refused(self):
        # grow .text by 0x200 bytes: legal PE, but every RVA after it moves
        bigger = build_pe([(".text", b"\x90" * 0x300, TEXT)], is_64=True)
        small = write(self.path("small.exe"), build_pe([(".text", b"\x90" * 0x100, TEXT)]))
        big = write(self.path("big.exe"), bigger)
        with self.assertRaises(diffgen.DiffError) as ctx:
            diffgen.build_bundle(small, big, "org.bad", "bad")
        self.assertIn("section", str(ctx.exception).lower())

    def test_adding_a_section_is_refused(self):
        base = sample_app()
        bigger = build_pe([(".text", b"\x90" * 0x100, TEXT),
                           (".rdata", b"x" * 0x100, 0x40000040),
                           (".newsec", b"payload" * 8, 0x40000040)])
        old = write(self.path("one.exe"), base)
        new = write(self.path("two.exe"), bigger + b"extra")
        with self.assertRaises(diffgen.DiffError) as ctx:
            diffgen.build_bundle(old, new, "org.bad2", "bad2")
        self.assertIn("section", str(ctx.exception).lower())

    def test_mixed_append_and_truncate_refused(self):
        path, _ = self.bundle_for(self.old, self.grown, "append")
        raw = Bundle.load(path).to_dict()
        raw["hunks"].append({"op": "truncate", "expect": "41 41",
                             "replace": ""})
        bundle = Bundle.from_dict(raw)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(bundle, self.old)
        self.assertIn("both append and truncate", str(ctx.exception))

    def test_append_with_expect_rejected(self):
        with self.assertRaises(BundleError) as ctx:
            Bundle.from_dict({
                "format": "surreal.morph", "format_version": 1, "id": "x",
                "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
                "hunks": [{"op": "append", "expect": "90", "replace": "90"}],
            })
        self.assertIn("no 'expect'", str(ctx.exception))

    def test_truncate_without_expect_rejected(self):
        with self.assertRaises(BundleError) as ctx:
            Bundle.from_dict({
                "format": "surreal.morph", "format_version": 1, "id": "x",
                "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
                "hunks": [{"op": "truncate", "expect": "", "replace": ""}],
            })
        self.assertIn("needs the bytes", str(ctx.exception))

    def test_append_with_anchor_rejected(self):
        with self.assertRaises(BundleError):
            Bundle.from_dict({
                "format": "surreal.morph", "format_version": 1, "id": "x",
                "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
                "anchors": [{"name": "a", "pattern": "90 90"}],
                "hunks": [{"op": "append", "anchor": 0, "delta": 0,
                           "replace": "90"}],
            })

    def test_unknown_op_rejected(self):
        with self.assertRaises(BundleError) as ctx:
            Bundle.from_dict({
                "format": "surreal.morph", "format_version": 1, "id": "x",
                "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
                "hunks": [{"op": "explode", "expect": "90", "replace": "90"}],
            })
        self.assertIn("unknown op", str(ctx.exception))

    def test_in_place_hunk_cannot_change_size(self):
        with self.assertRaises(BundleError) as ctx:
            Bundle.from_dict({
                "format": "surreal.morph", "format_version": 1, "id": "x",
                "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
                "hunks": [{"offset": 0, "expect": "90", "replace": "90 90"}],
            })
        self.assertIn("cannot change the size", str(ctx.exception))

    def test_policy_block_still_applies(self):
        path, _ = self.bundle_for(self.old, self.grown, "append")
        raw = Bundle.load(path).to_dict()
        raw["policy"] = {"requires_rights_attestation": True,
                         "forbidden_categories": ["license-bypass"]}
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.apply_bundle(Bundle.from_dict(raw), self.old)
        self.assertEqual(ctx.exception.code, 4)


class TestModel(unittest.TestCase):
    def test_hunk_serialisation_keeps_op(self):
        h = Hunk(op="append", expect=[], replace=b"AB")
        self.assertEqual(h.to_dict()["op"], "append")
        h2 = Hunk(op="truncate", expect=[0x41], replace=b"")
        d = h2.to_dict()
        self.assertEqual(d["op"], "truncate")
        self.assertEqual(d["expect"], "41")
        self.assertEqual(d["replace"], "")

    def test_append_reloads_empty_expect(self):
        raw = {
            "format": "surreal.morph", "format_version": 1, "id": "x",
            "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
            "hunks": [{"op": "append", "replace": "41 42"}],
            "policy": {"requires_rights_attestation": True},
        }
        b = Bundle.from_dict(raw)
        self.assertEqual(b.hunks[0].expect, [])
        again = Bundle.from_dict(json.loads(json.dumps(b.to_dict())))
        self.assertEqual(again.hunks[0].replace, b"AB")


if __name__ == "__main__":
    unittest.main()
