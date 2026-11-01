"""Image surgery: extend-section / add-section planning, apply and refusals."""

import os
import struct
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import diffgen, patcher, surgery
from surreal.patchfile import Bundle, BundleError, Hunk
from surreal.pe import PE
from surreal.util import sha256_file

TEXT = 0x60000020
RDATA = 0x40000040


def two_section_pe():
    return build_pe([(".text", b"\x90" * 0x100, TEXT),
                     (".rdata", b"hello" * 20, RDATA)])


def write_surgery(src, out_path, planner):
    """Apply a Surgery to a copy of ``src`` with a correct checksum (a stand-in
    for whatever tool the author used to produce their modified build)."""
    import shutil

    shutil.copyfile(src, out_path)
    pe = PE.open(out_path)
    try:
        plan = planner(pe)
    finally:
        pe.close()
    with open(out_path, "r+b") as fh:
        for offset, data in plan.writes:
            fh.seek(offset)
            fh.write(data)
        fh.seek(0, os.SEEK_END)
        fh.write(plan.payload)
    with PE.open(out_path) as after:
        checksum = after.compute_checksum()
        skip = after._checksum_offset
    with open(out_path, "r+b") as fh:
        fh.seek(skip)
        fh.write(struct.pack("<I", checksum))
    return plan


class TestPlanning(TempDirCase):
    def setUp(self):
        super().setUp()
        self.app = write(self.path("app.exe"), two_section_pe())

    def pe(self):
        return PE.open(self.app)

    def test_header_slack_and_table(self):
        with self.pe() as pe:
            self.assertEqual(surgery.section_table_offset(pe), 0x188)
            self.assertGreaterEqual(surgery.header_slack(pe), 40)
            self.assertEqual(surgery.align_up(0x201, 0x200), 0x400)

    def test_extend_plan(self):
        with self.pe() as pe:
            payload = b"A" * 90
            plan = surgery.plan_extend_section(pe, ".rdata", payload)
            self.assertEqual(plan.kind, "extend-section")
            # the file grows by whole FileAlignment units
            grown = plan.file_size_after - pe.size
            self.assertEqual(grown % pe.file_alignment, 0)
            self.assertGreaterEqual(grown, len(payload))
            self.assertEqual(len(plan.writes), 3)   # VirtualSize, RawSize, SizeOfImage
            self.assertEqual(len(plan.payload), grown)

    def test_extend_requires_last_section(self):
        with self.pe() as pe:
            with self.assertRaises(surgery.SurgeryError) as ctx:
                surgery.plan_extend_section(pe, ".text", b"A" * 8)
            self.assertIn("not the last section", str(ctx.exception))

    def test_extend_requires_no_overlay(self):
        data = two_section_pe() + b"OVERLAY"
        path = write(self.path("ov.exe"), data)
        with PE.open(path) as pe:
            with self.assertRaises(surgery.SurgeryError) as ctx:
                surgery.plan_extend_section(pe, ".rdata", b"A" * 8)
            self.assertIn("overlay", str(ctx.exception))

    def test_extend_checks_declared_raw_size(self):
        with self.pe() as pe:
            with self.assertRaises(surgery.SurgeryError) as ctx:
                surgery.plan_extend_section(pe, ".rdata", b"A" * 8,
                                            raw_size_before=0x999)
            self.assertIn("bundle expects", str(ctx.exception))

    def test_extend_rejects_bad_virtual_size(self):
        with self.pe() as pe:
            with self.assertRaises(surgery.SurgeryError):
                surgery.plan_extend_section(pe, ".rdata", b"A" * 8,
                                            virtual_size_after=8)
            with self.assertRaises(surgery.SurgeryError):
                surgery.plan_extend_section(pe, ".rdata", b"A" * 8,
                                            virtual_size_after=0x10000)

    def test_add_section_plan(self):
        with self.pe() as pe:
            plan = surgery.plan_add_section(pe, ".smod", RDATA, b"B" * 100)
            self.assertEqual(plan.kind, "add-section")
            self.assertEqual(plan.section_name, ".smod")
            self.assertEqual(plan.image_size_after % (pe.section_alignment or 0x1000), 0)
            header_off, header = plan.writes[0]
            self.assertEqual(len(header), 40)
            self.assertEqual(header[:6], b".smod\0")

    def test_add_section_refusals(self):
        with self.pe() as pe:
            with self.assertRaises(surgery.SurgeryError):
                surgery.plan_add_section(pe, "toolongname", RDATA, b"x")
            with self.assertRaises(surgery.SurgeryError):
                surgery.plan_add_section(pe, "", RDATA, b"x")
            with self.assertRaises(surgery.SurgeryError):
                surgery.plan_add_section(pe, ".rdata", RDATA, b"x")
            with self.assertRaises(surgery.SurgeryError):
                surgery.plan_add_section(pe, ".smod", RDATA, b"x",
                                         virtual_address=0x1000)

    def test_add_section_needs_header_slack(self):
        # 3 sections in this fixture leave no slack before SizeOfHeaders
        tight = build_pe([(".text", b"\x90" * 0x100, TEXT),
                          (".rdata", b"x" * 0x100, RDATA),
                          (".data", b"y" * 0x100, 0xC0000040)])
        path = write(self.path("tight.exe"), tight)
        with PE.open(path) as pe:
            if surgery.header_slack(pe) >= 40:
                self.skipTest("fixture has slack; covered by other cases")
            with self.assertRaises(surgery.SurgeryError) as ctx:
                surgery.plan_add_section(pe, ".smod", RDATA, b"x" * 8)
            self.assertIn("no room", str(ctx.exception))


class TestGeneratorAndApply(TempDirCase):
    def setUp(self):
        super().setUp()
        self.app = write(self.path("app.exe"), two_section_pe())

    def test_extend_section_roundtrip(self):
        target = self.path("grown.exe")
        write_surgery(self.app, target,
                      lambda pe: surgery.plan_extend_section(pe, ".rdata",
                                                             b"NEWDATA" * 10))
        bundle, stats = diffgen.build_bundle(self.app, target, "org.surgery.extend",
                                             "extend")
        self.assertEqual([h.op for h in bundle.hunks], ["extend-section"])
        self.assertEqual(bundle.hunks[0].section, ".rdata")
        self.assertTrue(any("layout change" in w for w in stats["warnings"]))
        path = self.path("extend.morph")
        bundle.save(path)
        patcher.apply_bundle(Bundle.load(path), self.app)
        with open(self.app, "rb") as a, open(target, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_add_section_roundtrip(self):
        target = self.path("added.exe")
        write_surgery(self.app, target,
                      lambda pe: surgery.plan_add_section(pe, ".smod", RDATA,
                                                          b"MOD" * 60))
        bundle, _ = diffgen.build_bundle(self.app, target, "org.surgery.add", "add")
        self.assertEqual([h.op for h in bundle.hunks], ["add-section"])
        self.assertEqual(bundle.hunks[0].name, ".smod")
        self.assertIsNotNone(bundle.hunks[0].characteristics)
        path = self.path("add.morph")
        bundle.save(path)
        patcher.apply_bundle(Bundle.load(path), self.app)
        with open(self.app, "rb") as a, open(target, "rb") as b:
            self.assertEqual(a.read(), b.read())
        with PE.open(self.app) as pe:
            self.assertEqual([s.name for s in pe.sections], [".text", ".rdata", ".smod"])
            self.assertTrue(pe.checksum_valid())

    def test_revert_after_surgery(self):
        target = self.path("grown.exe")
        write_surgery(self.app, target,
                      lambda pe: surgery.plan_extend_section(pe, ".rdata", b"Z" * 64))
        bundle, _ = diffgen.build_bundle(self.app, target, "org.surgery.r", "r")
        path = self.path("r.morph")
        bundle.save(path)
        before = sha256_file(self.app)
        patcher.apply_bundle(Bundle.load(path), self.app)
        patcher.revert(self.app)
        self.assertEqual(sha256_file(self.app), before)

    def test_drift_refused(self):
        target = self.path("grown.exe")
        write_surgery(self.app, target,
                      lambda pe: surgery.plan_extend_section(pe, ".rdata", b"Z" * 64))
        bundle, _ = diffgen.build_bundle(self.app, target, "org.surgery.d", "d")
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(bundle, self.app, accept_drift=True)
        self.assertIn("exact build", str(ctx.exception))

    def test_wrong_build_refused(self):
        target = self.path("grown.exe")
        write_surgery(self.app, target,
                      lambda pe: surgery.plan_extend_section(pe, ".rdata", b"Z" * 64))
        bundle, _ = diffgen.build_bundle(self.app, target, "org.surgery.w", "w")
        other = write(self.path("other.exe"),
                      build_pe([(".text", b"\x90" * 0x100, TEXT),
                                (".rdata", b"other" * 20, RDATA)]))
        with self.assertRaises(patcher.PatchError):
            patcher.build_plan(bundle, other)

    def test_mixed_size_ops_refused(self):
        raw = Bundle.from_dict({
            "format": "surreal.morph", "format_version": 1, "id": "org.mixed",
            "name": "mixed",
            "target": {"filename": "app.exe", "size": 1, "sha256": "00" * 32},
            "hunks": [{"op": "append", "replace": "41"},
                      {"op": "add-section", "name": ".x", "characteristics": "0x40000040",
                       "replace": "42"}],
        })
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(raw, self.app)
        self.assertIn("only one kind", str(ctx.exception))

    def test_two_surgery_hunks_refused(self):
        raw = Bundle.from_dict({
            "format": "surreal.morph", "format_version": 1, "id": "org.two",
            "name": "two",
            "target": {"filename": "app.exe", "size": 1, "sha256": "00" * 32},
            "hunks": [{"op": "extend-section", "section": ".rdata", "replace": "41"},
                      {"op": "extend-section", "section": ".rdata", "replace": "42"}],
        })
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(raw, self.app)
        self.assertIn("only one size-changing hunk", str(ctx.exception))

    def test_overlay_change_with_sections_still_uses_append(self):
        # an overlay append must not be misread as extend-section
        with open(self.app, "rb") as fh:
            base = fh.read()
        grown = write(self.path("ov.exe"), base + b"OVERLAY")
        bundle, _ = diffgen.build_bundle(self.app, grown, "org.surgery.ov", "ov")
        self.assertEqual([h.op for h in bundle.hunks], ["append"])

    def test_surgery_bundle_loader_rules(self):
        base = {"format": "surreal.morph", "format_version": 1, "id": "x",
                "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32}}
        bad_cases = [
            {"op": "extend-section", "replace": "41"},                      # no section
            {"op": "add-section", "replace": "41", "characteristics": "0x1"},  # no name
            {"op": "add-section", "name": ".x", "replace": "41"},           # no chars
            {"op": "extend-section", "section": ".text", "replace": "41",
             "expect": "90"},                                               # expect
            {"op": "add-section", "name": ".x", "characteristics": "0x1",
             "replace": "41", "offset": 5},                                 # locator
        ]
        for case in bad_cases:
            with self.assertRaises(BundleError):
                Bundle.from_dict(dict(base, hunks=[case]))

    def test_surgery_hunk_serialises(self):
        h = Hunk(op="add-section", expect=[], replace=b"\x41",
                 name=".smod", characteristics=0x40000040, rva=0x3000,
                 virtual_size_after=0x10)
        raw = h.to_dict()
        self.assertEqual(raw["name"], ".smod")
        self.assertEqual(raw["characteristics"], "0x40000040")
        again = Bundle.from_dict({
            "format": "surreal.morph", "format_version": 1, "id": "x",
            "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
            "hunks": [raw],
        })
        self.assertEqual(again.hunks[0].characteristics, 0x40000040)
        self.assertEqual(again.hunks[0].virtual_size_after, 0x10)


class TestVerifyAfter(TempDirCase):
    def test_detects_layout_mismatch(self):
        src = write(self.path("a.exe"), two_section_pe())
        out = self.path("b.exe")
        plan = write_surgery(src, out,
                             lambda pe: surgery.plan_extend_section(pe, ".rdata",
                                                                    b"K" * 32))
        with PE.open(src) as before:
            broken = surgery.Surgery(kind=plan.kind, writes=plan.writes,
                                     payload=plan.payload,
                                     file_size_after=plan.file_size_after + 0x200,
                                     image_size_after=plan.image_size_after,
                                     section_name=plan.section_name)
            with self.assertRaises(surgery.SurgeryError) as ctx:
                surgery.verify_after(before, broken, out)
            self.assertIn("file size", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
