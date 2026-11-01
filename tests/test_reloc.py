"""Base-relocation parsing and ASLR safety checks."""

import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import diffgen, patcher, reloc
from surreal.patchfile import Bundle
from surreal.pe import PE

TEXT = 0x60000020


def reloc_pe(entries, payload=None):
    body = payload if payload is not None else b"\x90" * 128
    return build_pe([(".text", body, TEXT)], relocs=entries, with_reloc_section=True)


class TestRelocParsing(TempDirCase):
    def load(self, data):
        return PE.open(write(self.path("r.exe"), data))

    def test_parses_blocks(self):
        with self.load(reloc_pe([(0x1000, 10), (0x1008, 10), (0x1010, 3)])) as pe:
            table = reloc.parse_relocs(pe)
            self.assertTrue(table)
            self.assertEqual(table.blocks[0].page_rva, 0x1000)
            self.assertEqual(table.covers_rva(0x1008), 10)
            self.assertEqual(table.covers_rva(0x1010), 3)
            self.assertIsNone(table.covers_rva(0x1004))
            self.assertIn(10, table.types)

    def test_no_reloc_directory(self):
        with self.load(sample_app()) as pe:
            self.assertFalse(reloc.parse_relocs(pe))

    def test_multi_page(self):
        with self.load(reloc_pe([(0x1000, 10), (0x2004, 3)])) as pe:
            table = reloc.parse_relocs(pe)
            self.assertEqual(len(table.blocks), 2)
            self.assertEqual(table.covers_rva(0x2004), 3)

    def test_malformed_table_does_not_raise(self):
        data = bytearray(reloc_pe([(0x1000, 10)]))
        with PE.open(write(self.path("m.exe"), bytes(data))) as pe:
            rva, size = pe.dir(5)
            off = pe.rva_to_offset(rva)
        data[off:off + 8] = b"\xff\xff\xff\xff\xff\xff\xff\xff"
        with PE.open(write(self.path("m2.exe"), bytes(data))) as pe:
            table = reloc.parse_relocs(pe)
            self.assertTrue(table.truncated or not table.blocks)

    def test_out_of_range_directory(self):
        data = bytearray(reloc_pe([(0x1000, 10)]))
        with PE.open(write(self.path("o.exe"), bytes(data))) as pe:
            dirs_off = pe.optional_offset + (112 if pe.is_64 else 96) + 5 * 8
        import struct
        struct.pack_into("<II", data, dirs_off, 0xFFFFFF, 64)
        with PE.open(write(self.path("o2.exe"), bytes(data))) as pe:
            table = reloc.parse_relocs(pe)
            self.assertTrue(table.truncated)

    def test_hunk_risk_classification(self):
        with self.load(reloc_pe([(0x1010, 10)])) as pe:
            class R:
                index = 0
                offset = pe.rva_to_offset(0x1010)
                length = 8
            risks = reloc.analyse_hunks(pe, [R()])
            self.assertTrue(risks[0].absolute_address_write)
            self.assertTrue(risks[0].in_code)
            self.assertIn("DIR64", risks[0].describe(pe))


class TestApplyRefusesRelocatedWrites(TempDirCase):
    def setUp(self):
        super().setUp()
        payload = b"\x90" * 16 + b"\0" * 8 + b"\x90" * 104
        base = reloc_pe([(0x1010, 10)], payload)
        old, new = bytearray(base), bytearray(base)
        # an edit that rewrites the relocated 8-byte absolute address in-place
        off = 0x200 + 0x10
        old[off:off + 8] = (0x100020).to_bytes(8, "little")
        new[off:off + 8] = (0x100030).to_bytes(8, "little")
        self.old = write(self.path("app.exe"), bytes(old))
        self.new = write(self.path("new.exe"), bytes(new))
        bundle, self.stats = diffgen.build_bundle(self.old, self.new, "org.t", "t")
        self.bundle_path = self.path("t.morph")
        bundle.save(self.bundle_path)

    def test_generator_warns(self):
        self.assertTrue(any("relocated" in w for w in self.stats["warnings"]))

    def test_apply_refused_by_default(self):
        bundle = Bundle.load(self.bundle_path)
        with self.assertRaises(patcher.PatchError) as ctx:
            patcher.build_plan(bundle, self.old)
        self.assertIn("allow-abs-address", str(ctx.exception))
        self.assertEqual(ctx.exception.code, 3)

    def test_apply_allowed_with_explicit_flag(self):
        bundle = Bundle.load(self.bundle_path)
        plan = patcher.build_plan(bundle, self.old, allow_abs_address=True)
        self.assertTrue(plan.relocs)
        self.assertTrue(any("ASLR risk accepted" in w for w in plan.warnings))
        patcher.apply_bundle(bundle, self.old, allow_abs_address=True)
        with open(self.old, "rb") as fh:
            self.assertIn((0x100030).to_bytes(8, "little"), fh.read())


class TestRelocFreeTargets(TempDirCase):
    def test_no_reloc_warning_for_plain_code(self):
        old = write(self.path("a.exe"), sample_app())
        new = write(self.path("b.exe"), sample_app(patch=True))
        bundle, stats = diffgen.build_bundle(old, new, "org.t2", "t")
        plan = patcher.build_plan(bundle, old)
        self.assertEqual(plan.relocs, [])
        self.assertTrue(any("no .reloc directory" in w for w in plan.warnings))


if __name__ == "__main__":
    unittest.main()
