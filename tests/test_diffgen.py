import os
import unittest

from helpers import TempDirCase, sample_app, write

from surreal.diffgen import (DiffError, build_bundle, choose_anchor, compare_files,
                             exclude_checksum, Range, MAX_ANCHOR_LEN)
from surreal.patchfile import Bundle
from surreal.pe import PE


class TestCompare(TempDirCase):
    def pair(self, a: bytes, b: bytes):
        pa = write(self.path("a.bin"), a)
        pb = write(self.path("b.bin"), b)
        return pa, pb

    def test_identical(self):
        pa, pb = self.pair(b"x" * 100, b"x" * 100)
        self.assertEqual(compare_files(pa, pb), [])

    def test_size_change_rejected(self):
        pa, pb = self.pair(b"x" * 100, b"x" * 101)
        with self.assertRaises(DiffError):
            compare_files(pa, pb)

    def test_single_byte(self):
        pa, pb = self.pair(b"x" * 100, b"x" * 50 + b"y" + b"x" * 49)
        r = compare_files(pa, pb)
        self.assertEqual([(x.start, x.end) for x in r], [(50, 51)])

    def test_merge_gap(self):
        a = bytearray(b"x" * 200)
        b = bytearray(a)
        b[50] = 1
        b[56] = 2  # 5-byte gap
        pa, pb = self.pair(bytes(a), bytes(b))
        self.assertEqual(len(compare_files(pa, pb, merge_gap=16)), 1)
        self.assertEqual(len(compare_files(pa, pb, merge_gap=0)), 2)

    def test_diff_across_chunk_boundary(self):
        # force the compare loop over many chunks
        size = 3 * 1024 * 1024 + 7
        a = b"\xAA" * size
        b = bytearray(a)
        b[1024 * 1024 - 1] = 0xBB
        b[1024 * 1024] = 0xBB
        pa, pb = self.pair(a, bytes(b))
        ranges = compare_files(pa, pb, merge_gap=0)
        self.assertEqual([(r.start, r.end) for r in ranges],
                         [(1024 * 1024 - 1, 1024 * 1024 + 1)])

    def test_too_many_differences(self):
        a = b"\0" * 4096
        b = bytes(0 if i % 4 else 0x41 for i in range(4096))
        pa, pb = self.pair(a, b)
        with self.assertRaises(DiffError):
            compare_files(pa, pb, merge_gap=0, max_ranges=100)


class TestAnchor(TempDirCase):
    def test_anchor_is_unique_and_grows(self):
        import random

        rnd = random.Random(7)
        data = bytearray(rnd.getrandbits(8) for _ in range(400))
        data[40] = 0xFF          # hunk; neighbours are unique within any 8+ bytes
        ranges = [Range(40, 41)]
        anchor = choose_anchor(data, ranges, 0)
        self.assertIsNotNone(anchor)
        astart, hstart, needle = anchor
        self.assertEqual(hstart, 40)
        self.assertLessEqual(len(needle), MAX_ANCHOR_LEN)
        self.assertEqual(data.find(needle), astart)
        self.assertEqual(data.find(needle, astart + 1), -1)

    def test_no_anchor_in_periodic_data(self):
        # a genuinely periodic file cannot be anchored — the generator must say
        # so instead of inventing a guess
        uniform = bytearray(b"\x90" * 512)
        uniform[300] = 0x7F
        self.assertIsNone(choose_anchor(uniform, [Range(300, 301)], 0))
        zeros = bytearray(b"\0" * 512)
        zeros[0] = 1
        self.assertIsNone(choose_anchor(zeros, [Range(0, 1)], 0))


class TestBuildBundle(TempDirCase):
    def test_bundle_from_pe_pair(self):
        old = write(self.path("old.exe"), sample_app())
        new = write(self.path("new.exe"), sample_app(patch=True))
        bundle, stats = build_bundle(old, new, "org.test.patch", "Test patch",
                                     author="tester")
        self.assertGreaterEqual(len(bundle.hunks), 1)
        self.assertEqual(stats["anchored"], len(bundle.hunks))
        self.assertLessEqual(len(bundle.hunks), stats["ranges"])
        for h in bundle.hunks:
            self.assertEqual(len(h.expect), len(h.replace))
            self.assertIsNotNone(h.section)
            self.assertIsNotNone(h.rva)
        self.assertEqual(bundle.target["pe"]["machine"], "0x8664")

    def test_json_roundtrip(self):
        old = write(self.path("old.exe"), sample_app())
        new = write(self.path("new.exe"), sample_app(patch=True))
        bundle, _ = build_bundle(old, new, "org.test.rt", "Roundtrip")
        out = self.path("rt.morph")
        bundle.save(out)
        loaded = Bundle.load(out)
        self.assertEqual(loaded.id, bundle.id)
        self.assertEqual([h.replace for h in loaded.hunks], [h.replace for h in bundle.hunks])
        self.assertEqual([h.expect for h in loaded.hunks], [h.expect for h in bundle.hunks])
        self.assertEqual([h.delta for h in loaded.hunks], [h.delta for h in bundle.hunks])

    def test_only_checksum_differs(self):
        import struct

        old = sample_app()
        pe = PE.open(write(self.path("c1.exe"), old))
        try:
            off = pe._checksum_offset
        finally:
            pe.close()
        tampered = bytearray(old)
        struct.pack_into("<I", tampered, off, 0xDEADBEEF)
        p1 = write(self.path("c1.exe"), old)
        p2 = write(self.path("c2.exe"), bytes(tampered))
        with self.assertRaises(DiffError) as ctx:
            build_bundle(p1, p2, "org.x", "x")
        self.assertIn("checksum", str(ctx.exception).lower())

    def test_exclude_checksum_splits_range(self):
        ranges = [Range(0x90, 0xA0)]
        out, dropped = exclude_checksum(ranges, 0x98)
        self.assertEqual(dropped, 1)
        self.assertEqual([(r.start, r.end) for r in out], [(0x90, 0x98), (0x9C, 0xA0)])

    def test_identical_files(self):
        p1 = write(self.path("i1.exe"), sample_app())
        p2 = write(self.path("i2.exe"), sample_app())
        with self.assertRaises(DiffError):
            build_bundle(p1, p2, "org.x", "x")

    def test_non_pe_rejected_unless_forced(self):
        p1 = write(self.path("t1.bin"), b"a" * 64)
        p2 = write(self.path("t2.bin"), b"a" * 32 + b"b" + b"a" * 31)
        with self.assertRaises(DiffError):
            build_bundle(p1, p2, "org.x", "x")
        bundle, stats = build_bundle(p1, p2, "org.x", "x", require_pe=False)
        self.assertIsNone(bundle.hunks[0].section)
        self.assertEqual(stats["offset_only"], 1)


if __name__ == "__main__":
    unittest.main()
