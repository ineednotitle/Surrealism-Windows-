"""Low-end budget tests: 4 GB RAM, 2 slow cores, an HDD.

These assert *ceiling* numbers that are generous enough for a Raspberry-Pi-class
runner but tight enough to catch a regression into "read the whole file and sort
it". They also assert the property that actually matters: memory does not grow
with file size.
"""

import os
import sys
import time
import unittest

from helpers import TempDirCase, write

from surreal import memguard, patcher
from surreal.diffgen import build_bundle
from surreal.patchfile import Bundle
from surreal.pe import PE
from surreal.scanner import find_pattern, parse_pattern
from surreal.testkit import sample_app

BIG_MB = int(os.environ.get("SURREAL_PERF_MB", "48"))  # keep CI snappy


def peak_rss_mb() -> float:
    """Peak RSS in MB, or 0.0 where the platform offers no measurement."""
    return memguard.peak_rss_mb()


class TestPerformance(TempDirCase):
    """The 4 GB-RAM budget, expressed as assertions."""

    base = sample_app()
    big_path = ""

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._shared = tempfile.TemporaryDirectory()
        cls.big_path = os.path.join(cls._shared.name, "big_%d.exe" % BIG_MB)
        target = BIG_MB * 1024 * 1024
        with open(cls.big_path, "wb") as fh:
            written = 0
            while written < target:
                take = min(len(cls.base), target - written)
                fh.write(cls.base[:take])
                written += take

    @classmethod
    def tearDownClass(cls):
        cls._shared.cleanup()

    def big_file(self, size_mb=None) -> str:
        return self.big_path

    def test_pe_parse_is_fast_on_large_file(self):
        path = self.big_file()
        t0 = time.time()
        with PE.open(path) as pe:
            self.assertEqual(pe.machine_name, "x64")
            pe.compute_checksum()
        elapsed = time.time() - t0
        self.assertLess(elapsed, 5.0, "PE parse+checksum took %.2fs on %d MB"
                        % (elapsed, BIG_MB))

    def test_scan_is_fast_on_large_file(self):
        path = self.big_file()
        with PE.open(path) as pe:
            t0 = time.time()
            hits = find_pattern(pe.data, parse_pattern("48 8D 15 ?? ?? ?? ??"), limit=10)
            elapsed = time.time() - t0
        self.assertTrue(hits)
        self.assertLess(elapsed, 5.0, "scan took %.2fs" % elapsed)

    def test_diff_and_apply_stream(self):
        old = self.big_file()
        new = self.path("big_edited.exe")
        with open(old, "rb") as src, open(new, "wb") as dst:
            data = bytearray(src.read(BIG_MB * 1024 * 1024))
            data[1024 * 1024] ^= 0xFF        # one edit, early in the file
            data[-4096] ^= 0xFF              # one edit, late
            dst.write(bytes(data))
        t0 = time.time()
        bundle, stats = build_bundle(old, new, "org.perf.big", "Big file patch")
        t_diff = time.time() - t0
        self.assertEqual(len(bundle.hunks), 2)
        # This fixture is a deliberately periodic file (the same 2 KiB block
        # repeated 24k times), so unique literal anchors do not exist. The
        # generator must fall back to section/RVA + offset and say so, rather
        # than pretend it found a unique anchor.
        self.assertEqual(stats["anchored"], 0)
        self.assertTrue(any("no unique literal anchor" in w for w in stats["warnings"]))
        self.assertTrue(all(h.offset is not None for h in bundle.hunks))

        path = self.path("big.morph")
        bundle.save(path)
        loaded = Bundle.load(path)
        t0 = time.time()
        patcher.apply_bundle(loaded, old, keep_backups=0)
        t_apply = time.time() - t0
        self.assertLess(t_diff, 20.0, "diff took %.2fs" % t_diff)
        self.assertLess(t_apply, 20.0, "apply took %.2fs" % t_apply)
        # apply recomputes the PE checksum, so compare everything else
        with PE.open(old) as pe:
            skip = pe._checksum_offset
        with open(old, "rb") as a, open(new, "rb") as b:
            applied, reference = a.read(), b.read()
        self.assertEqual(applied[:skip], reference[:skip])
        self.assertEqual(applied[skip + 4:], reference[skip + 4:])
        self.assertNotEqual(applied[skip:skip + 4], reference[skip:skip + 4])

    def test_memory_does_not_scale_with_file_size(self):
        small = sample_app()
        path = self.path("small.exe")
        write(path, small)
        if not peak_rss_mb():
            self.skipTest("no peak-RSS measurement on %s" % sys.platform)
        with PE.open(path) as pe:
            baseline = peak_rss_mb()
            for _ in range(8):
                find_pattern(pe.data, parse_pattern("48 8D 15 ?? ?? ?? ??"), limit=5)
        big = self.big_file()
        with PE.open(big) as pe:
            for _ in range(4):
                find_pattern(pe.data, parse_pattern("48 8D 15 ?? ?? ?? ??"), limit=5)
        grown = peak_rss_mb() - baseline
        # mmap + find() must not materialise the file: allow a generous 96 MB
        self.assertLess(grown, 96.0,
                        "peak RSS grew %.1f MB while scanning a %d MB file"
                        % (grown, BIG_MB))


if __name__ == "__main__":
    unittest.main()
