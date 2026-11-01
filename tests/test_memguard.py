"""Memory budget: refuse big allocations before they happen."""

import os
import unittest

from helpers import TempDirCase, sample_app, write

from surreal import memguard


class TestMemGuard(TempDirCase):
    def test_reserve_under_limit(self):
        budget = memguard.MemoryBudget(memguard.peak_rss_mb() + 200)
        budget.reserve(10 * memguard.MB, "small thing")

    def test_reserve_over_limit(self):
        budget = memguard.MemoryBudget(memguard.peak_rss_mb() + 1)
        with self.assertRaises(memguard.MemoryLimitError) as ctx:
            budget.reserve(512 * memguard.MB, "a huge read")
        self.assertIn("--max-mem", str(ctx.exception))
        self.assertAlmostEqual(ctx.exception.want_mb, 512, delta=1)

    def test_zero_bytes_is_fine(self):
        budget = memguard.MemoryBudget(0)
        budget.reserve(0, "nothing")

    def test_read_file_guarded(self):
        path = write(self.path("small.bin"), b"x" * 1024)
        budget = memguard.MemoryBudget(memguard.peak_rss_mb() + 200)
        self.assertEqual(len(budget.read_file(path)), 1024)
        greedy = memguard.MemoryBudget(memguard.peak_rss_mb())
        with self.assertRaises(memguard.MemoryLimitError):
            greedy.read_file(path)

    def test_set_default_returns_budget(self):
        budget = memguard.set_default(64)
        self.assertEqual(budget.limit_mb, 64)
        self.assertFalse(budget.enough_for(10 ** 12))
        self.assertIn("max-mem 64", budget.note())
        memguard.set_default(256)

    def test_peak_rss_is_plausible(self):
        self.assertGreater(memguard.peak_rss_mb(), 1.0)


if __name__ == "__main__":
    unittest.main()
