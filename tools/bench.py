#!/usr/bin/env python3
"""Measure surreal on a big synthetic PE — the low-end budget harness.

    python tools/bench.py            # 64 MiB fixture
    python tools/bench.py --mb 256   # stress it

Prints wall time and peak RSS for: parse, checksum, scan, diff, apply, revert.
Everything runs on generated data, so it is safe to run anywhere.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from surreal import memguard, patcher             # noqa: E402
from surreal.diffgen import build_bundle          # noqa: E402
from surreal.journal import Journal               # noqa: E402
from surreal.patchfile import Bundle              # noqa: E402
from surreal.pe import PE                         # noqa: E402
from surreal.scanner import find_pattern, parse_pattern  # noqa: E402
from surreal.testkit import sample_app            # noqa: E402
from surreal.util import human_size, sha256_file  # noqa: E402


def peak_rss_mb() -> float:
    """Peak RSS in MB (0.0 when the platform offers no measurement)."""
    return memguard.peak_rss_mb()


def _rss(value: float) -> str:
    return "%.1f MB" % value if value else "n/a"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb", type=int, default=64)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    work = tempfile.mkdtemp(prefix="surreal-bench-")
    base = sample_app()
    target_bytes = args.mb * 1024 * 1024
    old = os.path.join(work, "app.exe")
    new = os.path.join(work, "app_edited.exe")
    try:
        with open(old, "wb") as fh:
            written = 0
            while written < target_bytes:
                take = min(len(base), target_bytes - written)
                fh.write(base[:take])
                written += take
        edits = (1024 * 1024, target_bytes - 4096)
        with open(old, "rb") as src, open(new, "wb") as dst:
            pos = 0
            while True:
                chunk = bytearray(src.read(4 * 1024 * 1024))
                if not chunk:
                    break
                for edit in edits:
                    if pos <= edit < pos + len(chunk):
                        chunk[edit - pos] ^= 0xFF
                dst.write(chunk)
                pos += len(chunk)
        assert os.path.getsize(new) == os.path.getsize(old)
        size = os.path.getsize(old)

        rows = []

        def timed(label, fn):
            before = peak_rss_mb()
            t0 = time.perf_counter()
            detail = fn()
            dt = time.perf_counter() - t0
            rows.append((label, dt, max(before, peak_rss_mb()), detail))

        def _parse():
            pe = PE.open(old)
            try:
                return "%d sections, %s" % (len(pe.sections),
                                            "PE32+" if pe.is_64 else "PE32")
            finally:
                pe.close()

        timed("open + parse PE", _parse)

        def _sum():
            pe = PE.open(old)
            try:
                return "checksum 0x%08X" % pe.compute_checksum()
            finally:
                pe.close()

        timed("PE checksum", _sum)

        def _scan():
            pe = PE.open(old)
            try:
                hits = find_pattern(pe.data, parse_pattern("48 8D 15 ?? ?? ?? ??"),
                                    limit=5)
                return "%d hits" % len(hits)
            finally:
                pe.close()

        timed("byte-pattern scan", _scan)

        holder = {}

        def _diff():
            bundle, stats = build_bundle(old, new, "org.bench.big", "Bench")
            path = os.path.join(work, "bench.morph")
            bundle.save(path)
            holder["bundle"] = Bundle.load(path)
            holder["sha_before"] = sha256_file(old)
            return "%d hunks, %d anchored" % (len(bundle.hunks), stats["anchored"])

        timed("diff -> .morph bundle", _diff)

        timed("apply (check+backup+write)",
              lambda: "%d bytes written"
              % patcher.apply_bundle(holder["bundle"], old,
                                     keep_backups=0)["bytes_written"])

        timed("revert", lambda: "%s..." % patcher.revert(old)["restored_sha256"][:8])

        def _sign():
            from surreal import keys

            seed = keys.new_seed()
            signed = keys.sign_bundle(holder["bundle"].to_dict(), seed, signer="bench")
            keys.verify_bundle(signed)
            return "sign + verify one bundle"

        timed("bundle signing (ed25519)", _sign)

        assert sha256_file(old) == holder["sha_before"], "revert mismatch"

        # ASCII only: a Windows console may be cp437/cp1252
        print("surreal bench - %s fixture (%d cores)" % (human_size(size),
                                                         os.cpu_count() or 1))
        print("%-28s %9s %10s   %s" % ("step", "time", "peak RSS", "detail"))
        for label, dt, rss, detail in rows:
            print("%-28s %8.2fs %10s   %s" % (label, dt, _rss(rss), detail))
        print("\npeak RSS overall: %s" % _rss(peak_rss_mb()))
        return 0
    finally:
        if args.keep:
            print("workspace: %s" % work)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
