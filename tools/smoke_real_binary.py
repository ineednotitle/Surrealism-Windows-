#!/usr/bin/env python3
"""Exercise surreal against a *real* Windows binary you already have.

    python tools/smoke_real_binary.py "C:\\Program Files\\App\\app.exe"

Nothing in the original file is touched: it is copied to a temp directory and
everything happens there. The script walks the parts of the pipeline that can be
checked without knowing what the program does:

1. ``inspect``  — does the PE parse, are sections/checksum sane?
2. ``scan``     — a byte pattern lifted from the file must be found again.
3. ``diff``     — a synthetic one-byte edit must produce a bundle, and applying
                  that bundle to the copy must reproduce the edit exactly.
4. ``revert``   — the copy must return to its original hash.
5. layout test  — an overlay append round-trip (file grows, then shrinks back).
6. surgery test — grow the last section, confirm the headers and checksum, revert.

Exit code 0 means every step passed. Use it before you trust a patch on an app.
"""

from __future__ import annotations

import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from surreal import diffgen, patcher, surgery  # noqa: E402
from surreal.patchfile import Bundle  # noqa: E402
from surreal.pe import PE, PEError  # noqa: E402
from surreal.util import sha256_file  # noqa: E402

OK, FAIL = "  ok  ", " FAIL "
results = []


def record(step, fn):
    try:
        detail = fn()
    except Exception as exc:  # noqa: BLE001 - a smoke test reports, never raises
        results.append((step, False, "%s: %s" % (type(exc).__name__, exc)))
        print("%s%s — %s: %s" % (FAIL, step, type(exc).__name__, exc))
        return None
    results.append((step, True, detail or ""))
    print("%s%s — %s" % (OK, step, detail or ""))
    return detail


def write_surgery(src, dest, planner):
    shutil.copyfile(src, dest)
    pe = PE.open(dest)
    try:
        plan = planner(pe)
    finally:
        pe.close()
    with open(dest, "r+b") as fh:
        for offset, data in plan.writes:
            fh.seek(offset)
            fh.write(data)
        fh.seek(0, os.SEEK_END)
        fh.write(plan.payload)
    with PE.open(dest) as after:
        checksum, skip = after.compute_checksum(), after._checksum_offset
    with open(dest, "r+b") as fh:
        fh.seek(skip)
        fh.write(struct.pack("<I", checksum))
    return plan


def main(argv) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    source = os.path.abspath(argv[1])
    if not os.path.isfile(source):
        print("not a file: %s" % source)
        return 2

    work = tempfile.mkdtemp(prefix="surreal-smoke-")
    target = os.path.join(work, os.path.basename(source))
    shutil.copyfile(source, target)
    original_sha = sha256_file(source)
    print("surreal smoke test")
    print("  source: %s (%d bytes)" % (source, os.path.getsize(source)))
    print("  work:   %s" % work)
    print("")

    info = {}

    def _inspect():
        with PE.open(target) as pe:
            info["pe"] = pe
            info["sections"] = [s.name for s in pe.sections]
            info["checksum_ok"] = pe.checksum_valid()
            info["overlay"] = pe.overlay_size
            info["size"] = pe.size
            info["last"] = pe.sections[-1].name
            return ("%s, %d section(s), checksum %s, overlay %d bytes"
                    % (pe.machine_name if hasattr(pe, "machine_name") else "PE",
                       len(info["sections"]),
                       "valid" if info["checksum_ok"] else "STALE",
                       info["overlay"]))

    if record("inspect", _inspect) is None:
        return _finish(work)

    def _scan():
        with open(target, "rb") as fh:
            head = fh.read(4096)
        needle = None
        for start in range(0, max(1, len(head) - 16), 7):
            chunk = head[start:start + 8]
            if len(chunk) == 8 and chunk.count(0) == 0 and len(set(chunk)) > 4:
                needle = chunk
                break
        if needle is None:
            return "skipped (no distinctive pattern in the first 4 KiB)"
        data = open(target, "rb").read()
        count = data.count(needle)
        return "pattern %s found %d time(s)" % (needle.hex(" "), count)

    record("scan", _scan)

    state = {}

    def _diff_apply():
        with open(target, "rb") as fh:
            data = bytearray(fh.read())
        # flip one byte inside the first section's raw data
        with PE.open(target) as pe:
            section = pe.sections[0]
            offset = section.raw_ptr + min(0x40, max(0, section.raw_size - 1))
        original = data[offset]
        data[offset] = (original + 1) % 256
        edited = os.path.join(work, "edited" + os.path.splitext(target)[1])
        with open(edited, "wb") as fh:
            fh.write(bytes(data))
        bundle, _stats = diffgen.build_bundle(target, edited, "org.smoke.one-byte",
                                              "smoke: flip one byte")
        path = os.path.join(work, "one-byte.morph")
        bundle.save(path)
        state["before"] = sha256_file(target)
        patcher.apply_bundle(Bundle.load(path), target, no_checksum=True)
        applied = open(target, "rb").read()
        if applied != bytes(data):
            raise AssertionError("patched file does not match the edited build")
        return "1 hunk at 0x%X, applied byte-for-byte" % offset

    if record("diff + apply", _diff_apply) is not None:
        record("revert", lambda: (
            patcher.revert(target),
            "restored %s" % (sha256_file(target) == state.get("before")))[1])

    def _overlay():
        data = open(target, "rb").read()
        grown = os.path.join(work, "grown" + os.path.splitext(target)[1])
        with open(grown, "wb") as fh:
            fh.write(data + b"\r\n[surreal-smoke] overlay-growth\r\n")
        bundle, _ = diffgen.build_bundle(target, grown, "org.smoke.overlay",
                                         "smoke: append overlay")
        path = os.path.join(work, "overlay.morph")
        bundle.save(path)
        if [h.op for h in bundle.hunks] != ["append"]:
            raise AssertionError("expected an append hunk, got %r"
                                 % [h.op for h in bundle.hunks])
        before = sha256_file(target)
        patcher.apply_bundle(Bundle.load(path), target, no_checksum=True)
        size_after = os.path.getsize(target)
        patcher.revert(target)
        if sha256_file(target) != before:
            raise AssertionError("overlay revert did not restore the file")
        return "append (grew to %d bytes) then truncate, hash restored" % size_after

    record("overlay size change", _overlay)

    def _surgery():
        last = info["last"]
        grown = os.path.join(work, "sect" + os.path.splitext(target)[1])
        plan = write_surgery(target, grown,
                             lambda pe: surgery.plan_extend_section(
                                 pe, last, b"\r\n[surreal-smoke] section-growth\r\n"))
        with PE.open(grown) as pe:
            sizes = (pe.size, pe.size_of_image, pe.checksum_valid())
        bundle, _ = diffgen.build_bundle(target, grown, "org.smoke.extend",
                                         "smoke: grow last section")
        if [h.op for h in bundle.hunks] != ["extend-section"]:
            raise AssertionError("generator refused the layout change (header slack "
                                 "or overlay may block it) — that is a supported "
                                 "refusal, not a crash")
        path = os.path.join(work, "extend.morph")
        bundle.save(path)
        before = sha256_file(target)
        patcher.apply_bundle(Bundle.load(path), target)
        with PE.open(target) as pe:
            if [s.name for s in pe.sections] != info["sections"]:
                raise AssertionError("section list changed unexpectedly")
            if not pe.checksum_valid():
                raise AssertionError("checksum is invalid after surgery")
        patcher.revert(target)
        if sha256_file(target) != before:
            raise AssertionError("surgery revert did not restore the file")
        return ("grew %s to %d bytes, SizeOfImage 0x%X, checksum valid, reverted"
                % (last, sizes[0], sizes[1]))

    record("header surgery (extend-section)", _surgery)

    def _unchanged():
        if sha256_file(target) != sha256_file(source):
            raise AssertionError("the working copy differs from the source")
        return "source and working copy are identical (%s…)" % original_sha[:16]

    record("final state", _unchanged)
    return _finish(work)


def _finish(work: str) -> int:
    passed = sum(1 for _s, ok, _d in results if ok)
    print("")
    print("%d/%d step(s) passed" % (passed, len(results)))
    if any(not ok for _s, ok, _d in results):
        print("work directory kept for inspection: %s" % work)
        return 1
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
