"""Deterministic fuzzing: hostile input must produce clean errors, never a crash.

Nothing here proves absence of bugs, but a surprising exception type (KeyError,
struct.error, IndexError, ZeroDivisionError, infinite loop) escaping from a parser
is exactly the class of bug that turns "reject this weird file" into a crash.
"""

import json
import os
import random
import struct
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import patcher
from surreal import repo
from surreal.patchfile import Bundle, BundleError
from surreal.pe import PE, PEError

TEXT = 0x60000020
RDATA = 0x40000040


def parse_or_fail(path):
    """Open (and fully touch) a PE; return None on a clean rejection."""
    try:
        pe = PE.open(path)
    except PEError:
        return None
    try:
        for section in pe.sections:
            _ = (section.name, section.virtual_address, section.raw_size,
                 section.raw_ptr, section.executable, section.writable,
                 section.raw_end, section.rva_end)
            pe.section_for_rva(section.virtual_address or 1)
            pe.rva_to_offset(section.virtual_address or 1)
            pe.offset_to_rva(section.raw_ptr or 1)
            section.contains_rva(section.virtual_address or 1)
            section.to_dict()
        pe.compute_checksum()
        pe.checksum_valid()
        pe.overlay_size
        pe.last_section_end
        pe.dir(5)
        pe.imports()
        pe.exports()
        pe.heuristics()
        pe.word_sum()
        pe.identity()
        pe.to_dict(with_hashes=False)
        return pe
    finally:
        pe.close()


class TestPeFuzz(TempDirCase):
    def test_garbage_bytes(self):
        rng = random.Random(1234)
        for i in range(60):
            size = rng.choice([0, 1, 2, 63, 64, 200, 1024, 4096])
            data = bytes(rng.getrandbits(8) for _ in range(size))
            if rng.random() < 0.5:
                data = b"MZ" + data[2:]
                if size >= 0x40:
                    data = data[:0x3c] + struct.pack("<I", rng.choice(
                        [0, 0x40, 0x80, 0x1000, 0xFFFFFF])) + data[0x40:]
            path = write(self.path("f%d.bin" % i), data)
            parse_or_fail(path)   # never raises anything but PEError

    def test_random_field_corruption(self):
        rng = random.Random(99)
        base = build_pe([(".text", b"\x90" * 0x100, TEXT),
                         (".rdata", b"data" * 40, RDATA)])
        for i in range(80):
            data = bytearray(base)
            for _ in range(rng.randint(1, 8)):
                pos = rng.randrange(0, min(len(data), 0x400))
                data[pos] = rng.getrandbits(8)
            path = write(self.path("c%d.bin" % i), bytes(data))
            parse_or_fail(path)

    def test_truncated_headers(self):
        base = sample_app()
        for cut in (0x10, 0x3c, 0x40, 0x80, 0x100, 0x188, 0x200, len(base) - 1):
            path = write(self.path("t%d.bin" % cut), base[:cut])
            parse_or_fail(path)

    def test_absurd_section_counts(self):
        base = bytearray(sample_app())
        lfanew = struct.unpack_from("<I", base, 0x3c)[0]
        for count in (0, 1, 0xFFFF, 0xFFFFFFFF):
            data = bytearray(base)
            struct.pack_into("<H", data, lfanew + 6, count & 0xFFFF)
            path = write(self.path("n%d.bin" % count), bytes(data))
            parse_or_fail(path)


class TestBundleFuzz(TempDirCase):
    def test_random_json_objects(self):
        rng = random.Random(7)
        keys = ["format", "format_version", "id", "name", "hunks", "anchors",
                "target", "policy", "signature", "version"]
        for _ in range(120):
            raw = {}
            for _ in range(rng.randint(0, 6)):
                raw[rng.choice(keys)] = rng.choice(
                    [None, True, 0, 1, 1.5, "", "x", [], {}, {"a": 1}, [1, 2]])
            try:
                Bundle.from_dict(raw)
            except BundleError:
                pass   # the only acceptable failure mode

    def test_random_hunks(self):
        rng = random.Random(11)
        values = [None, "", "00", "zz", "41 42", "??", "4", 5, [], {}, "AA " * 40]
        ops = ["patch", "append", "truncate", "extend-section", "add-section",
               "bogus", None, 7]
        base = {"format": "surreal.morph", "format_version": 1, "id": "org.fuzz",
                "name": "fuzz",
                "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32}}
        for _ in range(150):
            hunk = {}
            for _ in range(rng.randint(1, 5)):
                hunk[rng.choice(["op", "expect", "replace", "anchor", "delta",
                                 "section", "rva", "offset", "enabled",
                                 "replace_hex", "name", "characteristics",
                                 "virtual_size_after", "raw_size_before"])] = \
                    rng.choice(values)
            raw = dict(base, hunks=[hunk])
            try:
                Bundle.from_dict(raw)
            except BundleError:
                pass

    def test_truncated_and_binary_files(self):
        base = Bundle.from_dict({
            "format": "surreal.morph", "format_version": 1, "id": "org.fuzz.file",
            "name": "fuzz",
            "target": {"filename": "a.exe", "size": 1, "sha256": "00" * 32},
            "hunks": [{"offset": 0, "expect": "00", "replace": "41"}],
        })
        path = self.path("good.morph")
        base.save(path)
        with open(path, "rb") as fh:
            text = fh.read()
        rng = random.Random(3)
        for i in range(40):
            cut = rng.randrange(1, len(text) - 1)
            variant = write(self.path("t%d.morph" % i), text[:cut])
            try:
                Bundle.load(variant)
            except BundleError:
                pass
        for i in range(20):
            variant = write(self.path("b%d.morph" % i),
                            bytes(rng.getrandbits(8) for _ in range(64)))
            try:
                Bundle.load(variant)
            except BundleError:
                pass


class TestPlannerFuzz(TempDirCase):
    """Whatever the loader accepts must either plan cleanly or raise PatchError."""

    def test_random_plans(self):
        rng = random.Random(4242)
        app = write(self.path("app.exe"),
                    build_pe([(".text", b"\x90" * 0x100, TEXT),
                              (".rdata", b"data" * 40, RDATA)]))
        for _ in range(200):
            hunk = {
                "op": rng.choice(["patch", "append", "truncate",
                                  "extend-section", "add-section"]),
                "replace": rng.choice(["41", "41 42", "00" * 4]),
                "expect": rng.choice(["00", "", "90 90", "00 00 00 00"]),
                "offset": rng.choice([0, 5, 0x1000, None]),
                "section": rng.choice([".text", ".nope", None]),
                "name": rng.choice([".smod", "", None]),
                "characteristics": rng.choice(["0x40000040", None]),
                "delta": rng.choice([0, 3, None]),
            }
            raw = {"format": "surreal.morph", "format_version": 1,
                   "id": "org.fuzz.plan", "name": "fuzz",
                   "target": {"filename": "app.exe", "size": os.path.getsize(app),
                              "sha256": "00" * 32},
                   "hunks": [hunk]}
            try:
                bundle = Bundle.from_dict(raw)
            except BundleError:
                continue
            try:
                patcher.build_plan(bundle, app)
            except patcher.PatchError:
                pass


class TestRepoFuzz(TempDirCase):
    def test_mutated_index(self):
        rng = random.Random(5)
        base = {
            "format": "surreal.repo", "format_version": 1, "name": "fuzz",
            "bundles": [{"id": "org.a", "file": "a.morph",
                         "bundle_sha256": "00" * 32}],
        }
        path = self.path("repo.json")
        for _ in range(60):
            raw = json.loads(json.dumps(base))
            target = rng.choice([raw, raw["bundles"][0]])
            key = rng.choice(list(target))
            target[key] = rng.choice([None, 1, "", "x", [], {}, "../a.morph",
                                      "/abs/a.morph"])
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(raw, fh)
            try:
                repo.load_index(path)
            except repo.RepoError:
                pass


if __name__ == "__main__":
    unittest.main()
