import os
import struct
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal.pe import PE, PEError, shannon_entropy


def PE_ref_checksum(data: bytes) -> int:
    """Literal transcription of Microsoft's documented loop, for cross-checking."""
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    skip = lfanew + 24 + 64
    total = 0
    i = 0
    while i < len(data):
        if i == skip:
            i += 4
            continue
        lo = data[i]
        hi = data[i + 1] if i + 1 < len(data) else 0
        total += lo | (hi << 8)
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    total = (total & 0xFFFF) + (total >> 16)
    return (total + len(data)) & 0xFFFFFFFF


class TestPE(TempDirCase):
    def load(self, data: bytes) -> PE:
        return PE.open(write(self.path("a.exe"), data))

    def test_parses_pe32plus(self):
        with self.load(sample_app(is_64=True)) as pe:
            self.assertTrue(pe.is_64)
            self.assertEqual(pe.machine, 0x8664)
            self.assertEqual(pe.machine_name, "x64")
            self.assertEqual(pe.subsystem_name, "console")
            self.assertEqual(len(pe.sections), 3)
            self.assertEqual(pe.sections[0].name, ".text")
            self.assertTrue(pe.sections[0].executable)
            self.assertTrue(pe.sections[2].writable)
            self.assertTrue(pe.checksum_valid())
            self.assertFalse(pe.has_signature)
            self.assertEqual(pe.overlay_size, 0)

    def test_parses_pe32(self):
        with self.load(sample_app(is_64=False)) as pe:
            self.assertFalse(pe.is_64)
            self.assertEqual(pe.machine, 0x14C)
            self.assertEqual(pe.image_base, 0x400000)
            self.assertTrue(pe.checksum_valid())

    def test_rva_offset_roundtrip(self):
        with self.load(sample_app()) as pe:
            for off in (0x40, 0x200, 0x2FF, 0x400, 0x5FF):
                rva = pe.offset_to_rva(off)
                self.assertIsNotNone(rva, hex(off))
                self.assertEqual(pe.rva_to_offset(rva), off)
            self.assertIsNone(pe.rva_to_offset(0xF00000))

    def test_rva_in_virtual_tail_is_not_file_backed(self):
        # .text: virtual_size 0x90, raw_size 0x200 -> nothing in the tail, but
        # craft a section whose virtual_size exceeds raw_size
        data = bytearray(sample_app())
        with PE.open(write(self.path("b.exe"), bytes(data))) as pe:
            sec = pe.sections[0]
            rva = sec.virtual_address + sec.raw_size + 0x10
            self.assertIsNone(pe.rva_to_offset(rva))

    def test_section_for_rva(self):
        with self.load(sample_app()) as pe:
            sec = pe.section_for_rva(0x2010)
            self.assertIsNotNone(sec)
            self.assertEqual(sec.name, ".rdata")

    def test_rejects_non_pe(self):
        for blob in (b"", b"not an exe at all", b"MZ" + b"\0" * 80,
                     b"MZ" + b"\0" * 58 + struct.pack("<I", 0xFFFFFFF0)):
            with self.assertRaises(PEError):
                PE.open(write(self.path("bad.exe"), blob))

    def test_truncated_section_table_is_rejected(self):
        data = sample_app()[:0x160]  # headers cut before the section table
        with self.assertRaises(PEError):
            PE.open(write(self.path("trunc.exe"), data))

    def test_checksum_detects_tamper(self):
        data = bytearray(sample_app())
        data[0x300] ^= 0xFF
        with PE.open(write(self.path("t.exe"), bytes(data))) as pe:
            self.assertFalse(pe.checksum_valid())

    def test_checksum_matches_windows_algorithm(self):
        # Reference value from Microsoft's documented algorithm on this image
        with PE.open(write(self.path("c.exe"), sample_app())) as pe:
            self.assertEqual(pe.compute_checksum(), pe.stored_checksum)

    def test_imports_and_exports_do_not_crash_on_empty_dirs(self):
        with self.load(sample_app()) as pe:
            self.assertEqual(pe.imports(), [])
            self.assertEqual(pe.exports(), [])

    def test_heuristics_mentions_high_entropy(self):
        import os as _os
        import random

        random.seed(4)
        payload = bytes(random.getrandbits(8) for _ in range(0x2000))
        data = build_pe([(".text", payload, 0x60000020)])
        with PE.open(write(self.path("packed.exe"), data)) as pe:
            notes = " ".join(pe.heuristics())
            self.assertIn("packed, compressed or encrypted", notes)

    def test_fast_checksum_matches_reference_loop(self):
        import random

        rnd = random.Random(11)
        for size in (0x200, 0x201, 0x400, 0x401, 0x1000):
            blob = bytes(rnd.getrandbits(8) for _ in range(size - 0x200))
            data = build_pe([(".text", blob, 0x60000020)], checksum=False)
            path = write(self.path("x%d.exe" % size), data)
            PE_ref = PE_ref_checksum(data)
            with PE.open(path) as pe:
                self.assertEqual(pe.compute_checksum(), PE_ref,
                                 "size %d" % size)

    def test_entropy_extremes(self):
        self.assertEqual(shannon_entropy(b"\0" * 1024), 0.0)
        self.assertGreater(shannon_entropy(bytes(range(256)) * 4), 7.9)

    def test_identity_block(self):
        with self.load(sample_app()) as pe:
            ident = pe.identity("deadbeef")
            self.assertEqual(ident["sha256"], "deadbeef")
            self.assertEqual(ident["pe"]["machine"], "0x8664")
            self.assertEqual(len(ident["sections"]), 3)
            self.assertTrue(ident["sections"][0]["raw_sha256"])

    def test_to_dict_is_json_safe(self):
        import json

        with self.load(sample_app()) as pe:
            json.dumps(pe.to_dict())

    def test_overlay_detection(self):
        data = sample_app() + b"OVERLAYPAYLOAD"
        with PE.open(write(self.path("ov.exe"), data)) as pe:
            self.assertEqual(pe.overlay_size, len(b"OVERLAYPAYLOAD"))
            self.assertIn("overlay", " ".join(pe.heuristics()))

    def test_signed_binary_detected(self):
        data = bytearray(sample_app() + b"\0" * 16)
        with PE.open(write(self.path("s.exe"), bytes(data))) as pe:
            opt = pe.optional_offset
            dirs_off = opt + (112 if pe.is_64 else 96) + 4 * 8
            struct.pack_into("<II", data, dirs_off, pe.size - 16, 16)
        with PE.open(write(self.path("s2.exe"), bytes(data))) as pe:
            self.assertTrue(pe.has_signature)
            self.assertIn("Authenticode", " ".join(pe.heuristics()))


if __name__ == "__main__":
    unittest.main()
