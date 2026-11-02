import unittest

from helpers import TempDirCase, sample_app, write

from surreal.scanner import (ScanError, find_both_strings, find_bytes, find_pattern,
                             find_string, parse_pattern)
from surreal.util import format_hex, longest_literal_run, parse_hex_bytes, parse_hex_tokens
from surreal.patchfile import Hunk, Anchor


class TestHexParsing(unittest.TestCase):
    def test_spaced(self):
        self.assertEqual(parse_hex_tokens("48 8B E8"), [0x48, 0x8B, 0xE8])

    def test_wildcards(self):
        self.assertEqual(parse_hex_tokens("48 8B ?? E8"), [0x48, 0x8B, None, 0xE8])
        self.assertEqual(parse_hex_tokens("48,8b,*,e8"), [0x48, 0x8B, None, 0xE8])
        self.assertEqual(parse_hex_tokens("48 8b ? e8"), [0x48, 0x8B, None, 0xE8])

    def test_packed(self):
        self.assertEqual(parse_hex_tokens("488BE8"), [0x48, 0x8B, 0xE8])
        self.assertEqual(parse_hex_tokens("0x48 0x8b"), [0x48, 0x8B])

    def test_nibble_and_ascii(self):
        self.assertEqual(parse_hex_tokens("4 8b f"), [0x04, 0x8B, 0x0F])
        self.assertEqual(parse_hex_tokens("ascii:MZ"), [0x4D, 0x5A])

    def test_errors(self):
        for bad in ("", "zz", "488B E", "48 8b 1g"):
            with self.assertRaises(ValueError):
                parse_hex_tokens(bad)
        with self.assertRaises(ValueError):
            parse_hex_bytes("48 ?? 90")

    def test_longest_literal_run(self):
        pat = parse_hex_tokens("?? ?? 48 8B 05 ?? ?? ?? ?? 90 C3")
        start, needle = longest_literal_run(pat)
        self.assertEqual(start, 2)
        self.assertEqual(needle, bytes([0x48, 0x8B, 0x05]))

    def test_format_hex(self):
        self.assertEqual(format_hex(b"\x48\x8b"), "48 8B")


class TestScanner(TempDirCase):
    def setUp(self):
        super().setUp()
        self.data = sample_app()
        self.path_ = write(self.path("scan.exe"), self.data)

    def test_pattern_finds_known_bytes(self):
        needle = bytes.fromhex("7F0F")
        pat = parse_pattern("7F 0F")
        hits = find_pattern(self.data, pat)
        self.assertEqual(hits, [self.data.find(needle)])

    def test_wildcard_pattern(self):
        pat = parse_pattern("48 8D 15 ?? ?? ?? ??")
        hits = find_pattern(self.data, pat)
        self.assertGreaterEqual(len(hits), 1)
        for h in hits:
            self.assertEqual(self.data[h:h + 3], bytes.fromhex("488D15"))

    def test_pattern_not_found(self):
        self.assertEqual(find_pattern(self.data, parse_pattern("DE AD BE EF CA FE")), [])

    def test_pattern_without_fixed_bytes_is_rejected(self):
        with self.assertRaises(ScanError):
            find_pattern(self.data, [None, None])

    def test_limit(self):
        data = b"A" * 100
        self.assertEqual(len(find_bytes(data, b"AA", limit=5)), 5)

    def test_ascii_and_utf16(self):
        text = "settings.ini"
        ascii_hits = find_string(self.data, text)
        self.assertEqual(len(ascii_hits), 1)
        blob = write(self.path("u16.bin"), b"\0\0" + text.encode("utf-16-le") + b"\0\0")
        with open(blob, "rb") as fh:
            raw = fh.read()
        self.assertEqual(find_string(raw, text, utf16=True), [2])
        both = find_both_strings(raw, text)
        self.assertEqual(both, [(2, "utf16le")])

    def test_start_end_window(self):
        needle = bytes.fromhex("488D15")
        first = self.data.find(needle)
        self.assertEqual(find_pattern(self.data, parse_pattern("48 8D 15"),
                                      start=first + 1), [])

    def test_attribute_pattern_raises_bundle_error(self):
        from surreal.patchfile import Bundle, BundleError

        with self.assertRaises(BundleError):
            Bundle.from_dict({
                "format": "surreal.morph", "format_version": 1, "id": "x",
                "target": {"filename": "a.exe"},
                "hunks": [{"replace": "90", "expect": "90 90"}],
            })

    def test_anchor_and_hunk_serialisation(self):
        a = Anchor(name="x", pattern=[0x48, None, 0x8B], file_offset=16, unique=True)
        self.assertEqual(a.to_dict()["pattern"], "48 ?? 8B")
        h = Hunk(expect=[0x7F], replace=b"\x7E", anchor=0, delta=8, offset=3)
        d = h.to_dict()
        self.assertEqual(d["expect"], "7F")
        self.assertEqual(d["replace"], "7E")
        self.assertEqual((d["anchor"], d["delta"]), (0, 8))


if __name__ == "__main__":
    unittest.main()
