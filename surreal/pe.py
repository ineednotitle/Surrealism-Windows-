"""Minimal, memory-frugal PE32 / PE32+ parser.

Everything is read through ``struct.unpack_from`` against a ``bytes`` or
``mmap.mmap`` object, so parsing a 200 MB executable costs a few KB of RSS.
"""

from __future__ import annotations

import array
import math
import struct
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MACHINES = {
    0x014C: "i386",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x0200: "IA64",
}

SUBSYSTEMS = {
    1: "native",
    2: "gui",
    3: "console",
    7: "efi-app",
    9: "win-ce",
    10: "efi-rom",
    16: "boot",
}

DIR_NAMES = {
    0: "export", 1: "import", 2: "resource", 3: "exception", 4: "security",
    5: "basereloc", 6: "debug", 7: "architecture", 8: "globalptr", 9: "tls",
    10: "loadconfig", 11: "boundimport", 12: "iat", 13: "delayimport",
    14: "clr", 15: "reserved",
}

SCN_CNT_CODE = 0x00000020
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

MAX_DIRS = 16


class PEError(Exception):
    """Raised when the file is not a parseable PE image."""


def _u8(d, o: int) -> int:
    return struct.unpack_from("<B", d, o)[0]


def _u16(d, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _u64(d, o: int) -> int:
    return struct.unpack_from("<Q", d, o)[0]


@dataclass
class Section:
    index: int
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int
    entropy: float = 0.0
    raw_sha256: str = ""

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & (SCN_CNT_CODE | SCN_MEM_EXECUTE))

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def rva_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_size)

    @property
    def raw_end(self) -> int:
        return self.raw_ptr + self.raw_size

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.rva_end

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "rva": self.virtual_address,
            "virtual_size": self.virtual_size,
            "raw_ptr": self.raw_ptr,
            "raw_size": self.raw_size,
            "executable": self.executable,
            "writable": self.writable,
            "entropy": round(self.entropy, 3),
            "raw_sha256": self.raw_sha256,
        }


def sum_words(view) -> int:
    """One's-complement-friendly sum of little-endian 16-bit words in ``view``.

    ``array('H')`` + ``sum()`` is C-speed; folding the carry is done by the
    caller and is equivalent to folding after every add (end-around carry is
    associative).
    """
    n = len(view)
    if n == 0:
        return 0
    total = 0
    big_endian = sys.byteorder == "big"  # PE words are little-endian
    step = 8 * 1024 * 1024               # bound the temporary copy, not the file
    pos = 0
    while pos < n:
        end = min(pos + step, n)
        end -= (end - pos) & 1
        if end > pos:
            arr = array.array("H")
            arr.frombytes(view[pos:end])
            if big_endian:
                arr.byteswap()
            total += sum(arr)
            pos = end
        else:
            break
    if n & 1 and pos >= n - 1:
        total += view[n - 1]
    return total


def fold_checksum(total: int, size: int) -> int:
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + size) & 0xFFFFFFFF


def shannon_entropy(data, sample_limit: int = 262144) -> float:
    """Entropy in bits/byte, computed over at most ``sample_limit`` bytes."""
    n = len(data)
    if n == 0:
        return 0.0
    if n > sample_limit:
        step = n // sample_limit
        view = memoryview(data)[::step][:sample_limit].tobytes()
    else:
        view = bytes(data)
    counts = [0] * 256
    for b in view:
        counts[b] += 1
    total = float(len(view))
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


class PE:
    """Parsed PE image. Construct with :meth:`from_bytes` or :meth:`open`."""

    def __init__(self, data, path: str = "<memory>", owning_file=None):
        self.data = data
        self.path = path
        self._file = owning_file
        self.size = len(data)
        self.warnings: List[str] = []
        self.sections: List[Section] = []
        self.data_dirs: List[Tuple[int, int]] = []
        self._parse()

    # -- lifecycle ---------------------------------------------------------- #
    @classmethod
    def open(cls, path: str) -> "PE":
        import mmap

        fh = open(path, "rb")
        try:
            size = fh.seek(0, 2)
            fh.seek(0)
            if size == 0:
                raise PEError("%s is empty" % path)
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except BaseException:
            fh.close()
            raise
        try:
            return cls(mm, path=path, owning_file=fh)
        except BaseException:
            mm.close()
            fh.close()
            raise

    def close(self) -> None:
        try:
            if hasattr(self.data, "close"):
                self.data.close()
        finally:
            if self._file is not None:
                self._file.close()
                self._file = None

    def __enter__(self) -> "PE":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- parsing ------------------------------------------------------------ #
    def _parse(self) -> None:
        d = self.data
        if self.size < 64 or d[0:2] != b"MZ":
            raise PEError("not a PE file: missing MZ signature")
        try:
            lfanew = _u32(d, 0x3C)
        except struct.error as exc:  # pragma: no cover - truncated
            raise PEError("truncated DOS header") from exc
        if lfanew <= 0 or lfanew + 24 > self.size:
            raise PEError("bogus e_lfanew (0x%X)" % lfanew)
        if bytes(d[lfanew : lfanew + 4]) != b"PE\0\0":
            raise PEError("not a PE file: missing PE signature")
        self.nt_offset = lfanew
        coff = lfanew + 4
        try:
            (self.machine, self.num_sections, self.timestamp, _sym_ptr,
             _sym_count, self.size_of_optional_header,
             self.characteristics) = struct.unpack_from("<HHIIIHH", d, coff)
        except struct.error as exc:
            raise PEError("truncated COFF header") from exc

        opt = coff + 20
        self.optional_offset = opt
        if self.size_of_optional_header < 2 or opt + 2 > self.size:
            raise PEError("missing optional header")
        self.magic = _u16(d, opt)
        if self.magic not in (0x10B, 0x20B):
            raise PEError("unsupported optional header magic 0x%X" % self.magic)
        self.is_64 = self.magic == 0x20B
        try:
            self._parse_optional(opt)
        except struct.error as exc:
            raise PEError("truncated optional header") from exc

        self._checksum_offset = opt + 64
        self._parse_sections(coff + 20 + self.size_of_optional_header)
        self._compute_entropy()
        self._detect_overlay()
        self._detect_signature()

    def _parse_optional(self, opt: int) -> None:
        d = self.data
        self.entrypoint_rva = _u32(d, opt + 16)
        self.base_of_code = _u32(d, opt + 20)
        if self.is_64:
            self.image_base = _u64(d, opt + 24)
            self.section_alignment = _u32(d, opt + 32)
            self.file_alignment = _u32(d, opt + 36)
            self.size_of_image = _u32(d, opt + 56)
            self.size_of_headers = _u32(d, opt + 60)
            self.stored_checksum = _u32(d, opt + 64)
            self.subsystem = _u16(d, opt + 68)
            self.dll_characteristics = _u16(d, opt + 70)
            self.num_dirs = _u32(d, opt + 108)
            dirs_off = opt + 112
        else:
            self.image_base = _u32(d, opt + 28)
            self.section_alignment = _u32(d, opt + 32)
            self.file_alignment = _u32(d, opt + 36)
            self.size_of_image = _u32(d, opt + 56)
            self.size_of_headers = _u32(d, opt + 60)
            self.stored_checksum = _u32(d, opt + 64)
            self.subsystem = _u16(d, opt + 68)
            self.dll_characteristics = _u16(d, opt + 70)
            self.num_dirs = _u32(d, opt + 92)
            dirs_off = opt + 96

        count = min(self.num_dirs, MAX_DIRS)
        if self.num_dirs > MAX_DIRS:
            self.warnings.append(
                "NumberOfRvaAndSizes=%d > %d, only the first %d are parsed"
                % (self.num_dirs, MAX_DIRS, MAX_DIRS))
        for i in range(count):
            off = dirs_off + i * 8
            if off + 8 > self.size:
                break
            self.data_dirs.append((_u32(d, off), _u32(d, off + 4)))
        while len(self.data_dirs) < MAX_DIRS:
            self.data_dirs.append((0, 0))

    def _parse_sections(self, table: int) -> None:
        d = self.data
        for i in range(self.num_sections):
            off = table + i * 40
            if off + 40 > self.size:
                self.warnings.append("section table truncated at entry %d" % i)
                break
            name = bytes(d[off : off + 8]).rstrip(b"\0").decode("latin-1", "replace")
            (vsize, vaddr, rawsize, rawptr, _relptr, _lineptr, _nrel,
             _nline, chars) = struct.unpack_from("<IIIIIIHHI", d, off + 8)
            self.sections.append(Section(
                index=i, name=name, virtual_size=vsize, virtual_address=vaddr,
                raw_size=rawsize, raw_ptr=rawptr, characteristics=chars))
            if rawptr + rawsize > self.size:
                self.warnings.append(
                    "section %s raw data extends past EOF (0x%X+0x%X > 0x%X)"
                    % (name, rawptr, rawsize, self.size))
        if not self.sections:
            raise PEError("PE image has no sections")

    def _compute_entropy(self) -> None:
        import hashlib

        d = self.data
        for sec in self.sections:
            end = min(sec.raw_end, self.size)
            if sec.raw_ptr >= self.size or end <= sec.raw_ptr:
                continue
            view = memoryview(d)[sec.raw_ptr:end]
            sec.entropy = shannon_entropy(view)
            h = hashlib.sha256()
            step = 1024 * 1024
            for off in range(0, len(view), step):
                h.update(view[off : off + step])
            sec.raw_sha256 = h.hexdigest()

    def _detect_overlay(self) -> None:
        last = max((s.raw_end for s in self.sections if s.raw_end <= self.size), default=0)
        self.last_section_end = min(last, self.size)
        self.overlay_offset = self.last_section_end
        self.overlay_size = max(0, self.size - self.last_section_end)

    def _detect_signature(self) -> None:
        rva, size = self.data_dirs[4]
        self.cert_offset = rva
        self.cert_size = size
        self.has_signature = bool(rva and size and rva + size <= self.size)

    # -- queries ------------------------------------------------------------ #
    @property
    def machine_name(self) -> str:
        return MACHINES.get(self.machine, "0x%04X" % self.machine)

    @property
    def subsystem_name(self) -> str:
        return SUBSYSTEMS.get(self.subsystem, str(self.subsystem))

    @property
    def is_dotnet(self) -> bool:
        rva, size = self.data_dirs[14]
        return bool(rva and size)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    def dir(self, index: int) -> Tuple[int, int]:
        return self.data_dirs[index] if index < len(self.data_dirs) else (0, 0)

    def section_for_rva(self, rva: int) -> Optional[Section]:
        for sec in self.sections:
            if sec.contains_rva(rva):
                return sec
        return None

    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Map an RVA to a file offset, ``None`` when not backed by file data."""
        if rva < self.size_of_headers and rva < self.size:
            return rva
        sec = self.section_for_rva(rva)
        if sec is None:
            return None
        delta = rva - sec.virtual_address
        if delta >= sec.raw_size:
            return None  # in the zero-filled tail (virtual_size > raw_size)
        off = sec.raw_ptr + delta
        if off >= self.size:
            return None
        return off

    def offset_to_rva(self, offset: int) -> Optional[int]:
        for sec in self.sections:
            if sec.raw_ptr <= offset < sec.raw_end:
                return sec.virtual_address + (offset - sec.raw_ptr)
        if 0 <= offset < min(self.size_of_headers, self.size):
            return offset
        return None

    def word_sum(self) -> int:
        """Unfolded 16-bit word sum of the whole image, CheckSum field treated as 0."""
        mv = memoryview(self.data)
        skip = self._checksum_offset
        if skip % 2 == 0 and skip + 4 <= self.size:
            return sum_words(mv[0:skip]) + sum_words(mv[skip + 4:self.size])
        # Rare: an odd CheckSum offset (hand-crafted headers). Pair-wise walk.
        total = 0
        d = self.data
        i = 0
        while i < self.size:
            if i == skip:
                i += 4
                continue
            hi = d[i + 1] if i + 1 < self.size else 0
            total += d[i] | (hi << 8)
            i += 2
        return total

    def compute_checksum(self) -> int:
        """The genuine PE image checksum (what ``CheckSumMappedFile`` returns)."""
        return fold_checksum(self.word_sum(), self.size)

    def checksum_valid(self) -> bool:
        return self.compute_checksum() == self.stored_checksum

    # -- imports / exports -------------------------------------------------- #
    def imports(self, max_dlls: int = 64, max_funcs: int = 256) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        rva, size = self.dir(1)
        if not rva:
            return out
        off = self.rva_to_offset(rva)
        if off is None:
            return out
        for i in range(max_dlls):
            ent = off + i * 20
            if ent + 20 > self.size:
                break
            try:
                oft, _ts, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", self.data, ent)
            except struct.error:
                break
            if not name_rva and not first_thunk:
                break
            name_off = self.rva_to_offset(name_rva)
            if name_off is None:
                break
            out.append({
                "dll": self._cstring(name_off),
                "thunks": self._thunk_names(first_thunk or oft, max_funcs),
            })
        return out

    def _thunk_names(self, thunk_rva: int, limit: int) -> List[str]:
        names: List[str] = []
        off = self.rva_to_offset(thunk_rva)
        if off is None:
            return names
        width, flag = (8, 1 << 63) if self.is_64 else (4, 1 << 31)
        for i in range(limit):
            pos = off + i * width
            if pos + width > self.size:
                break
            val = _u64(self.data, pos) if width == 8 else _u32(self.data, pos)
            if val == 0:
                break
            if val & flag:
                names.append("ordinal#%d" % (val & 0xFFFF))
                continue
            hint_off = self.rva_to_offset(val & 0x7FFFFFFF)
            if hint_off is None:
                names.append("?")
                continue
            names.append(self._cstring(hint_off + 2))
        if len(names) == limit:
            names.append("...")
        return names

    def exports(self, limit: int = 256) -> List[Dict[str, Any]]:
        rva, size = self.dir(0)
        off = self.rva_to_offset(rva) if rva else None
        if off is None or off + 40 > self.size:
            return []
        try:
            (_flags, _ts, _maj, _min, name_rva, base, n_funcs, n_names,
             funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", self.data, off)
        except struct.error:
            return []
        dll_name = ""
        name_off = self.rva_to_offset(name_rva) if name_rva else None
        if name_off is not None:
            dll_name = self._cstring(name_off)
        out = [{"dll": dll_name, "base": base, "functions": n_funcs, "names": []}]
        names_off = self.rva_to_offset(names_rva) if names_rva else None
        ords_off = self.rva_to_offset(ords_rva) if ords_rva else None
        funcs_off = self.rva_to_offset(funcs_rva) if funcs_rva else None
        if names_off and ords_off and funcs_off:
            for i in range(min(n_names, limit)):
                try:
                    n_rva = _u32(self.data, names_off + i * 4)
                    ordinal = _u16(self.data, ords_off + i * 2)
                    f_rva = _u32(self.data, funcs_off + ordinal * 4)
                except struct.error:
                    break
                s_off = self.rva_to_offset(n_rva)
                label = self._cstring(s_off) if s_off is not None else "?"
                out[0]["names"].append(
                    {"name": label, "ordinal": base + ordinal, "rva": f_rva})
        return out

    def _cstring(self, offset: int, maxlen: int = 256) -> str:
        end = min(self.size, offset + maxlen)
        raw = bytes(memoryview(self.data)[offset:end]).split(b"\0", 1)[0]
        return raw.decode("latin-1", "replace")

    # -- report ------------------------------------------------------------- #
    def to_dict(self, with_hashes: bool = True) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "path": self.path,
            "size": self.size,
            "format": "PE32+" if self.is_64 else "PE32",
            "machine": "0x%04X" % self.machine,
            "machine_name": self.machine_name,
            "timestamp": self.timestamp,
            "characteristics": "0x%04X" % self.characteristics,
            "is_dll": self.is_dll,
            "subsystem": self.subsystem_name,
            "dll_characteristics": "0x%04X" % self.dll_characteristics,
            "entrypoint_rva": self.entrypoint_rva,
            "image_base": self.image_base,
            "size_of_image": self.size_of_image,
            "size_of_headers": self.size_of_headers,
            "section_alignment": self.section_alignment,
            "file_alignment": self.file_alignment,
            "stored_checksum": self.stored_checksum,
            "computed_checksum": self.compute_checksum(),
            "checksum_valid": self.checksum_valid(),
            "dotnet": self.is_dotnet,
            "authenticode": self.has_signature,
            "certificate": {"offset": self.cert_offset, "size": self.cert_size},
            "overlay": {"offset": self.overlay_offset, "size": self.overlay_size},
            "data_directories": {
                DIR_NAMES.get(i, str(i)): {"rva": rva, "size": size}
                for i, (rva, size) in enumerate(self.data_dirs) if rva or size
            },
            "sections": [s.to_dict() for s in self.sections],
            "warnings": list(self.warnings),
        }
        if not with_hashes:
            for sec in info["sections"]:
                sec.pop("raw_sha256", None)
        return info

    def identity(self, sha256: str = "") -> Dict[str, Any]:
        """Compact identity block stored in a ``.morph`` bundle."""
        import os

        return {
            "filename": os.path.basename(self.path),
            "size": self.size,
            "sha256": sha256,
            "pe": {
                "magic": "0x%03X" % self.magic,
                "machine": "0x%04X" % self.machine,
                "timestamp": self.timestamp,
                "entrypoint_rva": self.entrypoint_rva,
                "image_base": self.image_base,
            },
            "authenticode": self.has_signature,
            "sections": [
                {"name": s.name, "rva": s.virtual_address,
                 "raw_size": s.raw_size, "raw_sha256": s.raw_sha256}
                for s in self.sections
            ],
        }

    def heuristics(self) -> List[str]:
        """Cheap, honest 'what am I looking at' notes — never verdicts."""
        notes: List[str] = []
        if self.warnings:
            notes.extend(self.warnings)
        for sec in self.sections:
            if sec.entropy > 7.2 and sec.raw_size > 4096:
                notes.append(
                    "section %s is %.1f bits/byte: likely packed, compressed or encrypted"
                    % (sec.name, sec.entropy))
        names = {s.name.lower() for s in self.sections}
        for odd, why in (("upx0", "UPX packer"), ("upx1", "UPX packer"),
                         (".aspack", "ASPack packer"), (".themida", "Themida VM"),
                         (".vmp0", "VMProtect VM"), (".enigma1", "Enigma protector")):
            if odd in names:
                notes.append("section %s present: looks like %s; unpack with the "
                             "vendor's own tool before patching" % (odd, why))
        if self.overlay_size > 0:
            notes.append("overlay: %d bytes after the last section (installer "
                         "payload, self-extractor data or signature blob)"
                         % self.overlay_size)
        if self.has_signature:
            notes.append("Authenticode signature present: any byte edit voids it "
                         "(the tool warns before writing)")
        return notes
