"""Relocation-aware safety checks.

Two independent failure modes are handled here:

1. **ASLR / rebasing (`.reloc`)**: if a hunk writes an absolute address, the
   patched image only stays correct if that address is covered by a base
   relocation entry. ``surreal`` can report such hunks and refuse them unless
   ``--allow-abs-address`` is given, because "it works on my machine" is exactly
   what a broken relocation looks like.

2. **Moved bytes (RVA drift)**: a hunk's ``expect`` bytes can still be present
   in the file after a rebuild has shifted code around. The anchor search finds
   them, but the ``section+rva`` locator may then disagree (or the ``expect``
   may match at a *different* place than the authored RVA). When the bytes are
   found at the authored RVA the hunk is fine; when they are found somewhere
   else, every relative displacement inside the hunk is suspect. This module
   flags that case so the plan can warn or abort instead of silently producing a
   binary that loads and then crashes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .pe import PE


# --------------------------------------------------------------------------- #
# .reloc parsing
# --------------------------------------------------------------------------- #
@dataclass
class RelocBlock:
    page_rva: int
    entries: List[Tuple[int, int]] = field(default_factory=list)  # (type, offset)


@dataclass
class RelocTable:
    blocks: List[RelocBlock] = field(default_factory=list)
    truncated: bool = False

    def __bool__(self) -> bool:
        return bool(self.blocks)

    def covers_rva(self, rva: int) -> Optional[int]:
        """Return the relocation type covering ``rva``, if any."""
        page = rva & 0xFFFFF000
        offset = rva & 0xFFF
        for block in self.blocks:
            if block.page_rva != page:
                continue
            for typ, off in block.entries:
                if off == offset:
                    return typ
            return None
        return None

    @property
    def types(self) -> List[int]:
        seen = set()
        for block in self.blocks:
            for typ, _off in block.entries:
                seen.add(typ)
        return sorted(seen)


RELOC_TYPE_NAMES = {
    0: "ABSOLUTE", 1: "HIGH", 2: "LOW", 3: "HIGHLOW", 4: "HIGHADJ",
    5: "MIPS_JMPADDR/ARM_MOV32", 9: "MIPS_JMPADDR16",
    10: "DIR64",
}


def parse_relocs(pe: PE, max_blocks: int = 100000) -> RelocTable:
    """Parse the base relocation directory. Never raises on malformed input."""
    table = RelocTable()
    rva, size = pe.dir(5)
    if not rva or not size:
        return table
    off = pe.rva_to_offset(rva)
    if off is None:
        table.truncated = True
        return table
    end = min(off + size, pe.size)
    pos = off
    while pos + 8 <= end:
        try:
            page_rva, block_size = struct.unpack_from("<II", pe.data, pos)
        except struct.error:  # pragma: no cover
            break
        if block_size < 8:
            table.truncated = True
            break
        block = RelocBlock(page_rva=page_rva)
        count = (block_size - 8) // 2
        entries_end = min(pos + 8 + count * 2, end)
        for i in range(count):
            entry_pos = pos + 8 + i * 2
            if entry_pos + 2 > entries_end:
                table.truncated = True
                break
            (value,) = struct.unpack_from("<H", pe.data, entry_pos)
            block.entries.append((value >> 12, value & 0x0FFF))
        table.blocks.append(block)
        if len(table.blocks) >= max_blocks:
            table.truncated = True
            break
        pos += block_size
    return table


# --------------------------------------------------------------------------- #
# write-target analysis
# --------------------------------------------------------------------------- #
@dataclass
class HunkRisk:
    index: int
    offset: int
    length: int
    reloc_hits: List[Tuple[int, str]] = field(default_factory=list)
    in_code: bool = False

    @property
    def absolute_address_write(self) -> bool:
        return bool(self.reloc_hits)

    def describe(self, pe: PE) -> str:
        parts = []
        for rva, name in self.reloc_hits:
            parts.append("0x%X (%s)" % (rva, name))
        where = "abs-address field at " + ", ".join(parts) if parts else "plain bytes"
        section = pe.section_for_rva(pe.offset_to_rva(self.offset) or 0)
        sec = section.name if section else "headers/overlay"
        return "hunk %d @0x%X in %s: %s" % (self.index, self.offset, sec, where)


def analyse_hunks(pe: PE, hunks) -> List[HunkRisk]:
    """Classify resolved hunks by what they actually overwrite."""
    table = parse_relocs(pe)
    risks: List[HunkRisk] = []
    for h in hunks:
        risk = HunkRisk(index=h.index, offset=h.offset, length=h.length)
        rva = pe.offset_to_rva(h.offset)
        if rva is not None:
            section = pe.section_for_rva(rva)
            risk.in_code = bool(section and section.executable)
            if table:
                # a 64-bit absolute address is 8 bytes; check every 8/4-byte
                # aligned window that the hunk overwrites
                for stride in (8, 4):
                    start = rva - (rva % stride)
                    pos = start
                    while pos < rva + h.length:
                        typ = table.covers_rva(pos)
                        if typ and typ != 0:
                            risk.reloc_hits.append(
                                (pos, RELOC_TYPE_NAMES.get(typ, str(typ))))
                        pos += stride
        # de-duplicate, keep order
        seen = set()
        unique = []
        for item in risk.reloc_hits:
            if item[0] not in seen:
                seen.add(item[0])
                unique.append(item)
        risk.reloc_hits = unique
        risks.append(risk)
    return risks


# --------------------------------------------------------------------------- #
# displacement heuristics for relocated hunks
# --------------------------------------------------------------------------- #
def relative_displacements(pe: PE, offset: int, data: bytes) -> List[Tuple[int, int]]:
    """Guess ``(position_in_hunk, signed_rel32)`` pairs for x86 rel32 operands.

    Heuristic, deliberately conservative: it looks for the common
    ``E8/E9/0F 8x`` opcode families and *reports*, never "fixes". A human (or a
    rebased build) decides.
    """
    out: List[Tuple[int, int]] = []
    n = len(data)
    i = 0
    while i < n:
        byte = data[i]
        is_rel = byte in (0xE8, 0xE9) or (
            byte == 0x0F and i + 1 < n and 0x80 <= data[i + 1] <= 0x8F)
        if is_rel:
            operand = i + (2 if byte == 0x0F else 1)
            if operand + 4 <= n:
                (disp,) = struct.unpack_from("<i", data, operand)
                rva = pe.offset_to_rva(offset)
                if rva is not None:
                    out.append((rva + operand, disp))
            i = operand + 4
            continue
        i += 1
    return out
