"""PE header surgery: grow the last section, or append a whole new section.

This is the part of patching that actually rewrites the image layout, so it is
kept in one small module with two rules:

1. **Only the end of the image moves.** A section may grow (or be added) only if
   it is the last section and nothing follows it in the file (no overlay). Then
   every existing RVA keeps its meaning and only derived header fields change.
2. **Every write is computed, never improvised.** :func:`plan_extend_section` and
   :func:`plan_add_section` return a ``Surgery`` object: explicit ``(offset,
   bytes)`` header writes plus the payload to append, with the preconditions
   captured so the applier can verify them again before writing.

Header fields touched (and nothing else):

============================  ==========================================
field                          why
============================  ==========================================
``Section.SizeOfRawData``      the section now occupies more file bytes
``Section.VirtualSize``        it also occupies more virtual bytes
``NumberOfSections``           only for ``add-section``
``SizeOfImage``                the image got bigger
``CheckSum``                   recomputed after writing (in ``patcher``)
============================  ==========================================
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .pe import MACHINES, PE


class SurgeryError(Exception):
    """The requested layout change is not safe or not possible."""


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    rem = value % alignment
    return value if rem == 0 else value + (alignment - rem)


def section_table_offset(pe: PE) -> int:
    return pe.nt_offset + 4 + 20 + pe.size_of_optional_header


def header_slack(pe: PE) -> int:
    """Free bytes between the section table and ``SizeOfHeaders``."""
    used = section_table_offset(pe) + 40 * pe.num_sections
    limit = pe.size_of_headers or align_up(used, pe.file_alignment)
    return max(0, min(limit, pe.size) - used)


@dataclass
class Surgery:
    kind: str                       # "extend-section" | "add-section"
    writes: List[Tuple[int, bytes]] = field(default_factory=list)
    payload: bytes = b""            # appended at EOF (already padded)
    file_size_after: int = 0
    image_size_after: int = 0
    section_name: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "section": self.section_name,
            "payload": len(self.payload),
            "file_size_after": self.file_size_after,
            "image_size_after": self.image_size_after,
            "header_writes": [{"offset": off, "bytes": data.hex()}
                              for off, data in self.writes],
            "notes": list(self.notes),
        }


def _require_last_section(pe: PE, sec) -> None:
    last = pe.sections[-1]
    if sec.index != last.index:
        raise SurgeryError(
            "section %s is not the last section (%s is); growing a section in the "
            "middle would move every following section's data — not supported"
            % (sec.name, last.name))


def _require_no_overlay(pe: PE) -> None:
    if pe.overlay_size:
        raise SurgeryError(
            "the image has a %d-byte overlay after the last section; a size change "
            "would have to absorb or move it. Remove the overlay first, or use "
            "op \"append\" (which keeps it intact)." % pe.overlay_size)


def _image_size(pe: PE, extra_sections: List[Tuple[int, int]] = ()) -> int:
    end = 0
    for sec in pe.sections:
        end = max(end, sec.virtual_address + max(sec.virtual_size, sec.raw_size))
    for va, vsize in extra_sections:
        end = max(end, va + vsize)
    return align_up(end, pe.section_alignment or 0x1000)


def plan_extend_section(pe: PE, section_name: str, payload: bytes,
                        raw_size_before: Optional[int] = None,
                        virtual_size_after: Optional[int] = None) -> Surgery:
    """Grow the last section by appending ``payload`` at EOF."""
    sec = next((s for s in pe.sections if s.name == section_name), None)
    if sec is None:
        raise SurgeryError("section %s does not exist" % section_name)
    if not payload:
        raise SurgeryError("extend-section needs bytes to append")
    _require_last_section(pe, sec)
    _require_no_overlay(pe)
    if sec.raw_end != pe.size:
        raise SurgeryError(
            "the last section's raw data ends at 0x%X but the file is 0x%X bytes: "
            "the extra bytes are an overlay, not section data"
            % (sec.raw_end, pe.size))
    if raw_size_before is not None and sec.raw_size != raw_size_before:
        raise SurgeryError(
            "section %s is 0x%X bytes of raw data, the bundle expects 0x%X"
            % (sec.name, sec.raw_size, raw_size_before))

    data_len = sec.raw_size + len(payload)
    new_raw = align_up(data_len, pe.file_alignment or 0x200)
    if virtual_size_after is None:
        new_virtual = max(sec.virtual_size, data_len)
    else:
        new_virtual = int(virtual_size_after)
        if new_virtual < sec.virtual_size:
            raise SurgeryError(
                "virtual_size_after (0x%X) is smaller than the current VirtualSize "
                "(0x%X)" % (new_virtual, sec.virtual_size))
        if new_virtual > new_raw:
            raise SurgeryError(
                "virtual_size_after (0x%X) exceeds the new SizeOfRawData (0x%X)"
                % (new_virtual, new_raw))
    pad = new_raw - data_len
    payload_padded = bytes(payload) + b"\0" * pad

    header = section_table_offset(pe) + sec.index * 40
    writes = [
        (header + 8, struct.pack("<I", new_virtual)),    # VirtualSize
        (header + 16, struct.pack("<I", new_raw)),       # SizeOfRawData
        (pe.optional_offset + 56, struct.pack("<I", _image_size(pe))),
    ]
    surgery = Surgery(
        kind="extend-section",
        writes=writes,
        payload=payload_padded,
        file_size_after=pe.size + len(payload_padded),
        image_size_after=_image_size(pe),
        section_name=sec.name,
    )
    if sec.executable and not sec.writable:
        surgery.notes.append(
            "growing executable section %s: code added here is loaded with the "
            "same protections (execute/read)" % sec.name)
    if pad:
        surgery.notes.append("%d padding byte(s) added to reach FileAlignment" % pad)
    return surgery


def plan_add_section(pe: PE, name: str, characteristics: int, payload: bytes,
                     virtual_address: Optional[int] = None,
                     virtual_size_after: Optional[int] = None) -> Surgery:
    """Append a brand-new section holding ``payload``."""
    if not payload:
        raise SurgeryError("add-section needs bytes for the new section")
    if not name or len(name) > 8:
        raise SurgeryError("section name must be 1..8 characters, got %r" % (name,))
    _require_no_overlay(pe)
    slack = header_slack(pe)
    if slack < 40:
        raise SurgeryError(
            "no room for another section header: %d free byte(s) before "
            "SizeOfHeaders (0x%X), 40 needed" % (slack, pe.size_of_headers))
    if any(s.name == name for s in pe.sections):
        raise SurgeryError("section %s already exists" % name)

    if virtual_address is None:
        highest = max(s.virtual_address + max(s.virtual_size, s.raw_size)
                      for s in pe.sections)
        va = align_up(highest, pe.section_alignment or 0x1000)
    else:
        va = virtual_address
        for sec in pe.sections:
            if sec.virtual_address <= va < sec.virtual_address + max(
                    sec.virtual_size, sec.raw_size):
                raise SurgeryError("requested RVA 0x%X collides with section %s"
                                   % (va, sec.name))

    raw_ptr = align_up(pe.size, pe.file_alignment or 0x200) if pe.size != align_up(
        pe.size, pe.file_alignment or 0x200) else pe.size
    # data must start at a FileAlignment boundary; pad the file first if needed
    lead_pad = raw_ptr - pe.size
    new_raw = align_up(len(payload), pe.file_alignment or 0x200)
    pad = new_raw - len(payload)
    new_virtual = len(payload) if virtual_size_after is None else int(virtual_size_after)
    if not (0 < new_virtual <= new_raw):
        raise SurgeryError("virtual_size_after (0x%X) must be 1..0x%X"
                           % (new_virtual, new_raw))
    header = section_table_offset(pe) + pe.num_sections * 40
    entry = struct.pack(
        "<8sIIIIIIHHI",
        name.encode("latin-1", "replace")[:8].ljust(8, b"\0"),
        new_virtual,                  # VirtualSize
        va,                           # VirtualAddress
        new_raw,                      # SizeOfRawData
        raw_ptr,                      # PointerToRawData
        0, 0, 0, 0,                   # relocs/lines/reloc count/line count
        characteristics,
    )
    writes = [
        (header, entry),
        (pe.nt_offset + 6, struct.pack("<H", pe.num_sections + 1)),
        (pe.optional_offset + 56,
         struct.pack("<I", _image_size(pe, [(va, new_virtual)]))),
    ]
    surgery = Surgery(
        kind="add-section",
        writes=writes,
        payload=b"\0" * lead_pad + bytes(payload) + b"\0" * pad,
        file_size_after=raw_ptr + new_raw,
        image_size_after=_image_size(pe, [(va, new_virtual)]),
        section_name=name,
    )
    surgery.notes.append("new section %s at RVA 0x%X, file offset 0x%X (raw 0x%X)"
                         % (name, va, raw_ptr, new_raw))
    if lead_pad:
        surgery.notes.append("%d byte(s) of alignment padding before the new section"
                             % lead_pad)
    if slack - 40 < 8:
        surgery.notes.append("header slack is nearly exhausted (%d bytes left)"
                             % (slack - 40))
    return surgery


def predict_checksum_after(pe: PE, surgery: Surgery) -> None:
    """Placeholder hook: the applier recomputes the checksum from the file."""
    return None


def plan_for_hunk(pe: PE, hunk, index: int) -> Surgery:
    """Build the :class:`Surgery` for a resolved ``extend-section``/``add-section``."""
    if hunk.op == "extend-section":
        return plan_extend_section(pe, hunk.section, hunk.replace,
                                   raw_size_before=hunk.raw_size_before,
                                   virtual_size_after=hunk.virtual_size_after)
    if hunk.op == "add-section":
        chars = hunk.characteristics
        if chars is None:
            raise SurgeryError("add-section needs 'characteristics'")
        return plan_add_section(pe, hunk.name or hunk.section or ".smod", chars,
                                hunk.replace, virtual_address=hunk.rva,
                                virtual_size_after=hunk.virtual_size_after)
    raise SurgeryError("hunk %d is not a surgery op (%r)" % (index, hunk.op))


def verify_after(pe_before: PE, surgery: Surgery, path_after: str) -> List[str]:
    """Re-parse the written file and check the layout is what we promised."""
    problems: List[str] = []
    with PE.open(path_after) as after:
        if surgery.kind == "add-section":
            if after.num_sections != pe_before.num_sections + 1:
                problems.append("NumberOfSections is %d, expected %d"
                                % (after.num_sections, pe_before.num_sections + 1))
        elif after.num_sections != pe_before.num_sections:
            problems.append("NumberOfSections changed unexpectedly")
        if after.size_of_image != surgery.image_size_after:
            problems.append("SizeOfImage is 0x%X, expected 0x%X"
                            % (after.size_of_image, surgery.image_size_after))
        if after.size != surgery.file_size_after:
            problems.append("file size is %d, expected %d"
                            % (after.size, surgery.file_size_after))
        for sec in after.sections:
            if sec.raw_end > after.size:
                problems.append("section %s claims data past EOF" % sec.name)
            mapped_end = sec.virtual_address + max(sec.virtual_size, sec.raw_size)
            if mapped_end > after.size_of_image:
                problems.append("section %s extends past SizeOfImage" % sec.name)
        if not after.checksum_valid():
            problems.append("PE checksum is stale")
    if problems:
        raise SurgeryError("post-surgery verification failed: " + "; ".join(problems))
    return problems
