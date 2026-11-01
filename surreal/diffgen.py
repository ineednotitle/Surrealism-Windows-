"""Generate a ``.morph`` bundle from a before/after pair of binaries.

Pipeline (all streaming, constant memory):

1. compare the two files in 1 MiB chunks → ``[start, end)`` ranges
2. coalesce ranges closer than ``merge_gap`` (a 4-byte constant edit must
   become one hunk, not four)
3. for each range pick an anchor: the shortest literal window immediately
   before (or, failing that, after) the hunk that occurs **exactly once** in the
   whole target binary — proven by a full scan, not assumed
4. record section+RVA and file offset as corroborating locators
5. capture identity of the target (size, sha256, PE headers, section hashes)
"""

from __future__ import annotations

import datetime
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import TOOL_NAME, __version__
from .patchfile import Anchor, Bundle, Hunk, Policy
from .pe import PE, PEError
from .util import CHUNK, sha256_file

MAX_ANCHOR_LEN = 64
MIN_ANCHOR_LEN = 8
DEFAULT_MERGE_GAP = 16


class DiffError(Exception):
    pass


@dataclass
class Range:
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


def compare_files(old_path: str, new_path: str, merge_gap: int = DEFAULT_MERGE_GAP,
                  max_ranges: int = 10000) -> List[Range]:
    """Return merged differing ranges between two same-length files."""
    old_size = os.path.getsize(old_path)
    new_size = os.path.getsize(new_path)
    if old_size != new_size:
        raise DiffError(
            "files differ in size (%d vs %d bytes): size-changing patches are not "
            "supported in format v1 (see PLAN.md §3.1 step 5)" % (old_size, new_size))

    raw: List[Range] = []
    with open(old_path, "rb") as fa, open(new_path, "rb") as fb:
        base = 0
        while base < old_size:
            a = fa.read(CHUNK)
            b = fb.read(CHUNK)
            if not a or not b:
                break
            n = min(len(a), len(b))
            if a[:n] == b[:n]:
                base += n
                continue
            i = 0
            while i < n:
                if a[i] == b[i]:
                    i += 1
                    continue
                start = i
                while i < n and a[i] != b[i]:
                    i += 1
                raw.append(Range(base + start, base + i))
                if len(raw) > max_ranges:
                    raise DiffError(
                        "more than %d differing ranges: these files are not a "
                        "patchable pair (different build?)" % max_ranges)
            base += n

    # merge across chunk boundaries and small gaps
    merged: List[Range] = []
    for r in raw:
        if merged and r.start - merged[-1].end <= merge_gap:
            merged[-1].end = max(merged[-1].end, r.end)
        else:
            merged.append(Range(r.start, r.end))

    # merge single-byte islands inside an already-dirty span (e.g. a changed
    # integer whose bytes happen to coincide)
    stable: List[Range] = []
    for r in merged:
        if stable and r.start - stable[-1].end <= merge_gap:
            stable[-1].end = max(stable[-1].end, r.end)
        else:
            stable.append(Range(r.start, r.end))
    return stable


def _candidates_for_anchor(ranges: List[Range], idx: int, size: int) -> List[Tuple[int, int]]:
    """Yield ``(anchor_start, hunk_start)`` candidate placements, nearest first."""
    r = ranges[idx]
    prev_end = ranges[idx - 1].end if idx > 0 else 0
    next_start = ranges[idx + 1].start if idx + 1 < len(ranges) else size
    out: List[Tuple[int, int]] = []
    span_before = r.start - prev_end
    for length in (MIN_ANCHOR_LEN, 12, 16, 24, 32, 48, MAX_ANCHOR_LEN):
        if length > span_before:
            continue
        out.append((r.start - length, r.start))
    span_after = next_start - r.end
    for length in (MIN_ANCHOR_LEN, 12, 16, 24, 32, 48, MAX_ANCHOR_LEN):
        if length > span_after:
            continue
        out.append((r.end, r.end + length))
    return out


def choose_anchor(data, ranges: List[Range], idx: int) -> Optional[Tuple[int, int, bytes]]:
    """Return ``(anchor_offset, hunk_offset, anchor_bytes)`` or ``None``."""
    size = len(data)
    for astart, hstart in _candidates_for_anchor(ranges, idx, size):
        needle = bytes(data[astart:hstart])
        if len(needle) < MIN_ANCHOR_LEN:
            continue
        first = data.find(needle)
        if first < 0:
            continue
        second = data.find(needle, first + 1)
        if second >= 0:
            continue  # not unique — grow the context instead
        return astart, hstart, needle
    return None


def build_bundle(old_path: str, new_path: str, bundle_id: str, name: str,
                 author: str = "", description: str = "", notes: str = "",
                 merge_gap: int = DEFAULT_MERGE_GAP, require_pe: bool = True,
                 version: str = "1.0.0",
                 created_utc: Optional[str] = None) -> Tuple[Bundle, dict]:
    """Create an in-memory :class:`Bundle`. Returns ``(bundle, stats)``."""
    ranges = compare_files(old_path, new_path, merge_gap=merge_gap)
    if not ranges:
        raise DiffError("the two files are byte-identical — nothing to record")

    stats = {"ranges": len(ranges), "anchored": 0, "section_rva": 0,
             "offset_only": 0, "warnings": []}

    try:
        pe = PE.open(old_path)
    except (PEError, OSError) as exc:
        if require_pe:
            raise DiffError("target is not a readable PE image: %s" % exc) from exc
        pe = None

    new_fh = open(new_path, "rb")
    try:
        if pe is not None:
            # The PE checksum field is derived data: surreal recomputes it on
            # apply, so a differing checksum must never become a hunk of its own.
            ranges, dropped = exclude_checksum(ranges, pe._checksum_offset)
            if dropped:
                stats["warnings"].append(
                    "ignored %d difference(s) inside the PE CheckSum field "
                    "(recomputed automatically on apply)" % dropped)
            if not ranges:
                raise DiffError("the only differences are in the PE checksum field "
                                "— these builds are identical for patching purposes")
            header_hits = [r for r in ranges if r.start < pe.size_of_headers]
            if header_hits:
                stats["warnings"].append(
                    "%d hunk(s) fall inside the PE headers (< SizeOfHeaders 0x%X); "
                    "headers are structural — double-check those"
                    % (len(header_hits), pe.size_of_headers))

        if pe is not None:
            data = pe.data
        else:
            with open(old_path, "rb") as fh:
                data = fh.read()
        anchors: List[Anchor] = []
        hunks: List[Hunk] = []

        for idx, r in enumerate(ranges):
            old_bytes = bytes(data[r.start:r.end])
            new_fh.seek(r.start)
            new_bytes = new_fh.read(r.length)
            hunk = Hunk(expect=list(old_bytes), replace=new_bytes, offset=r.start,
                        comment="bytes %d..%d" % (r.start, r.end))

            anchor = choose_anchor(data, ranges, idx)
            if anchor is not None:
                astart, hstart, needle = anchor
                anchor_index = len(anchors)
                anchors.append(Anchor(
                    name="anchor_%d" % anchor_index,
                    pattern=list(needle),
                    file_offset=astart,
                    rva=_safe_rva(pe, astart),
                    section=_safe_section(pe, astart),
                    unique=True,
                    comment="%d bytes of literal context at file offset 0x%X"
                            % (len(needle), astart),
                ))
                hunk.anchor = anchor_index
                hunk.delta = r.start - astart
                stats["anchored"] += 1
            else:
                stats["warnings"].append(
                    "hunk at 0x%X: no unique literal anchor found within %d bytes; "
                    "it will be located by section/RVA + file offset only"
                    % (r.start, MAX_ANCHOR_LEN))

            if pe is not None:
                rva = pe.offset_to_rva(r.start)
                sec = pe.section_for_rva(rva) if rva is not None else None
                if sec is not None:
                    hunk.section = sec.name
                    hunk.rva = rva
                    stats["section_rva"] += 1
            if pe is None:
                stats["offset_only"] += 1
            hunks.append(hunk)

        sha = sha256_file(old_path)
        target = pe.identity(sha) if pe is not None else {
            "filename": os.path.basename(old_path),
            "size": os.path.getsize(old_path),
            "sha256": sha,
        }
        target["filename"] = os.path.basename(old_path)

        bundle = Bundle(
            id=bundle_id,
            name=name,
            target=target,
            hunks=hunks,
            anchors=anchors,
            description=description,
            notes=notes,
            version=version,
            author=author,
            created_utc=created_utc or
            datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            tool={"name": TOOL_NAME, "version": __version__},
            policy=Policy(requires_rights_attestation=True, forbidden_categories=[]),
        )
        return bundle, stats
    finally:
        new_fh.close()
        if pe is not None:
            pe.close()


def exclude_checksum(ranges: List[Range], checksum_off: int) -> Tuple[List[Range], int]:
    """Remove (or split around) any range covering the 4-byte PE checksum field."""
    lo, hi = checksum_off, checksum_off + 4
    out: List[Range] = []
    dropped = 0
    for r in ranges:
        if r.end <= lo or r.start >= hi:
            out.append(r)
            continue
        dropped += 1
        if r.start < lo:
            out.append(Range(r.start, lo))
        if r.end > hi:
            out.append(Range(hi, r.end))
    return out, dropped


def _safe_rva(pe: Optional[PE], offset: int) -> Optional[int]:
    if pe is None:
        return None
    try:
        return pe.offset_to_rva(offset)
    except Exception:
        return None


def _safe_section(pe: Optional[PE], offset: int) -> Optional[str]:
    if pe is None:
        return None
    for sec in pe.sections:
        if sec.raw_ptr <= offset < sec.raw_end:
            return sec.name
    return None
