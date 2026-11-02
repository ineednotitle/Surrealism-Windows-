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
    ranges, tail = compare_files_ex(old_path, new_path, merge_gap, max_ranges,
                                    allow_size_change=False)
    return ranges


def compare_files_ex(old_path: str, new_path: str, merge_gap: int = DEFAULT_MERGE_GAP,
                     max_ranges: int = 10000, allow_size_change: bool = True):
    """Compare two files, allowing a size change at EOF.

    Returns ``(ranges, tail)`` where ``tail`` is ``None`` or
    ``("append", bytes)`` / ``("truncate", bytes)``. Only a difference at the
    very end of the file is represented — a size change anywhere else would
    move every following byte, which is a different patch class entirely.
    """
    old_size = os.path.getsize(old_path)
    new_size = os.path.getsize(new_path)
    if old_size != new_size and not allow_size_change:
        raise DiffError(
            "files differ in size (%d vs %d bytes): size-changing patches are only "
            "supported for the overlay (see PLAN.md §3.1 step 5)"
            % (old_size, new_size))
    common = min(old_size, new_size)

    raw: List[Range] = []
    with open(old_path, "rb") as fa, open(new_path, "rb") as fb:
        base = 0
        while base < common:
            a = fa.read(min(CHUNK, common - base))
            b = fb.read(min(CHUNK, common - base))
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

    # tail: a size difference is only representable when it sits at EOF (the
    # overlay). Anything else would shift every following byte.
    tail = None
    if new_size > old_size:
        with open(new_path, "rb") as fb:
            fb.seek(old_size)
            tail = ("append", fb.read(new_size - old_size))
    elif old_size > new_size:
        with open(old_path, "rb") as fa:
            fa.seek(new_size)
            tail = ("truncate", fa.read(old_size - new_size))
    return merged, tail


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
                 created_utc: Optional[str] = None,
                 budget=None) -> Tuple[Bundle, dict]:
    """Create an in-memory :class:`Bundle`. Returns ``(bundle, stats)``."""
    image_hunk = None
    if os.path.getsize(old_path) != os.path.getsize(new_path):
        image_hunk = _classify_image_change(old_path, new_path, budget=budget)
        if image_hunk is not None:
            return _bundle_with_hunk(old_path, image_hunk, bundle_id, name, author,
                                     description, notes, version, created_utc)

    ranges, tail = compare_files_ex(old_path, new_path, merge_gap=merge_gap)
    if not ranges and tail is None:
        raise DiffError("the two files are byte-identical — nothing to record")

    stats = {"ranges": len(ranges), "anchored": 0, "section_rva": 0,
             "offset_only": 0, "warnings": [], "size_delta": 0}

    try:
        pe = PE.open(old_path)
    except (PEError, OSError) as exc:
        if require_pe:
            raise DiffError("target is not a readable PE image: %s" % exc) from exc
        pe = None

    if tail is not None:
        stats["size_delta"] = len(tail[1]) * (1 if tail[0] == "append" else -1)
        if pe is not None:
            _validate_overlay_change(pe, old_path, new_path, tail, stats)
        else:
            stats["warnings"].append(
                "size change on a non-PE file: recorded as a raw append/truncate "
                "with no PE-level checks (--force)")

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
            if not ranges and tail is None:
                raise DiffError("the only differences are in the PE checksum field "
                                "— these builds are identical for patching purposes")
            _warn_about_relocations(pe, ranges, stats)
            header_hits = [r for r in ranges if r.start < pe.size_of_headers]
            if header_hits:
                stats["warnings"].append(
                    "%d hunk(s) fall inside the PE headers (< SizeOfHeaders 0x%X); "
                    "headers are structural — double-check those"
                    % (len(header_hits), pe.size_of_headers))

        if pe is not None:
            data = pe.data
        else:
            from .memguard import DEFAULT_BUDGET

            budget = budget or DEFAULT_BUDGET
            data = budget.read_file(old_path, "target (non-PE, --force)")
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

        if tail is not None:
            kind, blob = tail
            if kind == "append":
                hunks.append(Hunk(op="append", expect=[], replace=blob,
                                  comment="append %d bytes after the last section "
                                          "(overlay)" % len(blob)))
            else:
                hunks.append(Hunk(op="truncate", expect=list(blob), replace=b"",
                                  comment="truncate %d trailing overlay bytes"
                                          % len(blob)))

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


def _warn_about_relocations(pe: PE, ranges: List[Range], stats: dict) -> None:
    """Tell the author when a hunk lands on a field the loader rebases."""
    from .reloc import RELOC_TYPE_NAMES, parse_relocs

    try:
        table = parse_relocs(pe)
    except Exception:  # noqa: BLE001 - hostile .reloc data must not kill a diff
        stats["warnings"].append("could not parse .reloc; ASLR analysis skipped")
        return
    if not table:
        return
    found = {}
    for r in ranges:
        rva = pe.offset_to_rva(r.start)
        if rva is None:
            continue
        for stride in (8, 4):
            pos = rva - (rva % stride)
            while pos < rva + r.length:
                typ = table.covers_rva(pos)
                if typ and typ != 0:
                    found.setdefault((r.start, pos), RELOC_TYPE_NAMES.get(typ, str(typ)))
                pos += stride
    hits = [(start, pos, kind) for (start, pos), kind in sorted(found.items())]
    if hits:
        where = ", ".join("0x%X (%s)" % (off, kind) for _h, off, kind in hits[:6])
        stats["warnings"].append(
            "%d hunk(s) overwrite relocated (absolute-address) fields: %s — apply "
            "will refuse these unless you have verified rebasing"
            % (len(hits), where))


def _classify_image_change(old_path: str, new_path: str, budget=None) -> Optional[Hunk]:
    """Recognise ``extend-section`` / ``add-section`` and prove it by replaying it.

    The generator never trusts its own structural guess: it builds the candidate
    hunk, applies it to a temporary copy of the *old* file with the real applier,
    and only reports success when the result is byte-identical to the new file.
    """
    try:
        old_pe = PE.open(old_path)
    except (PEError, OSError):
        return None
    try:
        try:
            new_pe = PE.open(new_path)
        except (PEError, OSError):
            return None
        try:
            candidate = _guess_image_hunk(old_pe, new_pe, new_path)
        finally:
            new_pe.close()
    finally:
        old_pe.close()
    if candidate is None:
        return None
    if not _replay_matches(old_path, new_path, candidate):
        return None
    return candidate


def _sections_equal(a, b) -> bool:
    return (a.name == b.name and a.virtual_address == b.virtual_address
            and a.raw_ptr == b.raw_ptr and a.raw_size == b.raw_size
            and a.virtual_size == b.virtual_size
            and a.characteristics == b.characteristics)


def _guess_image_hunk(old_pe: PE, new_pe: PE, new_path: str) -> Optional[Hunk]:
    with open(new_path, "rb") as fh:
        new_size = os.path.getsize(new_path)
        if new_size <= old_pe.size:
            return None
        if new_pe.overlay_size or old_pe.overlay_size:
            return None  # overlays complicate the layout; use append/truncate

        # --- extend-section: identical sections, last one grew in place ----- #
        if len(new_pe.sections) == len(old_pe.sections):
            pairs = list(zip(old_pe.sections, new_pe.sections))
            if not all(_sections_equal(a, b) for a, b in pairs[:-1]):
                return None
            old_last, new_last = pairs[-1]
            if (old_last.name != new_last.name
                    or old_last.raw_ptr != new_last.raw_ptr
                    or old_last.characteristics != new_last.characteristics
                    or new_last.raw_size <= old_last.raw_size
                    or new_last.virtual_size < old_last.virtual_size):
                return None
            if old_last.raw_end != old_pe.size or new_last.raw_end != new_size:
                return None
            if old_last.raw_size != (old_pe.size - old_last.raw_ptr):
                return None
            payload_len = new_size - old_pe.size
            fh.seek(old_pe.size)
            payload = fh.read(payload_len)
            if not payload:
                return None
            return Hunk(op="extend-section", section=old_last.name, expect=[],
                        replace=payload, raw_size_before=old_last.raw_size,
                        virtual_size_after=new_last.virtual_size,
                        comment="grow %s from 0x%X to 0x%X raw bytes"
                                % (old_last.name, old_last.raw_size,
                                   new_last.raw_size))

        # --- add-section: one extra section, everything else identical ------ #
        if len(new_pe.sections) == len(old_pe.sections) + 1:
            if not all(_sections_equal(a, b) for a, b in
                       zip(old_pe.sections, new_pe.sections)):
                return None
            extra = new_pe.sections[-1]
            expected_ptr = align_up(old_pe.size, old_pe.file_alignment or 0x200)
            if extra.raw_ptr != expected_ptr or extra.raw_end != new_size:
                return None
            if old_pe.last_section_end != old_pe.size:
                return None
            fh.seek(extra.raw_ptr)
            payload = fh.read(new_size - extra.raw_ptr)
            if not payload:
                return None
            return Hunk(op="add-section", name=extra.name, section=extra.name,
                        expect=[], replace=payload,
                        characteristics=extra.characteristics,
                        rva=extra.virtual_address,
                        virtual_size_after=extra.virtual_size,
                        comment="add section %s at RVA 0x%X (0x%X raw bytes)"
                                % (extra.name, extra.virtual_address, extra.raw_size))
    return None


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    rem = value % alignment
    return value if rem == 0 else value + (alignment - rem)


def _replay_matches(old_path: str, new_path: str, hunk: Hunk) -> bool:
    """Apply the candidate hunk to a copy of ``old`` and compare with ``new``."""
    import shutil
    import tempfile

    from .patcher import PatchError, apply_bundle
    from .patchfile import Bundle

    workdir = tempfile.mkdtemp(prefix="surreal-replay-")
    copy_path = os.path.join(workdir, os.path.basename(old_path))
    try:
        shutil.copyfile(old_path, copy_path)
        sha = sha256_file(copy_path)
        bundle = Bundle(
            id="org.surreal.replay", name="replay",
            target={"filename": os.path.basename(old_path),
                    "size": os.path.getsize(copy_path), "sha256": sha},
            hunks=[hunk],
        )
        try:
            apply_bundle(bundle, copy_path, no_backup=True, keep_backups=0,
                         no_checksum=False)
        except PatchError:
            return False
        return _files_equal_ignoring_checksum(copy_path, new_path)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _files_equal_ignoring_checksum(a_path: str, b_path: str) -> bool:
    if os.path.getsize(a_path) != os.path.getsize(b_path):
        return False
    try:
        with PE.open(a_path) as pe:
            skip = pe._checksum_offset
    except (PEError, OSError):
        skip = None
    with open(a_path, "rb") as fa, open(b_path, "rb") as fb:
        if skip is None:
            while True:
                a = fa.read(CHUNK)
                b = fb.read(CHUNK)
                if not a and not b:
                    return True
                if a != b:
                    return False
        fa.seek(0)
        fb.seek(0)
        if fa.read(skip) != fb.read(skip):
            return False
        fa.seek(skip + 4)
        fb.seek(skip + 4)
        while True:
            a = fa.read(CHUNK)
            b = fb.read(CHUNK)
            if not a and not b:
                return True
            if a != b:
                return False


def _bundle_with_hunk(old_path: str, hunk: Hunk, bundle_id: str, name: str,
                      author: str, description: str, notes: str, version: str,
                      created_utc: Optional[str]) -> Tuple[Bundle, dict]:
    """Build a bundle that contains exactly one layout-changing hunk."""
    stats = {"ranges": 0, "anchored": 0, "section_rva": 0, "offset_only": 0,
             "warnings": [], "size_delta": 0}
    pe = PE.open(old_path)
    try:
        sha = sha256_file(old_path)
        target = pe.identity(sha)
        target["filename"] = os.path.basename(old_path)
        stats["warnings"].append(
            "layout change: %s (%d payload bytes) — verified by replaying it "
            "against the target" % (hunk.op, len(hunk.replace)))
    finally:
        pe.close()
    bundle = Bundle(
        id=bundle_id, name=name, target=target, hunks=[hunk], anchors=[],
        description=description, notes=notes, version=version, author=author,
        created_utc=created_utc or datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        tool={"name": TOOL_NAME, "version": __version__},
        policy=Policy(forbidden_categories=[]),
    )
    return bundle, stats


def _validate_overlay_change(pe: PE, old_path: str, new_path: str,
                             tail: Tuple[str, bytes], stats: dict) -> None:
    """Refuse size changes that touch mapped image data.

    Growing into or out of a section would change ``SizeOfImage``, the section
    table and every following RVA. Only the overlay (bytes after the last
    section's raw data) can change size without rewriting the image.
    """
    kind, blob = tail
    new_size = os.path.getsize(new_path)
    new_start = pe.size if kind == "append" else new_size
    if new_start < pe.last_section_end:
        raise DiffError(
            "the size change starts at 0x%X, inside the last section (which ends at "
            "0x%X). Resizing a section needs new headers and relocated RVAs — "
            "out of scope for this format version." % (new_start, pe.last_section_end))
    try:
        new_pe = PE.open(new_path)
    except (PEError, OSError) as exc:
        raise DiffError("the modified build is not a readable PE image: %s" % exc) from exc
    try:
        if len(new_pe.sections) != len(pe.sections):
            raise DiffError(
                "the modified build has %d sections, the original has %d — adding or "
                "removing sections is not supported" % (len(new_pe.sections),
                                                       len(pe.sections)))
        for old_sec, new_sec in zip(pe.sections, new_pe.sections):
            signature = (old_sec.name, old_sec.virtual_address, old_sec.raw_ptr,
                         old_sec.raw_size, old_sec.virtual_size)
            if signature != (new_sec.name, new_sec.virtual_address,
                             new_sec.raw_ptr, new_sec.raw_size,
                             new_sec.virtual_size):
                raise DiffError(
                    "section %s was resized or moved between the builds; only "
                    "overlay size changes are supported" % old_sec.name)
        if new_pe.last_section_end != pe.last_section_end:
            raise DiffError("the section layout moved between the builds")
        stats["warnings"].append(
            "size change confined to the overlay: %s %d bytes after 0x%X"
            % (kind, len(blob), pe.last_section_end))
    finally:
        new_pe.close()


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
