"""Byte-pattern and string scanning over an mmap'd (or in-memory) image.

Strategy: turn the pattern into its longest run of fixed bytes, use the
C-speed ``bytes.find`` loop on that needle, then verify the (short) wildcard
remainder. Memory use is constant; time is dominated by ``memmem``.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .util import longest_literal_run, parse_hex_tokens


class ScanError(Exception):
    pass


def find_pattern(data, pattern: Sequence[Optional[int]], start: int = 0,
                 end: Optional[int] = None, limit: int = 1000) -> List[int]:
    """Return absolute offsets of every match of ``pattern`` in ``data``."""
    size = len(data)
    if end is None or end > size:
        end = size
    plen = len(pattern)
    if plen == 0:
        raise ScanError("empty pattern")
    if start < 0:
        start = 0

    needle_start, needle = longest_literal_run(pattern)
    if not needle:
        raise ScanError("pattern contains no fixed bytes to anchor the search")

    hits: List[int] = []
    pos = start
    while len(hits) < limit:
        probe = pos + needle_start
        if probe > end:
            break
        idx = data.find(needle, probe, end)
        if idx < 0:
            break
        cand = idx - needle_start
        if cand >= start and cand + plen <= end and _verify(data, cand, pattern):
            hits.append(cand)
        pos = cand + 1
    return hits


def _verify(data, offset: int, pattern: Sequence[Optional[int]]) -> bool:
    for i, tok in enumerate(pattern):
        if tok is not None and data[offset + i] != tok:
            return False
    return True


def find_bytes(data, needle: bytes, start: int = 0, end: Optional[int] = None,
               limit: int = 1000) -> List[int]:
    if not needle:
        raise ScanError("empty needle")
    size = len(data)
    if end is None or end > size:
        end = size
    hits: List[int] = []
    pos = start
    while len(hits) < limit:
        idx = data.find(needle, pos, end)
        if idx < 0:
            break
        hits.append(idx)
        pos = idx + 1
    return hits


def find_string(data, text: str, utf16: bool = False, start: int = 0,
                end: Optional[int] = None, limit: int = 1000,
                min_len: int = 1) -> List[int]:
    """ASCII (latin-1) or UTF-16LE search. ``min_len`` only affects utf16 scan."""
    if utf16:
        # Little-endian UTF-16 without BOM: "T\0e\0x\0t\0".
        needle = text.encode("utf-16-le")
        if len(needle) < 2 * min_len:
            raise ScanError("search string shorter than min_len")
    else:
        needle = text.encode("latin-1", "replace")
    return find_bytes(data, needle, start=start, end=end, limit=limit)


def find_both_strings(data, text: str, start: int = 0, end: Optional[int] = None,
                      limit: int = 1000) -> List[Tuple[int, str]]:
    """ASCII + UTF-16LE occurrences, tagged with encoding."""
    out: List[Tuple[int, str]] = []
    for off in find_string(data, text, False, start, end, limit):
        out.append((off, "ascii"))
    if len(text) >= 4:  # UTF-16 needles shorter than 4 chars are noise
        for off in find_string(data, text, True, start, end, limit):
            out.append((off, "utf16le"))
    out.sort()
    return out


def context_bytes(data, offset: int, before: int = 16, after: int = 16,
                  match_len: int = 0) -> Tuple[bytes, bytes]:
    lo = max(0, offset - before)
    hi = min(len(data), offset + max(match_len, 0) + after)
    return bytes(data[lo:offset]), bytes(data[offset + match_len : hi])


def parse_pattern(text: str) -> List[Optional[int]]:
    try:
        return parse_hex_tokens(text)
    except ValueError as exc:
        raise ScanError(str(exc)) from exc


_PRINTABLE = None


def find_best_strings(data, limit: int = 20, min_len: int = 6) -> List[dict]:
    """'Notable strings' for ``inspect``: ASCII runs, deduped, first N.

    Lazy ``re.finditer`` over the buffer — no copies of the file are made.
    """
    global _PRINTABLE
    import re

    if _PRINTABLE is None:
        _PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    seen = set()
    out: List[dict] = []
    for m in _PRINTABLE.finditer(data):
        text = bytes(m.group(0)).decode("latin-1")
        key = text.strip()
        if not key or key in seen:
            continue
        if key.lower() in ("this program cannot be run in dos mode",):
            continue
        seen.add(key)
        out.append({"offset": int(m.start()), "text": text})
        if len(out) >= limit:
            break
    return out
