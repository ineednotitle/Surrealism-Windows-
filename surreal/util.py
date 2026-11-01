"""Small utilities: hex parse/format, hashing, sizes, atomic file IO."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import Iterable, List, Optional, Sequence

CHUNK = 1024 * 1024  # 1 MiB — the one and only IO buffer size


# --------------------------------------------------------------------------- #
# hex / byte patterns
# --------------------------------------------------------------------------- #
def parse_hex_tokens(text: str) -> List[Optional[int]]:
    """Parse a hex byte pattern into a list of ints, with ``None`` wildcards.

    Accepted forms::

        "48 8B ?? E8"      spaced, ?? / ? wildcards
        "488B??E8"         packed, same rules
        "48,8b,*,e8"       comma separated, * wildcard
        "MZ"               ascii, only when prefixed with ascii:

    Raises ``ValueError`` on anything malformed.
    """
    if text is None:
        raise ValueError("empty byte pattern")
    raw = text.strip()
    if not raw:
        raise ValueError("empty byte pattern")
    if raw.lower().startswith("ascii:"):
        return list(raw[6:].encode("latin-1"))

    raw = raw.replace(",", " ").replace("\t", " ").replace("\n", " ")
    tokens = [t for t in raw.split(" ") if t]
    if len(tokens) == 1 and len(tokens[0]) > 2 and not _is_wild(tokens[0]):
        tok = tokens[0]
        if len(tok) % 2:
            raise ValueError("packed hex must have an even number of digits: %r" % text)
        tokens = [tok[i : i + 2] for i in range(0, len(tok), 2)]

    out: List[Optional[int]] = []
    for tok in tokens:
        if _is_wild(tok):
            out.append(None)
            continue
        core = tok[2:] if tok.lower().startswith("0x") else tok
        if len(core) == 1:
            core = "0" + core
        if len(core) != 2 or any(c not in "0123456789abcdefABCDEF" for c in core):
            raise ValueError("not a hex byte: %r" % tok)
        out.append(int(core, 16))
    return out


def _is_wild(tok: str) -> bool:
    t = tok.strip()
    if t in ("*", "**"):
        return True
    return len(t) in (1, 2) and set(t) <= {"?"}


def parse_hex_bytes(text: str) -> bytes:
    """Fixed bytes only (used for ``replace`` payloads)."""
    vals = parse_hex_tokens(text)
    if any(v is None for v in vals):
        raise ValueError("wildcards are not allowed here: %r" % text)
    return bytes(v for v in vals)  # type: ignore[arg-type]


def format_hex(data: bytes, sep: str = " ") -> str:
    return sep.join("%02X" % b for b in data)


def longest_literal_run(pattern: Sequence[Optional[int]]) -> tuple:
    """Return ``(start, needle)`` for the longest run of fixed bytes."""
    best_start, best_len, cur_start, cur_len = 0, 0, 0, 0
    for i, tok in enumerate(pattern):
        if tok is None:
            cur_len = 0
            cur_start = i + 1
        else:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
    needle = bytes(v for v in pattern[best_start : best_start + best_len] if v is not None)
    return best_start, needle


# --------------------------------------------------------------------------- #
# hashing / sizes
# --------------------------------------------------------------------------- #
def sha256_file(path: str, limit: Optional[int] = None) -> str:
    h = hashlib.sha256()
    remaining = limit
    with open(path, "rb") as fh:
        while True:
            want = CHUNK if remaining is None else min(CHUNK, remaining)
            if want <= 0:
                break
            chunk = fh.read(want)
            if not chunk:
                break
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return h.hexdigest()


def sha256_bytes(data) -> str:
    return hashlib.sha256(data).hexdigest()


def human_size(n: int) -> str:
    step = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if step < 1024 or unit == "GiB":
            return ("%d %s" % (step, unit)) if unit == "B" else ("%.1f %s" % (step, unit))
        step /= 1024.0
    return "%d B" % n


# --------------------------------------------------------------------------- #
# fs helpers
# --------------------------------------------------------------------------- #
def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def write_json_atomic(path: str, obj) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(directory)
    fd, tmp = tempfile.mkstemp(prefix=".surreal-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=2, sort_keys=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: str, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join("%02X" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08X  %-*s  |%s|" % (base + off, width * 3 - 1, hexpart, text))
    return "\n".join(lines)


def iter_chunks(fh, size: int, chunk: int = CHUNK) -> Iterable[tuple]:
    """Yield ``(offset, bytes)`` for a file object."""
    off = 0
    while off < size:
        data = fh.read(min(chunk, size - off))
        if not data:
            break
        yield off, data
        off += len(data)
