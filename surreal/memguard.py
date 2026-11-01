"""Memory budget enforcement for 4 GB machines.

The design rule is "never materialise a whole executable". This module exists
for the handful of paths where that is *unavoidable* (diffing non-PE files with
``--force``, or reading a target into RAM for a fallback), so they can refuse
instead of swapping the machine to death.

``--max-mem MB`` sets the ceiling (default 256 MB). It is checked *before* the
allocation, using file size + current usage, so a refusal costs nothing.
"""

from __future__ import annotations

import os
from typing import Optional

MB = 1024 * 1024


class MemoryLimitError(Exception):
    def __init__(self, want_mb: float, limit_mb: float, what: str):
        super().__init__(
            "refusing to allocate ~%.0f MB for %s (limit %.0f MB, --max-mem)\n"
            "  → this machine has little RAM to spare; raise --max-mem only if "
            "you really have it" % (want_mb, what, limit_mb))
        self.want_mb = want_mb
        self.limit_mb = limit_mb


def peak_rss_mb() -> float:
    """Best-effort peak resident set size of this process, in MB."""
    try:
        import resource  # POSIX

        usage = getattr(resource, "RUSAGE_SELF", None)
        peak = resource.getrusage(usage).ru_maxrss
        # Linux: KiB, macOS: bytes
        import sys

        return peak / (1024.0 * 1024.0) if sys.platform == "darwin" else peak / 1024.0
    except Exception:
        pass
    if os.name == "nt":  # pragma: no cover - Windows only
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()  # type: ignore[attr-defined]
            psapi = ctypes.windll.psapi  # type: ignore[attr-defined]
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters),
                                          counters.cb):
                return counters.PeakWorkingSetSize / float(MB)
        except Exception:
            pass
    return 0.0


class MemoryBudget:
    """A pre-flight check for allocations that scale with file size."""

    def __init__(self, limit_mb: float = 256.0):
        self.limit_mb = float(limit_mb)

    def note(self) -> str:
        return "max-mem %d MB (current peak %.0f MB)" % (
            round(self.limit_mb), peak_rss_mb())

    def reserve(self, nbytes: int, what: str) -> None:
        """Raise :class:`MemoryLimitError` if ``nbytes`` would blow the budget."""
        if nbytes <= 0:
            return
        want_mb = nbytes / float(MB)
        headroom = self.limit_mb - peak_rss_mb()
        if want_mb > headroom:
            raise MemoryLimitError(want_mb, self.limit_mb, what)

    def read_file(self, path: str, what: str = "file") -> bytes:
        size = os.path.getsize(path)
        self.reserve(size, "%s (%s)" % (what, os.path.basename(path)))
        with open(path, "rb") as fh:
            return fh.read()

    def enough_for(self, nbytes: int) -> bool:
        try:
            self.reserve(nbytes, "probe")
            return True
        except MemoryLimitError:
            return False


DEFAULT_BUDGET = MemoryBudget()


def set_default(limit_mb: Optional[float]) -> MemoryBudget:
    """Install the process-wide budget (used by the CLI's ``--max-mem``)."""
    global DEFAULT_BUDGET
    if limit_mb is not None:
        DEFAULT_BUDGET = MemoryBudget(limit_mb)
    return DEFAULT_BUDGET
