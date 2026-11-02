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
            "refusing to allocate ~%.0f MB for %s (budget %.0f MB, --max-mem)\n"
            "  → this machine has little RAM to spare; raise --max-mem only if "
            "you really have it" % (want_mb, what, limit_mb))
        self.want_mb = want_mb
        self.limit_mb = limit_mb


def peak_rss_mb() -> float:
    """Best-effort peak resident set size of this process, in MB.

    Returns ``0.0`` when the platform does not offer a measurement, so callers
    must treat 0 as "unknown" rather than "used no memory".
    """
    try:
        import resource  # POSIX only

        usage = getattr(resource, "RUSAGE_SELF", None)
        peak = resource.getrusage(usage).ru_maxrss
        import sys

        # Linux reports KiB, macOS reports bytes
        return peak / (1024.0 * 1024.0) if sys.platform == "darwin" else peak / 1024.0
    except Exception:
        pass
    if os.name == "nt":  # pragma: no cover - Windows only
        return _windows_peak_rss_mb()
    return 0.0


def _windows_peak_rss_mb() -> float:  # pragma: no cover - Windows only
    """Peak working set via psapi/kernel32 (no dependencies, no ctypes on POSIX)."""
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
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.GetCurrentProcess()
        candidates = []
        try:
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            candidates.append(psapi.GetProcessMemoryInfo)
        except OSError:
            pass
        if hasattr(kernel32, "K32GetProcessMemoryInfo"):
            candidates.append(kernel32.K32GetProcessMemoryInfo)
        for function in candidates:
            try:
                function.argtypes = [ctypes.c_void_p,
                                     ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                                     wintypes.DWORD]
                function.restype = wintypes.BOOL
                if function(ctypes.c_void_p(handle), ctypes.byref(counters),
                            counters.cb):
                    peak = max(counters.PeakWorkingSetSize,
                               counters.WorkingSetSize)
                    if peak:
                        return peak / float(MB)
            except Exception:
                continue
    except Exception:
        pass
    return 0.0


SMALL_ALLOW_MB = 32.0


class MemoryBudget:
    """A pre-flight check for allocations that scale with file size.

    Two thresholds, because "peak RSS" is a process-wide number that can already
    sit above the budget for unrelated reasons (an mmap, an earlier big read):

    * anything at or below ``small_allow_mb`` is always allowed — refusing a
      200 KB allocation helps nobody;
    * a big allocation must fit in ``limit - peak``.
    """

    def __init__(self, limit_mb: float = 256.0, small_allow_mb: float = SMALL_ALLOW_MB):
        self.limit_mb = float(limit_mb)
        self.small_allow_mb = float(small_allow_mb)

    def note(self) -> str:
        return "max-mem %d MB (peak %.0f MB, small reads ≤ %d MB free)" % (
            round(self.limit_mb), peak_rss_mb(), round(self.small_allow_mb))

    def reserve(self, nbytes: int, what: str) -> None:
        """Raise :class:`MemoryLimitError` if ``nbytes`` would blow the budget."""
        if nbytes <= 0:
            return
        want_mb = nbytes / float(MB)
        if want_mb <= self.small_allow_mb:
            return
        if want_mb > self.limit_mb:
            raise MemoryLimitError(want_mb, self.limit_mb, what)
        headroom = self.limit_mb - peak_rss_mb()
        if want_mb > headroom:
            raise MemoryLimitError(want_mb, max(headroom, 0.0), what)

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


def restore(budget: MemoryBudget) -> None:
    """Put a previous budget back (so an in-process CLI run cannot leak it)."""
    global DEFAULT_BUDGET
    DEFAULT_BUDGET = budget
