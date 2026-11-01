"""A small, crash-tolerant lock so two applies cannot race on one target.

``<dir>/.surreal/lock`` is created with ``O_CREAT|O_EXCL`` and holds JSON:
pid, host, user, time, target, bundle. A lock is considered **stale** when its
PID is not alive on this host, or when it is older than ``STALE_AFTER`` seconds
(a crashed process, a reboot, a USB stick moved to another machine).

Honest limits: this is a cooperative lock between ``surreal`` processes. It is
not a kernel lock, it will not stop another program from writing the file, and
a PID can be recycled. ``--force-unlock`` exists for the day it is wrong.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
import time
from typing import Any, Dict, Optional

from .journal import journal_dir
from .util import ensure_dir

STALE_AFTER = 15 * 60  # seconds


class LockError(Exception):
    pass


def lock_path(target_path: str) -> str:
    return os.path.join(journal_dir(target_path), "lock")


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        # No os.kill(pid, 0) on Windows; use a handle probe via ctypes.
        try:
            import ctypes

            k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
            if not handle:
                return False
            k32.CloseHandle(handle)
            return True
        except Exception:  # pragma: no cover - non-Windows or restricted
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except OSError:
        return True
    return True


def _hostname() -> str:
    return os.environ.get("COMPUTERNAME") or socket.gethostname()


class TargetLock:
    """Context manager: ``with TargetLock(target) as lk: ...``."""

    def __init__(self, target_path: str, action: str = "apply",
                 bundle_id: str = "", force: bool = False):
        self.target_path = os.path.abspath(target_path)
        self.path = lock_path(self.target_path)
        self.action = action
        self.bundle_id = bundle_id
        self.force = force
        self.acquired = False

    # -- helpers ------------------------------------------------------------ #
    def read(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else None
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def is_stale(self, data: Optional[Dict[str, Any]]) -> bool:
        if not data:
            return True
        if data.get("host") != _hostname():
            return True  # another machine's lock file, shared folder, etc.
        age = time.time() - float(data.get("time_epoch") or 0)
        if age > STALE_AFTER:
            return True
        return not _pid_alive(int(data.get("pid") or 0))

    # -- lifecycle ---------------------------------------------------------- #
    def acquire(self) -> "TargetLock":
        ensure_dir(os.path.dirname(self.path))
        payload = {
            "pid": os.getpid(),
            "host": _hostname(),
            "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
            "time_epoch": time.time(),
            "time_utc": datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "action": self.action,
            "bundle": self.bundle_id,
            "target": self.target_path,
        }
        cleared = False
        for attempt in (0, 1):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                holder = self.read()
                if attempt == 1 and not cleared:
                    raise LockError(
                        "another surreal process is working on %s\n"
                        "  lock: %s\n  held by: pid %s on %s since %s (%s)\n"
                        "  → wait for it to finish, or re-run with --force-unlock"
                        % (os.path.basename(self.target_path), self.path,
                           (holder or {}).get("pid", "?"),
                           (holder or {}).get("host", "?"),
                           (holder or {}).get("time_utc", "?"),
                           (holder or {}).get("action", "?")))
                if self.force or self.is_stale(holder):
                    try:
                        os.remove(self.path)
                        cleared = True
                    except OSError:
                        pass
                    continue
                raise LockError(
                    "another surreal process is working on %s (pid %s, %s, %s)\n"
                    "  → wait for it to finish, or re-run with --force-unlock"
                    % (os.path.basename(self.target_path),
                       (holder or {}).get("pid", "?"),
                       (holder or {}).get("host", "?"),
                       (holder or {}).get("action", "?")))
            else:
                try:
                    os.write(fd, json.dumps(payload, indent=2).encode("utf-8"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self.acquired = True
                return self
        raise LockError("could not acquire %s" % self.path)  # pragma: no cover

    def release(self) -> None:
        if not self.acquired:
            return
        # only remove our own lock
        holder = self.read()
        if holder and holder.get("pid") != os.getpid():
            return
        try:
            os.remove(self.path)
        except OSError:
            pass
        self.acquired = False

    def __enter__(self) -> "TargetLock":
        return self.acquire()

    def __exit__(self, *exc) -> None:
        self.release()
