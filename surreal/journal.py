"""Per-directory journal + backups: ``<dir>/.surreal/journal.json``.

Kept next to the patched binary on purpose: portable, obvious, and easy to
delete. Backups are full copies (a PE is not safely editable in place without
one) but only one per apply, and ``prune`` keeps the newest N.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import time
from typing import Any, Dict, List, Optional

from .util import ensure_dir, read_json, sha256_file, write_json_atomic

JOURNAL_DIRNAME = ".surreal"


def journal_dir(target_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(target_path)), JOURNAL_DIRNAME)


def journal_path(target_path: str) -> str:
    return os.path.join(journal_dir(target_path), "journal.json")


class Journal:
    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self.dir = journal_dir(self.target_path)
        self.path = journal_path(self.target_path)
        data = read_json(self.path, default=None)
        if not isinstance(data, dict):
            data = {"version": 1, "target": os.path.basename(self.target_path),
                    "entries": []}
        data.setdefault("entries", [])
        self.data: Dict[str, Any] = data

    # -- persistence -------------------------------------------------------- #
    def save(self) -> None:
        ensure_dir(self.dir)
        write_json_atomic(self.path, self.data)

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return self.data["entries"]

    # -- records ------------------------------------------------------------ #
    def new_backup_path(self, label: str) -> str:
        """Unique, never-reused backup name.

        The random suffix matters: pruning deletes files, and a recycled name
        would make an *old* journal entry point at a *new* backup.
        """
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)[:40]
        bdir = ensure_dir(os.path.join(self.dir, "backups"))
        nonce = hashlib.sha1(os.urandom(16)).hexdigest()[:8]
        return os.path.join(bdir, "%s-%s-%s.bak" % (stamp, safe, nonce))

    def backup(self, label: str) -> str:
        """Copy the current target to the backup store; return the backup path."""
        dest = self.new_backup_path(label)
        shutil.copy2(self.target_path, dest)
        if sha256_file(dest) != sha256_file(self.target_path):
            raise IOError("backup verification failed: %s" % dest)
        return dest

    def record(self, action: str, **fields) -> Dict[str, Any]:
        entry = {
            "action": action,
            "target": self.target_path,
            "time_utc": datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }
        entry.update(fields)
        self.entries.append(entry)
        self.save()
        return entry

    def last(self, actions=("apply", "apply-collection", "apply-vault",
                            "revert")) -> Optional[Dict[str, Any]]:
        """Newest entry for *this* file.

        One journal covers a whole directory, so a vault (several binaries side
        by side) writes one entry per file into the same file: entries that name
        a different target are skipped.
        """
        for entry in reversed(self.entries):
            if entry.get("action") not in actions:
                continue
            recorded = entry.get("target")
            if recorded and os.path.abspath(recorded) != self.target_path:
                continue
            return entry
        return None

    def prune(self, keep: int = 3) -> List[str]:
        """Delete all but the newest ``keep`` backups referenced by the journal."""
        removed: List[str] = []
        backups = [e.get("backup") for e in self.entries if e.get("backup")]
        seen = []
        for path in reversed(backups):
            if path and path not in seen:
                seen.append(path)
        for stale in seen[keep:]:
            try:
                if stale and os.path.isfile(stale):
                    os.remove(stale)
                    removed.append(stale)
            except OSError:
                pass
        return removed


def fsync_dir(path: str) -> None:
    """Best-effort directory fsync (no-op on Windows)."""
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
