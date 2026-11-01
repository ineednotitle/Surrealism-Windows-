"""Patch collections: apply several bundles to one target as **one transaction**.

A Morphe-style workflow usually ends with "apply these four patches", not one.
A collection is a small manifest next to a directory of ``.morph`` files:

```json
{
  "format": "surreal.collection",
  "format_version": 1,
  "name": "BetterNotepad patch set",
  "patches": [
    { "bundle": "dark-theme.morph", "order": 10 },
    { "bundle": "no-nag.morph",     "order": 20, "required": true }
  ]
}
```

Semantics
---------
* Patches are selected by target identity (size + sha256), then ordered by
  ``order`` (ties broken by id) so the result is deterministic.
* **One backup, one journalled action, all-or-nothing.** If patch *n* fails, the
  original file is restored from the backup before anything is reported.
* Collections do not allow size-changing bundles: every patch must keep the file
  size, otherwise the RVAs the later patches were authored against would move.
* The first patch must match the target exactly. Later patches were authored
  against the pristine build, so their hash check is expected to drift; the
  per-hunk ``expect`` verification (the real safety net) still runs in full.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import patchfile
from .journal import Journal, fsync_dir
from .patchfile import Bundle, BundleError
from .patcher import PatchError, apply_bundle, build_plan
from .util import read_json, sha256_file

MANIFEST_NAMES = ("surreal-collection.json", "collection.json", "surreal-repo.json")
FORMAT = "surreal.collection"
FORMAT_VERSION = 1

ALLOWED_KEYS = {"format", "format_version", "name", "description", "author",
                "homepage", "license", "patches", "created_utc"}
ALLOWED_PATCH_KEYS = {"bundle", "order", "required", "description", "enabled"}


class CollectionError(Exception):
    pass


@dataclass
class Entry:
    bundle_file: str
    order: int = 100
    required: bool = False
    description: str = ""
    enabled: bool = True
    bundle: Optional[Bundle] = None
    path: Optional[str] = None


@dataclass
class Collection:
    name: str
    entries: List[Entry] = field(default_factory=list)
    description: str = ""
    author: str = ""
    homepage: str = ""
    license: str = ""
    base_dir: str = ""
    path: Optional[str] = None

    @property
    def sort_key(self):
        return (self.name.lower(), self.path or "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": FORMAT,
            "format_version": FORMAT_VERSION,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "homepage": self.homepage,
            "license": self.license,
            "patches": [
                {"bundle": e.bundle_file, "order": e.order,
                 "required": e.required, "description": e.description,
                 **({} if e.enabled else {"enabled": False})}
                for e in self.entries
            ],
        }

    def save(self, path: str) -> None:
        from .util import write_json_atomic

        write_json_atomic(path, self.to_dict())
        self.path = path


def find_manifest(path: str) -> str:
    """Accept a directory (known manifest names) or a manifest file."""
    if os.path.isdir(path):
        for name in MANIFEST_NAMES:
            candidate = os.path.join(path, name)
            if os.path.isfile(candidate):
                return candidate
        raise CollectionError(
            "no collection manifest in %s (looked for %s)"
            % (path, ", ".join(MANIFEST_NAMES)))
    if os.path.isfile(path):
        return path
    raise CollectionError("collection not found: %s" % path)


def load_collection(path: str, strict: bool = True) -> Collection:
    manifest = find_manifest(path)
    raw = read_json(manifest)
    if not isinstance(raw, dict):
        raise CollectionError("collection manifest must be a JSON object")
    if strict:
        unknown = set(raw) - ALLOWED_KEYS
        if unknown:
            raise CollectionError("unknown collection keys: %s"
                                  % ", ".join(sorted(unknown)))
    if (raw.get("format") or FORMAT) != FORMAT:
        raise CollectionError("not a %s file (format=%r)"
                              % (FORMAT, raw.get("format")))
    if int(raw.get("format_version") or FORMAT_VERSION) != FORMAT_VERSION:
        raise CollectionError("unsupported collection format_version %r"
                              % raw.get("format_version"))

    base = os.path.dirname(os.path.abspath(manifest))
    entries: List[Entry] = []
    for i, item in enumerate(raw.get("patches") or []):
        if not isinstance(item, dict):
            raise CollectionError("patch %d must be an object" % i)
        if strict and set(item) - ALLOWED_PATCH_KEYS:
            raise CollectionError("patch %d has unknown keys: %s"
                                  % (i, ", ".join(sorted(set(item) - ALLOWED_PATCH_KEYS))))
        bundle_file = item.get("bundle")
        if not bundle_file or not isinstance(bundle_file, str):
            raise CollectionError("patch %d has no 'bundle' filename" % i)
        if os.path.isabs(bundle_file) or ".." in bundle_file.replace("\\", "/").split("/"):
            raise CollectionError(
                "patch %d: bundle path %r must be relative to the collection "
                "directory (absolute paths and '..' are refused)" % (i, bundle_file))
        bundle_path = os.path.join(base, bundle_file)
        try:
            bundle = Bundle.load(bundle_path, strict=strict)
        except BundleError as exc:
            raise CollectionError("patch %d (%s): %s" % (i, bundle_file, exc)) from exc
        entries.append(Entry(
            bundle_file=bundle_file,
            order=int(item.get("order", 100)),
            required=bool(item.get("required", False)),
            description=str(item.get("description") or ""),
            enabled=bool(item.get("enabled", True)),
            bundle=bundle,
            path=bundle_path,
        ))
    if not entries:
        raise CollectionError("collection contains no patches")
    entries.sort(key=lambda e: (e.order, e.bundle.id if e.bundle else e.bundle_file))
    return Collection(
        name=str(raw.get("name") or os.path.splitext(os.path.basename(manifest))[0]),
        entries=entries,
        description=str(raw.get("description") or ""),
        author=str(raw.get("author") or ""),
        homepage=str(raw.get("homepage") or ""),
        license=str(raw.get("license") or ""),
        base_dir=base,
        path=manifest,
    )


# --------------------------------------------------------------------------- #
# selection
# --------------------------------------------------------------------------- #
def matches(bundle: Bundle, target_path: str, sha: str) -> bool:
    tgt = bundle.target or {}
    if tgt.get("size") is not None and int(tgt["size"]) != os.path.getsize(target_path):
        return False
    want = (tgt.get("sha256") or "").lower()
    if want and want != sha.lower():
        return False
    name = tgt.get("filename")
    if want is None and name and name.lower() != os.path.basename(target_path).lower():
        return False
    return True


def select(collection: Collection, target_path: str) -> Tuple[List[Entry], List[Entry]]:
    """Split entries into (applicable, not-applicable) for this target."""
    sha = sha256_file(target_path)
    ok, skipped = [], []
    for entry in collection.entries:
        if not entry.enabled:
            skipped.append(entry)
        elif matches(entry.bundle, target_path, sha):
            ok.append(entry)
        else:
            skipped.append(entry)
    return ok, skipped


# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #
def preflight(collection: Collection, target_path: str, require_signature: bool = False,
              extra_trusted: Optional[List[str]] = None,
              allow_abs_address: bool = False) -> Dict[str, Any]:
    """Check every applicable patch against a *simulated* patched copy.

    Runs in a temp directory: nothing outside it is touched, so a failing
    collection can be inspected safely before committing to anything.
    """
    entries, skipped = select(collection, target_path)
    if not entries:
        raise CollectionError(
            "no patch in collection %r applies to %s (size/sha256 mismatch)"
            % (collection.name, os.path.basename(target_path)))

    report: Dict[str, Any] = {"applicable": [], "skipped": [], "notes": [],
                             "warnings": []}
    for entry in skipped:
        reason = "disabled" if not entry.enabled else "target mismatch"
        report["skipped"].append({"bundle": entry.bundle.id, "file": entry.bundle_file,
                                  "reason": reason})

    workdir = tempfile.mkdtemp(prefix="surreal-collection-")
    simulated = os.path.join(workdir, os.path.basename(target_path))
    try:
        shutil.copyfile(target_path, simulated)
        for index, entry in enumerate(entries):
            bundle = entry.bundle
            ops = {h.op for h in bundle.hunks if h.enabled}
            if ops & {"append", "truncate"}:
                raise CollectionError(
                    "patch %s changes the file size; collections require "
                    "size-preserving patches so later RVAs stay valid"
                    % bundle.id)
            blocked = bundle.is_policy_blocked()
            if blocked:
                raise CollectionError("patch %s is policy-blocked: %s"
                                      % (bundle.id, blocked))
            # the first patch must match the pristine build exactly; after that
            # the hash is expected to differ (we verify bytes instead)
            plan = build_plan(bundle, simulated, accept_drift=index > 0,
                              require_signature=require_signature,
                              extra_trusted=extra_trusted,
                              allow_abs_address=allow_abs_address)
            apply_bundle(bundle, simulated, accept_drift=index > 0, no_backup=True,
                         no_checksum=True, require_signature=require_signature,
                         extra_trusted=extra_trusted,
                         allow_abs_address=allow_abs_address, force_unlock=True)
            report["applicable"].append({
                "bundle": bundle.id, "file": entry.bundle_file,
                "hunks": len(plan.resolved),
                "signature": (plan.signature or {}).get("state", "unknown"),
                "warnings": list(plan.warnings),
            })
            if index == 0:
                report["warnings"].extend(plan.warnings)
        report["result_sha256"] = sha256_file(simulated)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return report


# --------------------------------------------------------------------------- #
# transactional apply
# --------------------------------------------------------------------------- #
def apply_collection(collection: Collection, target_path: str,
                     require_signature: bool = False,
                     extra_trusted: Optional[List[str]] = None,
                     allow_abs_address: bool = False,
                     keep_backups: int = 3) -> Dict[str, Any]:
    """Apply every applicable patch, rolling the file back on any failure."""
    target = os.path.abspath(target_path)
    if not os.path.isfile(target):
        raise CollectionError("target not found: %s" % target)
    entries, skipped = select(collection, target)
    if not entries:
        raise CollectionError(
            "no patch in collection %r applies to %s"
            % (collection.name, os.path.basename(target)))

    applied: List[Dict[str, Any]] = []
    journal = Journal(target)
    backup = None
    original_sha = sha256_file(target)
    try:
        for index, entry in enumerate(entries):
            blocked = entry.bundle.is_policy_blocked()
            if blocked:
                raise CollectionError("patch %s is policy-blocked: %s"
                                      % (entry.bundle.id, blocked))
            if index == 0:
                if backup is None:
                    backup = journal.backup("collection:" + collection.name[:24])
            result = apply_bundle(entry.bundle, target, accept_drift=index > 0,
                                  no_backup=True, keep_backups=0,
                                  require_signature=require_signature,
                                  extra_trusted=extra_trusted,
                                  allow_abs_address=allow_abs_address)
            applied.append({
                "bundle": entry.bundle.id,
                "sha256_before": result["sha256_before"],
                "sha256_after": result["sha256_after"],
                "hunks": result["hunks"],
                "signature": (result.get("signature") or {}).get("state", "unknown"),
            })
    except BaseException as exc:
        # roll everything back to the single backup
        restored = False
        if backup and os.path.isfile(backup):
            directory = os.path.dirname(target)
            fd, tmp = tempfile.mkstemp(prefix=".surreal-rollback-", dir=directory)
            os.close(fd)
            try:
                shutil.copyfile(backup, tmp)
                os.replace(tmp, target)
                fsync_dir(directory)
                restored = sha256_file(target) == original_sha
            except OSError:
                pass
        journal.record("collection-rollback", collection=collection.name,
                       applied=[a["bundle"] for a in applied],
                       restored=restored, backup=backup,
                       error=str(exc))
        message = "%s\n  → applied %d patch(es) before failing; %s" % (
            exc, len(applied),
            "target restored from backup" if restored
            else "ROLLBACK FAILED — restore %s manually" % backup)
        raise CollectionError(message) from exc

    final_sha = sha256_file(target)
    journal.record("apply-collection", collection=collection.name,
                   collection_file=collection.path, backup=backup,
                   sha256_before=original_sha, sha256_after=final_sha,
                   patches=[a["bundle"] for a in applied],
                   patches_sha256=[a["sha256_after"] for a in applied])
    if keep_backups > 0:
        journal.prune(keep_backups)
    return {
        "collection": collection.name,
        "target": target,
        "applied": applied,
        "skipped": [{"bundle": e.bundle.id, "reason": "disabled" if not e.enabled
                     else "target mismatch"} for e in skipped],
        "sha256_before": original_sha,
        "sha256_after": final_sha,
        "backup": backup,
    }
