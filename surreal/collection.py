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

Vaults (multi-file)
-------------------
If every patch entry carries a relative ``"target"`` path, the collection is a
**vault**: it patches several binaries under one application directory (the
``--target`` you pass is that directory). Each file gets its own backup and its
own journal entry, so ``surreal revert <file>`` still works per file, but the
whole set is all-or-nothing: a failure on file *n* restores every file touched
so far. Vault members must also be size-preserving, and paths may not escape the
root (no absolute paths, no ``..``).
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
ALLOWED_PATCH_KEYS = {"bundle", "order", "required", "description", "enabled",
                      "target", "depends_on", "conflicts_with"}


class CollectionError(Exception):
    pass


def _id_list(item: Dict[str, Any], key: str, index: int) -> List[str]:
    """Read a list-of-bundle-ids field (``depends_on`` / ``conflicts_with``)."""
    raw = item.get(key)
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raise CollectionError("patch %d: '%s' must be a list of bundle ids"
                              % (index, key))
    out: List[str] = []
    for value in raw:
        if not isinstance(value, str) or not value.strip():
            raise CollectionError("patch %d: '%s' entries must be non-empty "
                                  "strings" % (index, key))
        if value not in out:
            out.append(value.strip())
    return out


def safe_relative(path: str, what: str = "path") -> str:
    """Reject absolute paths, drive letters and ``..`` segments."""
    normalised = str(path).replace("\\", "/").strip()
    if not normalised:
        raise CollectionError("%s must not be empty" % what)
    if normalised.startswith("/") or (len(normalised) > 1 and normalised[1] == ":"):
        raise CollectionError("%s %r must be relative (absolute paths are refused)"
                              % (what, path))
    parts = [p for p in normalised.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise CollectionError("%s %r must not contain '..'" % (what, path))
    return "/".join(parts)


@dataclass
class Entry:
    bundle_file: str
    order: int = 100
    required: bool = False
    description: str = ""
    enabled: bool = True
    bundle: Optional[Bundle] = None
    path: Optional[str] = None
    target: Optional[str] = None      # vault: path relative to the app root
    depends_on: List[str] = field(default_factory=list)
    conflicts_with: List[str] = field(default_factory=list)


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
    def is_vault(self) -> bool:
        return any(e.target for e in self.entries)

    def files(self) -> List[str]:
        """Distinct target paths in manifest order (vault mode)."""
        seen: List[str] = []
        for e in self.entries:
            if e.target and e.target not in seen:
                seen.append(e.target)
        return seen

    def by_file(self) -> List[Tuple[str, List[Entry]]]:
        """Group entries per target, keeping the global order inside a file."""
        groups: List[Tuple[str, List[Entry]]] = []
        index: Dict[str, List[Entry]] = {}
        for e in self.entries:
            key = e.target or ""
            if key not in index:
                index[key] = []
                groups.append((key, index[key]))
            index[key].append(e)
        return groups

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
                 **({"target": e.target} if e.target else {}),
                 **({"depends_on": list(e.depends_on)} if e.depends_on else {}),
                 **({"conflicts_with": list(e.conflicts_with)}
                    if e.conflicts_with else {}),
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
        depends_on = _id_list(item, "depends_on", i)
        conflicts_with = _id_list(item, "conflicts_with", i)
        target_rel = item.get("target")
        if target_rel is not None:
            if not isinstance(target_rel, str):
                raise CollectionError("patch %d: 'target' must be a string" % i)
            target_rel = safe_relative(target_rel, "patch %d target" % i)
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
            target=target_rel,
            depends_on=depends_on,
            conflicts_with=conflicts_with,
        ))
    if not entries:
        raise CollectionError("collection contains no patches")
    entries = _order_by_dependencies(_primary_order(entries))
    with_target = [e for e in entries if e.target]
    if with_target and len(with_target) != len(entries):
        missing = [e.bundle_file for e in entries if not e.target]
        raise CollectionError(
            "mixed collection: %d patch(es) name a 'target' file but %s do not. "
            "Either every patch names one (a vault over an application directory) "
            "or none do (a single-target collection)"
            % (len(with_target), ", ".join(missing[:3])))
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
# dependencies
# --------------------------------------------------------------------------- #
def _primary_order(entries: List[Entry]) -> List[Entry]:
    """Deterministic baseline: ``order`` first, bundle id (or filename) on ties."""
    return sorted(entries, key=lambda e: (e.order,
                                          e.bundle.id if e.bundle else e.bundle_file))


def _order_by_dependencies(entries: List[Entry]) -> List[Entry]:
    """Stable topological sort: a patch always follows what it depends on.

    ``order``/bundle-id ordering still decides the sequence *between* unrelated
    patches, so the result stays deterministic.
    """
    ids = {}
    for entry in entries:
        if entry.bundle is not None:
            if entry.bundle.id in ids:
                raise CollectionError("duplicate bundle id %r in collection "
                                      "(ids must be unique)" % entry.bundle.id)
            ids[entry.bundle.id] = entry
    for entry in entries:
        for dep in entry.depends_on:
            if entry.bundle is not None and dep == entry.bundle.id:
                raise CollectionError("patch %s depends on itself" % dep)
            if dep not in ids:
                raise CollectionError(
                    "patch %s depends on %r, which is not in this collection"
                    % (entry.bundle.id if entry.bundle else entry.bundle_file, dep))

    ordered: List[Entry] = []
    placed = set()
    pending = list(entries)
    while pending:
        ready = [e for e in pending
                 if all(dep in placed for dep in e.depends_on)]
        if not ready:
            cycle = ", ".join(sorted(e.bundle.id for e in pending
                                     if e.bundle is not None))
            raise CollectionError(
                "dependency cycle between patches: %s — break the cycle (a "
                "collection is a sequence, not a graph)" % cycle)
        # keep the existing (order, id) sequence among ready entries
        chosen = ready[0]
        ordered.append(chosen)
        placed.add(chosen.bundle.id if chosen.bundle else chosen.bundle_file)
        pending.remove(chosen)
    return ordered


def check_conflicts(selected: List[Entry]) -> None:
    """Refuse a set where one patch declares a conflict with another member."""
    ids = {}
    for entry in selected:
        if entry.bundle is not None:
            ids[entry.bundle.id] = entry
    for entry in selected:
        if entry.bundle is None:
            continue
        for other in entry.conflicts_with:
            if other in ids:
                raise CollectionError(
                    "patch %s conflicts with %s — remove one of them from the "
                    "collection (or disable it with \"enabled\": false)"
                    % (entry.bundle.id, other))


# --------------------------------------------------------------------------- #
# dependency graph (whole collection, across target files)
# --------------------------------------------------------------------------- #
def _find_cycle(adj: Dict[str, List[str]], ids: List[str]) -> Optional[List[str]]:
    """Return one dependency cycle as ``a -> b -> a``, or None. Iterative DFS."""
    color = {i: 0 for i in ids}          # 0 unvisited, 1 on stack, 2 done
    for start in ids:
        if color[start]:
            continue
        color[start] = 1
        path = [start]
        stack = [(start, iter(adj[start]))]
        while stack:
            node, it = stack[-1]
            descended = False
            for nxt in it:
                if color.get(nxt) == 0:
                    color[nxt] = 1
                    path.append(nxt)
                    stack.append((nxt, iter(adj[nxt])))
                    descended = True
                    break
                if color.get(nxt) == 1:
                    return path[path.index(nxt):] + [nxt]
            if not descended:
                color[node] = 2
                path.pop()
                stack.pop()
    return None


def dependency_graph(collection: Collection,
                     active_ids: Optional[set] = None) -> Dict[str, Any]:
    """Structural view of the collection: nodes, edges, and what is wrong.

    Works on the whole manifest, so a vault can declare that a patch for
    ``lib/core.dll`` needs a patch for ``app.exe``. Issues are only reported for
    *active* patches (enabled, and applicable when the caller knows that).
    """
    nodes: List[Dict[str, Any]] = []
    for entry in collection.entries:
        bundle = entry.bundle
        nodes.append({
            "id": bundle.id if bundle is not None else entry.bundle_file,
            "file": entry.target or None,
            "order": entry.order,
            "enabled": entry.enabled,
            "depends_on": list(entry.depends_on),
            "conflicts_with": list(entry.conflicts_with),
        })
    known = {n["id"]: n for n in nodes}
    if active_ids is None:
        active_ids = {n["id"] for n in nodes if n["enabled"]}
    active = {i for i in active_ids if i in known}

    edges: List[Dict[str, Any]] = []
    issues: List[Dict[str, Any]] = []
    for node in nodes:
        if node["id"] not in active:
            continue
        for dep in node["depends_on"]:
            target = known.get(dep)
            if target is None:
                issues.append({"kind": "missing-dependency", "patch": node["id"],
                               "depends_on": dep,
                               "detail": "not defined in this collection"})
                continue
            cross = bool(node["file"] and target["file"]
                         and node["file"] != target["file"])
            edges.append({"from": node["id"], "to": dep, "cross_file": cross,
                          "from_file": node["file"], "to_file": target["file"]})
            if not target["enabled"]:
                issues.append({"kind": "disabled-dependency", "patch": node["id"],
                               "depends_on": dep,
                               "detail": "the required patch is disabled"})
            elif dep not in active:
                issues.append({"kind": "inactive-dependency", "patch": node["id"],
                               "depends_on": dep,
                               "detail": "the required patch is not applied to "
                                         "any target here (other or missing file?)"})
        for other in node["conflicts_with"]:
            if other in active:
                # report once, on the alphabetically first of the pair
                if node["id"] < other:
                    issues.append({"kind": "conflict", "patch": node["id"],
                                   "depends_on": other,
                                   "detail": "%s and %s are both selected"
                                             % (node["id"], other)})

    cycle = _find_cycle({n["id"]: n["depends_on"] for n in nodes}, sorted(active))
    if cycle:
        issues.append({"kind": "cycle", "patch": cycle[0], "chain": cycle,
                       "detail": " -> ".join(cycle)})
    return {
        "nodes": nodes,
        "edges": edges,
        "issues": issues,
        "cross_file_edges": [e for e in edges if e["cross_file"]],
    }


_ISSUE_ORDER = {"cycle": 0, "missing-dependency": 1, "disabled-dependency": 2,
                "inactive-dependency": 3, "conflict": 4, "ordering": 5}


def validate_graph(collection: Collection,
                   active_ids: Optional[set] = None) -> Dict[str, Any]:
    """Raise on a broken dependency graph; return the graph when it is sound."""
    graph = dependency_graph(collection, active_ids)
    hard = [i for i in graph["issues"] if i["kind"] != "ordering"]
    if hard:
        hard.sort(key=lambda i: _ISSUE_ORDER.get(i["kind"], 9))
        lines = []
        for issue in hard:
            if issue["kind"] == "cycle":
                lines.append("dependency cycle between patches: %s" % issue["detail"])
            elif issue["kind"] == "conflict":
                lines.append("%s conflicts with %s" % (issue["patch"], issue["depends_on"]))
            else:
                lines.append("patch %s depends on %s, which is %s"
                             % (issue["patch"], issue["depends_on"], issue["detail"]))
        raise CollectionError(
            "collection %r has %d dependency problem(s):\n  - %s"
            % (collection.name, len(hard), "\n  - ".join(lines)))
    return graph


def _ordering_notes(graph: Dict[str, Any],
                    file_rank: Dict[str, int]) -> List[str]:
    """Cross-file dependencies point *backwards*: warn when one points forward."""
    notes = []
    for edge in graph["cross_file_edges"]:
        before, after = file_rank.get(edge["to_file"]), file_rank.get(edge["from_file"])
        if before is None or after is None or before <= after:
            continue
        notes.append(
            "patch %s (%s) depends on %s (%s), but %s is patched after %s — "
            "reorder the manifest so the dependency comes first"
            % (edge["from"], edge["from_file"], edge["to"], edge["to_file"],
               edge["to_file"], edge["from_file"]))
    return notes


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
    check_conflicts(ok)
    _check_dependencies(collection, ok, skipped)
    return ok, skipped


def _check_dependencies(collection: Collection, ok: List[Entry],
                        skipped: List[Entry]) -> None:
    """A selected patch must not depend on a patch that will not be applied."""
    applied = {e.bundle.id for e in ok if e.bundle is not None}
    known = {e.bundle.id for e in collection.entries if e.bundle is not None}
    for entry in ok:
        if entry.bundle is None:
            continue
        for dep in entry.depends_on:
            if dep in applied:
                continue
            reason = ("disabled" if any(e.bundle is not None and e.bundle.id == dep
                                        and not e.enabled
                                        for e in collection.entries)
                      else "not applicable to this target")
            raise CollectionError(
                "patch %s depends on %s, which is %s — enable it or drop the "
                "patch" % (entry.bundle.id, dep,
                           reason if dep in known else "missing"))


# --------------------------------------------------------------------------- #
# member guards
# --------------------------------------------------------------------------- #
LAYOUT_OPS = {"append", "truncate", "extend-section", "add-section"}


def _check_member(bundle: Bundle) -> None:
    """Refuse members a collection cannot safely combine with others."""
    ops = {h.op for h in bundle.hunks if h.enabled}
    if ops & LAYOUT_OPS:
        raise CollectionError(
            "patch %s changes the size or layout of the file (%s); collections "
            "require size-preserving patches so later RVAs stay valid — apply it "
            "on its own" % (bundle.id, ", ".join(sorted(ops & LAYOUT_OPS))))
    blocked = bundle.is_policy_blocked()
    if blocked:
        raise CollectionError("patch %s is policy-blocked: %s" % (bundle.id, blocked))


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
            _check_member(bundle)
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
            _check_member(entry.bundle)
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
        if not applied and not backup:
            tail = "nothing was written"
        elif restored:
            tail = "target restored from backup"
        else:
            tail = ("ROLLBACK FAILED — restore %s manually" % backup
                    if backup else "ROLLBACK FAILED — no backup was taken")
        message = "%s\n  → applied %d patch(es) before failing; %s" % (
            exc, len(applied), tail)
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


# --------------------------------------------------------------------------- #
# vaults: several binaries, one transaction
# --------------------------------------------------------------------------- #
def resolve_root(collection: Collection, root: str) -> str:
    """Validate the application root and every target inside it."""
    if not collection.is_vault:
        raise CollectionError("collection %r is not a vault (no patch names a "
                              "'target' file)" % collection.name)
    root_abs = os.path.abspath(root)
    if not os.path.isdir(root_abs):
        raise CollectionError(
            "vault collections patch a whole application directory; --target must "
            "be that directory (%s is not a directory)" % root_abs)
    real_root = os.path.realpath(root_abs)
    for rel in collection.files():
        path = os.path.join(root_abs, *rel.split("/"))
        if not os.path.isfile(path):
            raise CollectionError(
                "patch target %r not found under %s (the vault expects the "
                "application's own layout)" % (rel, root_abs))
        real = os.path.realpath(path)
        if os.path.dirname(real) != real_root and not real.startswith(real_root + os.sep):
            raise CollectionError(
                "patch target %r resolves outside %s (symlink escape refused)"
                % (rel, root_abs))
    return root_abs


def _vault_plan(collection: Collection, root_abs: str) -> List[Tuple[str, str, List[Entry]]]:
    """[(relative target, absolute path, applicable entries)] in manifest order."""
    plan = []
    for rel, entries in collection.by_file():
        path = os.path.join(root_abs, *rel.split("/"))
        sha = sha256_file(path)
        applicable = [e for e in entries if e.enabled and matches(e.bundle, path, sha)]
        plan.append((rel, path, applicable))
    return plan


def preflight_vault(collection: Collection, root: str,
                    require_signature: bool = False,
                    extra_trusted: Optional[List[str]] = None,
                    allow_abs_address: bool = False) -> Dict[str, Any]:
    """Dry-run every vault member on temp copies. Nothing outside the temp dir."""
    root_abs = resolve_root(collection, root)
    plan = _vault_plan(collection, root_abs)
    selected = {e.bundle.id for _rel, _path, entries in plan for e in entries
                if e.bundle is not None}
    graph = validate_graph(collection, selected)
    report: Dict[str, Any] = {"vault": collection.name, "root": root_abs,
                              "files": [], "skipped": [], "warnings": [],
                              "graph": graph}
    report["warnings"].extend(
        _ordering_notes(graph, {rel: i for i, (rel, _p, _e) in enumerate(plan)}))
    for rel, entries in collection.by_file():
        applicable = next(p[2] for p in plan if p[0] == rel)
        if not applicable:
            report["skipped"].append({"file": rel, "reason": "target mismatch"})
    if not any(p[2] for p in plan):
        raise CollectionError(
            "no patch in vault %r applies to any file under %s"
            % (collection.name, root_abs))

    workdir = tempfile.mkdtemp(prefix="surreal-vault-")
    try:
        for rel, path, entries in plan:
            if not entries:
                continue
            for entry in entries:
                _check_member(entry.bundle)
            simulated = os.path.join(workdir, rel.replace("/", "_"))
            shutil.copyfile(path, simulated)
            applied = []
            for index, entry in enumerate(entries):
                member_plan = build_plan(
                    entry.bundle, simulated, accept_drift=index > 0,
                    require_signature=require_signature,
                    extra_trusted=extra_trusted,
                    allow_abs_address=allow_abs_address)
                apply_bundle(entry.bundle, simulated, accept_drift=index > 0,
                             no_backup=True, no_checksum=True,
                             require_signature=require_signature,
                             extra_trusted=extra_trusted,
                             allow_abs_address=allow_abs_address, force_unlock=True)
                applied.append({"bundle": entry.bundle.id,
                                "hunks": len(member_plan.resolved),
                                "signature": (member_plan.signature or {}).get("state", "unknown")})
                if index == 0:
                    report["warnings"].extend(member_plan.warnings)
            report["files"].append({"file": rel, "patches": applied,
                                    "result_sha256": sha256_file(simulated)})
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return report


def _restore(path: str, backup: str, want_sha: str) -> bool:
    """Atomically copy ``backup`` back over ``path`` and verify the hash."""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".surreal-rollback-", dir=directory)
    os.close(fd)
    try:
        shutil.copyfile(backup, tmp)
        os.replace(tmp, path)
        fsync_dir(directory)
        return sha256_file(path) == want_sha
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def apply_vault(collection: Collection, root: str,
                require_signature: bool = False,
                extra_trusted: Optional[List[str]] = None,
                allow_abs_address: bool = False,
                keep_backups: int = 3) -> Dict[str, Any]:
    """Patch every file in the vault; restore *all* of them if any step fails."""
    root_abs = resolve_root(collection, root)
    plan = _vault_plan(collection, root_abs)
    if not any(p[2] for p in plan):
        raise CollectionError(
            "no patch in vault %r applies to any file under %s"
            % (collection.name, root_abs))
    # refuse before the first byte is written: a broken graph is not something a
    # rollback should have to hide
    validate_graph(collection, {e.bundle.id for _rel, _path, entries in plan
                                for e in entries if e.bundle is not None})

    results: List[Dict[str, Any]] = []
    touched: List[Tuple[str, str, str]] = []   # (path, backup, sha_before)
    try:
        for rel, path, entries in plan:
            if not entries:
                continue
            backup = None
            original_sha = sha256_file(path)
            applied = []
            for index, entry in enumerate(entries):
                _check_member(entry.bundle)
                if backup is None:
                    backup = Journal(path).backup("vault:" + collection.name[:20])
                    touched.append((path, backup, original_sha))
                result = apply_bundle(
                    entry.bundle, path, accept_drift=index > 0, no_backup=True,
                    keep_backups=0, require_signature=require_signature,
                    extra_trusted=extra_trusted,
                    allow_abs_address=allow_abs_address)
                applied.append({
                    "bundle": entry.bundle.id,
                    "sha256_before": result["sha256_before"],
                    "sha256_after": result["sha256_after"],
                    "hunks": result["hunks"],
                })
            final_sha = sha256_file(path)
            # a fresh Journal: apply_bundle wrote its own per-patch entries since
            # the backup was taken, and a cached instance would drop them
            Journal(path).record(
                "apply-vault", collection=collection.name,
                collection_file=collection.path, file=rel, backup=backup,
                sha256_before=original_sha, sha256_after=final_sha,
                patches=[a["bundle"] for a in applied],
                vault_files=collection.files())
            results.append({"file": rel, "target": path, "backup": backup,
                            "applied": applied, "sha256_before": original_sha,
                            "sha256_after": final_sha})
    except BaseException as exc:
        restored, failed = [], []
        for path, backup, sha_before in reversed(touched):
            ok = bool(backup) and os.path.isfile(backup) and _restore(path, backup, sha_before)
            (restored if ok else failed).append(path)
            Journal(path).record("vault-rollback", collection=collection.name,
                           backup=backup, restored=ok,
                           sha256_after=sha256_file(path) if os.path.isfile(path) else None,
                           error=str(exc))
        message = "%s\n  → %d file(s) touched; %s" % (
            exc, len(touched),
            "all restored from backup" if not failed
            else "ROLLBACK FAILED for %s — restore manually" % ", ".join(failed))
        raise CollectionError(message) from exc

    if keep_backups > 0:
        for _rel, path, _entries in plan:
            if os.path.isfile(path):
                Journal(path).prune(keep_backups)
    return {
        "collection": collection.name,
        "root": root_abs,
        "vault": True,
        "files": results,
        "skipped": [{"file": rel, "reason": "target mismatch or disabled"}
                    for rel, _path, entries in plan if not entries],
    }
