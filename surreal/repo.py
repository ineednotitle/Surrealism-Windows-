"""A local patch repository: an index of ``.morph`` bundles on disk.

There is no HTTP client in this tool and there never will be (surreal runs
offline and must stay auditable), so a "repo" here is a *file*: a JSON index of
bundles that already sit in a directory you control — a shared folder, a synced
drive, a copy-pasted bundle collection.

```json
{
  "format": "surreal.repo",
  "format_version": 1,
  "name": "My patch repo",
  "bundles": [
    { "id": "org.you.dark-theme", "file": "dark-theme.morph",
      "bundle_sha256": "…", "version": "1.0.0",
      "target": { "filename": "app.exe", "size": 2048, "sha256": "…" },
      "hunks": 3, "ops": ["patch"], "signer": "you" }
  ]
}
```

The index is a *directory listing with integrity hashes*, not a trust anchor:
a signature (and the trusted-key store) is what tells you who wrote a bundle.
The index hash tells you the bytes on disk are the bytes that were indexed.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from .keys import is_trusted
from .patchfile import Bundle, BundleError
from .util import read_json, sha256_file, write_json_atomic

FORMAT = "surreal.repo"
FORMAT_VERSION = 1
INDEX_NAMES = ("surreal-repo.json", "repo.json", "surreal-index.json")

ALLOWED_KEYS = {"format", "format_version", "name", "description", "created_utc",
                "base", "bundles"}
ALLOWED_ENTRY_KEYS = {"id", "file", "bundle_sha256", "name", "version", "author",
                      "description", "target", "pe", "hunks", "ops", "signer",
                      "public_key", "policy_blocked", "license", "homepage"}


class RepoError(Exception):
    pass


def _relative_path_error(value: str) -> Optional[str]:
    """Why ``value`` is not a safe relative path (``None`` when it is fine)."""
    rel = str(value).replace("\\", "/").strip()
    if not rel:
        return "is empty"
    if rel.startswith("/"):
        return "is absolute"
    if len(rel) > 1 and rel[1] == ":":
        return "names a drive letter"
    if ".." in [p for p in rel.split("/") if p]:
        return "contains '..'"
    return None


# --------------------------------------------------------------------------- #
# building an index
# --------------------------------------------------------------------------- #
def _entry(bundle: Bundle, path: str, base_dir: str) -> Dict[str, Any]:
    target = bundle.target or {}
    return {
        "id": bundle.id,
        "name": bundle.name,
        "file": os.path.relpath(path, base_dir).replace(os.sep, "/"),
        "bundle_sha256": sha256_file(path),
        "version": bundle.version,
        "author": bundle.author,
        "description": bundle.description,
        "license": bundle.license,
        "homepage": bundle.homepage,
        "hunks": len(bundle.hunks),
        "ops": sorted({h.op for h in bundle.hunks if h.enabled}),
        "target": {
            "filename": target.get("filename"),
            "size": target.get("size"),
            "sha256": (target.get("sha256") or "").lower() or None,
        },
        "signer": bundle.signer(),
        "public_key": (bundle.signature or {}).get("public_key"),
        "policy_blocked": bundle.is_policy_blocked(),
    }


def _relative_root(directory: str, base_dir: Optional[str]) -> str:
    """Where the bundle tree sits, relative to the index file's directory."""
    if not base_dir:
        return ""
    rel = os.path.relpath(directory, os.path.abspath(base_dir)).replace(os.sep, "/")
    if rel in (".", ""):
        return ""
    if rel.startswith("..") or os.path.isabs(rel):
        raise RepoError(
            "the index must live inside the folder it describes, or below it — "
            "%s is not reachable with a relative path from %s (copy the index "
            "next to the bundles instead)" % (directory, base_dir))
    return rel


def build_index(directory: str, name: str = "", description: str = "",
                config_dir: str = "", created_utc: Optional[str] = None,
                base_dir: Optional[str] = None,
                strict: bool = True) -> Dict[str, Any]:
    """Scan ``directory`` for ``.morph`` files and return an index dict.

    ``base_dir`` is the directory the index will be written to; bundle paths are
    stored relative to it (with a ``base`` prefix when the scanned folder is a
    subfolder), so the index never contains an absolute path and stays portable.
    """
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise RepoError("not a directory: %s" % directory)
    root_prefix = _relative_root(directory, base_dir)
    entries: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}
    errors: List[str] = []
    for root, dirnames, filenames in os.walk(directory):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for filename in sorted(filenames):
            if not filename.lower().endswith(".morph"):
                continue
            path = os.path.join(root, filename)
            try:
                bundle = Bundle.load(path, strict=strict)
            except BundleError as exc:
                errors.append("%s: %s" % (os.path.relpath(path, directory), exc))
                continue
            if bundle.id in seen:
                errors.append("duplicate bundle id %s (%s and %s)"
                              % (bundle.id, seen[bundle.id],
                                 os.path.relpath(path, directory)))
                continue
            seen[bundle.id] = os.path.relpath(path, directory)
            entries.append(_entry(bundle, path, directory))
    if not entries:
        raise RepoError("no readable .morph bundles under %s%s"
                        % (directory, (": " + "; ".join(errors[:3])) if errors else ""))
    entries.sort(key=lambda e: (e["id"], e["file"]))
    index = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "name": name or os.path.basename(directory) or "patch repo",
        "description": description,
        "bundles": entries,
    }
    if root_prefix:
        index["base"] = root_prefix
    if created_utc:
        index["created_utc"] = created_utc
    if errors:
        index["skipped"] = errors
    return index


# --------------------------------------------------------------------------- #
# reading an index
# --------------------------------------------------------------------------- #
def find_index(path: str) -> str:
    if os.path.isdir(path):
        for name in INDEX_NAMES:
            candidate = os.path.join(path, name)
            if os.path.isfile(candidate):
                return candidate
        raise RepoError("no repo index in %s (looked for %s)"
                        % (path, ", ".join(INDEX_NAMES)))
    if os.path.isfile(path):
        return path
    raise RepoError("repo index not found: %s" % path)


def load_index(path: str, strict: bool = True) -> Dict[str, Any]:
    real = find_index(path)
    raw = read_json(real)
    if not isinstance(raw, dict):
        raise RepoError("repo index must be a JSON object")
    if (raw.get("format") or FORMAT) != FORMAT:
        raise RepoError("not a %s file (format=%r)" % (FORMAT, raw.get("format")))
    if int(raw.get("format_version") or FORMAT_VERSION) != FORMAT_VERSION:
        raise RepoError("unsupported repo format_version %r"
                        % raw.get("format_version"))
    if strict:
        unknown = set(raw) - ALLOWED_KEYS - {"skipped"}
        if unknown:
            raise RepoError("unknown repo keys: %s" % ", ".join(sorted(unknown)))
    bundles = raw.get("bundles")
    if not isinstance(bundles, list) or not bundles:
        raise RepoError("repo index contains no bundles")
    for i, entry in enumerate(bundles):
        if not isinstance(entry, dict):
            raise RepoError("bundle %d must be an object" % i)
        if strict:
            unknown = set(entry) - ALLOWED_ENTRY_KEYS
            if unknown:
                raise RepoError("bundle %d has unknown keys: %s"
                                % (i, ", ".join(sorted(unknown))))
        for key in ("id", "file", "bundle_sha256"):
            if not entry.get(key):
                raise RepoError("bundle %d is missing %r" % (i, key))
        why = _relative_path_error(entry["file"])
        if why:
            raise RepoError("bundle %d: file %r %s — paths must be relative to "
                            "the index and stay inside it"
                            % (i, entry["file"], why))
    base = str(raw.get("base") or "").replace("\\", "/").strip("/")
    if base:
        why = _relative_path_error(base)
        if why:
            raise RepoError("repo 'base' %r %s — it must be a relative path that "
                            "stays inside the index directory"
                            % (raw.get("base"), why))
    raw["_index_path"] = os.path.abspath(real)
    raw["_base_dir"] = os.path.join(os.path.dirname(os.path.abspath(real)),
                                    *([p for p in base.split("/") if p] or []))
    return raw


def entries(index: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(index.get("bundles") or [])


def get(index: Dict[str, Any], bundle_id: str) -> Dict[str, Any]:
    for entry in entries(index):
        if entry.get("id") == bundle_id:
            return entry
    raise RepoError("bundle %r is not in this repo (%d available)"
                    % (bundle_id, len(entries(index))))


def matching(index: Dict[str, Any], target_path: str,
             sha: Optional[str] = None) -> List[Dict[str, Any]]:
    """Entries whose recorded target identity matches this file."""
    size = os.path.getsize(target_path)
    if sha is None:
        sha = sha256_file(target_path)
    out = []
    for entry in entries(index):
        tgt = entry.get("target") or {}
        if tgt.get("size") is not None and int(tgt["size"]) != size:
            continue
        want = (tgt.get("sha256") or "").lower()
        if want and want != sha.lower():
            continue
        out.append(entry)
    return out


def bundle_path(index: Dict[str, Any], entry: Dict[str, Any]) -> str:
    rel = str(entry["file"]).replace("\\", "/")
    return os.path.join(index["_base_dir"], *rel.split("/"))


def load_bundle(index: Dict[str, Any], entry: Dict[str, Any],
                strict: bool = True) -> Tuple[Bundle, str]:
    """Load the bundle for ``entry`` and prove it matches the indexed hash."""
    path = bundle_path(index, entry)
    if not os.path.isfile(path):
        raise RepoError("bundle file missing: %s (the repo index is stale)"
                        % path)
    actual = sha256_file(path)
    want = str(entry["bundle_sha256"]).lower()
    if actual != want:
        raise RepoError(
            "bundle %s does not match the repo index (sha256 %s… vs %s…) — the "
            "file changed after indexing; re-run `surreal repo index` and "
            "re-check the new hash" % (entry["id"], actual[:16], want[:16]))
    try:
        bundle = Bundle.load(path, strict=strict)
    except BundleError as exc:
        raise RepoError("bundle %s: %s" % (entry["id"], exc)) from exc
    if bundle.id != entry["id"]:
        raise RepoError("bundle file %s declares id %s, index says %s"
                        % (path, bundle.id, entry["id"]))
    return bundle, path


def trust_state(index: Dict[str, Any], entry: Dict[str, Any],
                config_dir: str) -> str:
    """'trusted' / 'untrusted' / 'unsigned' for display purposes."""
    pub = (entry.get("public_key") or "").lower()
    if not pub:
        return "unsigned"
    return "trusted" if pub and is_trusted(config_dir, pub) else "untrusted"


def summarize(index: Dict[str, Any], config_dir: str = "") -> Dict[str, Any]:
    items = entries(index)
    return {
        "name": index.get("name"),
        "path": index.get("_index_path"),
        "bundles": len(items),
        "signed": sum(1 for e in items if e.get("public_key")),
        "trusted": sum(1 for e in items if trust_state(index, e, config_dir) == "trusted"),
        "policy_blocked": sum(1 for e in items if e.get("policy_blocked")),
        "layout_changing": sum(1 for e in items
                               if set(e.get("ops") or []) &
                               {"append", "truncate", "extend-section", "add-section"}),
    }


def write_index(index: Dict[str, Any], path: str) -> str:
    payload = {k: v for k, v in index.items() if not k.startswith("_")}
    write_json_atomic(path, payload)
    return path
