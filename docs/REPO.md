# Local patch repositories

Surreal has **no network code** — not a lazy omission, a design rule enforced by
CI (`grep` fails the build if a socket/urllib import appears under `surreal/`).
A "repo" is therefore a *file*: a JSON index describing bundles that already sit
in a folder you can read — a shared drive, a synced folder, a `.zip` you unpacked.

```bash
surreal repo index patches/ -o patches/surreal-repo.json   # build the index
surreal repo list  patches/surreal-repo.json --target app.exe
surreal repo show  patches/surreal-repo.json --id org.you.dark-theme
surreal repo apply patches/surreal-repo.json --id org.you.dark-theme --target app.exe
```

## What the index contains

```json
{
  "format": "surreal.repo",
  "format_version": 1,
  "name": "My patch repo",
  "base": "bundles",
  "bundles": [
    {
      "id": "org.you.dark-theme",
      "name": "Dark theme",
      "file": "dark-theme.morph",
      "bundle_sha256": "…64 hex chars…",
      "version": "1.0.0",
      "author": "you",
      "hunks": 3,
      "ops": ["patch"],
      "target": { "filename": "app.exe", "size": 2048, "sha256": "…" },
      "signer": "you <4f1c…>",
      "public_key": "4f1c…",
      "policy_blocked": null
    }
  ]
}
```

* `file` is always **relative**, and `base` (optional) places the bundle tree
  relative to the index file. Absolute paths, drive letters, `..` and symlink
  escapes are refused at load time, so an index you copy out of a chat message
  cannot point at `C:\Windows\System32`.
* `bundle_sha256` is the integrity check: `repo apply` hashes the file on disk
  and refuses to continue if it does not match the index ("the file changed
  after indexing"). Re-index when you intentionally update a bundle.
* The index is **not** a trust anchor. It records who *signed* a bundle so you
  can see it, but trust still comes from your key store
  (`surreal keys --trust …`) and, if you want hard enforcement,
  `--require-signature`.
* Unreadable bundles (bad JSON, wrong format) and duplicate ids are **skipped and
  recorded** under `skipped`, so one broken file does not hide the rest.

## `repo index`

```bash
surreal repo index patches/                          # writes patches/surreal-repo.json
surreal repo index patches/ -o repo.json --name "Mine"
```

* Walks the folder recursively (skipping dotted directories), loads every
  `.morph`, and records the target identity it was authored for.
* The index must live inside the folder it describes, or below it. That keeps
  every path relative; if you want the index elsewhere, copy it next to the
  bundles.
* Output is deterministic: bundles sorted by id, no timestamps unless you pass
  `--created`.

## `repo list` / `repo show`

`repo list --target app.exe` marks (`*`) the bundles whose recorded size and
sha256 match the file you point at — the same identity check `surreal check`
performs, without loading every bundle. `repo show` prints the full bundle JSON,
the file hash and the signature state, so you can review before applying.

## `repo apply`

`repo apply` is the same code path as `surreal apply` once the bundle is
resolved — plan, verify, back up, patch a copy, recompute the checksum, atomic
swap. The only extra steps are: the file must match the index hash, the bundle id
must match the index entry, and a policy-blocked bundle is refused before any
write. Accepts `--dry-run`, `--accept-drift`, `--require-signature`,
`--trusted-key`, `--allow-abs-address`, `--force-unlock`, `--keep-backups`.

## Sharing

Share the bundles and the index, not the patched executables (see
[`LEGAL.md`](LEGAL.md)). Sign the bundles and publish your public key in your
README; a user then runs:

```bash
surreal keys --trust <your-public-key> --label you
surreal repo apply repo.json --id org.you.patch --target app.exe --require-signature
```

An index is only a convenience: anyone can re-index a folder. If you want a
reviewable, tamper-evident artefact, the signatures are what matter.
