# Patch collections (apply a set as one transaction)

One patch is rarely the whole story: a modded app usually needs "theme + no nag +
console". A **collection** is a small manifest next to a directory of `.morph`
files, applied all-or-nothing.

```json
{
  "format": "surreal.collection",
  "format_version": 1,
  "name": "Surrealism Window demo set",
  "description": "Two size-preserving demo patches",
  "patches": [
    { "bundle": "demo-shorten-nag.morph",  "order": 10 },
    { "bundle": "demo-blank-version.morph", "order": 20 }
  ]
}
```

File name: `surreal-collection.json` (also accepted: `collection.json`,
`surreal-repo.json`). Pass either the directory or the manifest file to
`surreal collection …`.

## Commands

```bash
surreal collection list  patches/                     # what is in the set?
surreal collection check patches/ --target app.exe    # dry run on a temp copy
surreal collection apply patches/ --target app.exe -y # one backup, all-or-nothing
surreal revert app.exe                                # undo the whole set
```

Useful flags: `--require-signature`, `--trusted-key HEX`,
`--allow-abs-address`, `--keep-backups N`, `--json`.

## Selection and ordering

* A patch applies when `target.size` and `target.sha256` match the file you
  point at. Everything else is *skipped and reported*, never silently ignored.
* Order is `order` (default 100), ties broken by bundle id — so two runs, and two
  machines, produce the same bytes.
* `"enabled": false` disables an entry without editing anything else.
* `"required": true` is recorded for humans and CI; it does not change the
  all-or-nothing behaviour (every selected patch is required by definition).
* `"depends_on": ["org.you.other"]` — this patch must be applied *after* the
  listed bundle ids. The loader topologically sorts the set (cycles are an
  error, self-dependency is an error, and the id must exist in the same
  collection), while `order` still decides the sequence between unrelated
  patches. A dependency that ends up disabled or inapplicable blocks the patch:
  you get "patch X depends on Y, which is disabled" instead of a half-applied
  result.
* `"conflicts_with": ["org.you.rival"]` — if both bundles are in the set and
  applicable, the whole run is refused. Ids that are not in the set are allowed
  (the conflicting patch may live in another collection), so this is a
  forward-compatible guard.
* Bundle ids must be unique inside one collection, otherwise ordering and
  dependency resolution would be ambiguous.

## The transaction

```
select → preflight (temp copy, nothing touched)
  → one backup of the target
      → patch 1 → patch 2 → … → patch N   (each fully verified)
          → journal: one "apply-collection" entry
  on any failure → restore the backup, journal a "collection-rollback", exit non-zero
```

Two rules make this safe:

1. **Size-preserving only.** A collection refuses `append`/`truncate` members.
   Growing the file would invalidate the RVAs that later patches were authored
   against. Use a standalone bundle for overlay changes.
2. **Exact match for the first patch, byte verification for the rest.** Patch 1
   must match the pristine target's hash. Patch 2..N were authored against that
   same pristine build, so their recorded hash is expected to drift once patch 1
   lands ("hash drift accepted" warning); their per-hunk `expect` bytes — the
   actual proof of correctness — are still verified in full.

## Vaults: several binaries, one transaction (v0.5)

Real apps ship as a handful of files (`app.exe` + `helper.dll` + plugins). If
**every** patch entry names a `target`, the collection becomes a **vault**: you
point `--target` at the application directory and the set is applied across
files:

```json
{
  "format": "surreal.collection",
  "format_version": 1,
  "name": "BetterApp vault",
  "patches": [
    { "bundle": "main-theme.morph",   "target": "app.exe",          "order": 10 },
    { "bundle": "plugin-fix.morph",   "target": "plugins/scan.dll", "order": 20 },
    { "bundle": "helper-clean.morph", "target": "bin/helper.exe",   "order": 30 }
  ]
}
```

```bash
surreal collection list  vault/                          # shows the file of each patch
surreal collection check vault/ --target "C:/Apps/BetterApp"
surreal collection apply vault/ --target "C:/Apps/BetterApp" -y
surreal revert "C:/Apps/BetterApp/bin/helper.exe"        # per file
```

Rules:

* **All or nothing, across files.** Each file gets its own backup before its
  first patch; if any file fails, every file touched so far is restored, and each
  one's journal records a `vault-rollback`. The message names what could not be
  restored if the rollback itself fails.
* **One journal entry per file**, `action: "apply-vault"`, listing every file in
  the vault. So `surreal revert <file>` undoes that file (the same directory's
  journal is filtered by target path, so two binaries side by side do not
  confuse each other).
* **Paths stay inside the root.** Absolute paths, drive letters and `..` are
  refused, and a target that resolves outside the root through a symlink is
  refused too.
* **Still size-preserving only.** Vault members may not use `append`,
  `truncate`, `extend-section` or `add-section` — apply a layout change on its
  own, outside the vault.
* Mixing vault and non-vault entries in one manifest is an error: either every
  patch names a target or none does.
* Files with no matching patch (wrong build, disabled entry) are *skipped and
  reported*, not treated as failures.

## Safety notes

* `collection check` runs the whole set against a copy in your temp directory and
  reports the resulting hash, so you can diff expectations before committing.
* A policy-blocked member blocks the entire set (exit 4) — one refused patch is
  not silently dropped.
* Paths inside the manifest must be relative and cannot contain `..`, so a
  downloaded collection cannot reach outside its own directory.
* `revert` restores the single backup, which undoes every patch in the set at
  once (the journal records the ordered bundle ids). For a vault, revert each
  file — the backups are per file.

## Authoring tips

* Keep collections small and orthogonal (theme, strings, behaviour) so a
  failing patch is easy to bisect.
* Author each bundle against the *pristine* binary, not against a partially
  patched one.
* Sign the bundles (`surreal sign`) and publish your public key in the README;
  users can then run `collection apply --require-signature`.
* `examples/` in this repo is a working collection you can copy as a template.
