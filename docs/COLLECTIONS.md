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

## Safety notes

* `collection check` runs the whole set against a copy in your temp directory and
  reports the resulting hash, so you can diff expectations before committing.
* A policy-blocked member blocks the entire set (exit 4) — one refused patch is
  not silently dropped.
* Paths inside the manifest must be relative and cannot contain `..`, so a
  downloaded collection cannot reach outside its own directory.
* `revert` restores the single backup, which undoes every patch in the set at
  once (the journal records the ordered bundle ids).

## Authoring tips

* Keep collections small and orthogonal (theme, strings, behaviour) so a
  failing patch is easy to bisect.
* Author each bundle against the *pristine* binary, not against a partially
  patched one.
* Sign the bundles (`surreal sign`) and publish your public key in the README;
  users can then run `collection apply --require-signature`.
* `examples/` in this repo is a working collection you can copy as a template.
