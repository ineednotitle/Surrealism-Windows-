# Changelog

All notable changes to **Surrealism Window** (`surreal`). Bundle format version is
`surreal.morph` v1 throughout; every release is additive within that format, so a
bundle written for an older version keeps loading.

## Unreleased

### Collections across files
* Vault collections validate the dependency graph of the *whole* manifest, not one
  target at a time: cross-file `depends_on` is honoured, disabled/absent
  dependencies block the run, conflicts are caught across files, and cycles are
  refused before any byte is written.
* New `surreal collection graph <collection> [--json]` shows patches, their target
  file, requirements and conflicts; `collection check --json` now embeds the same
  graph.

## v0.5.0 — layout changes, vaults, dependencies, repos

### Header surgery (`op: extend-section`, `op: add-section`)
* `extend-section` grows the **last** section: appends the payload at EOF (padded
  to `FileAlignment`) and rewrites that section's `VirtualSize`, `SizeOfRawData`
  and the image's `SizeOfImage`. No RVA fixups are needed because nothing after
  the last section moves.
* `add-section` writes a new 40-byte section header (when the headers have at
  least 40 bytes of slack) plus its aligned raw data.
* New module `surreal/surgery.py` plans and *proves* both: refusals for non-last
  sections, existing overlays, last-section raw end ≠ EOF, RVA collisions,
  invalid `virtual_size_after` and full headers; after writing, the temp file is
  re-parsed and `NumberOfSections`, `SizeOfImage`, file size, section bounds and
  the checksum are checked **before** the atomic swap.
* `surreal diff` emits a surgery hunk only when replaying it through the real
  applier reproduces the new build byte-for-byte (checksum field excepted).
* One size/layout hunk per bundle, and never with `--accept-drift`.

### Multi-file vaults
* A collection whose entries all name a relative `target` becomes a vault:
  `surreal collection apply vault/ --target "C:/Apps/App"` patches every named
  binary as one transaction, with one backup and one journal entry per file and
  all-or-nothing rollback across files.
* Paths are confined to the root (absolute paths, drive letters, `..` and
  symlink escapes refused).
* The per-directory journal now filters entries by target path, so two binaries
  side by side keep separate histories and `surreal revert <file>` stays exact.

### Dependencies and conflicts
* `"depends_on": [...]` — stable topological ordering on top of `order`/id;
  cycles, self-references, unknown ids and disabled dependencies are refused.
* `"conflicts_with": [...]` — refused when both bundles are applicable.
* Bundle ids must be unique inside one collection.

### Local patch repositories
* `surreal repo index|list|show|apply` over a folder of `.morph` files: a JSON
  index with per-bundle sha256, target identity, ops and signer. Applying refuses
  a bundle whose bytes no longer match the index. Still zero network code.

### Interactive mode
* `surreal tui --target app.exe --dir patches/`: toggle bundles with numbers,
  `a` to apply the selection as one transaction, `r` to revert, `q` to quit. Plain
  line input (no curses), so it works frozen, over SSH and when piped.

### Windows fixes (found by the Windows CI legs, not guesswork)
* The frozen `surreal.exe` used to die on `--version`: PyInstaller was pointed at
  `surreal/cli.py`, which breaks the package's relative imports at startup. It now
  freezes the `surreal.py` shim, and `surreal.collection`, `surreal.repo` and
  `surreal.surgery` are in the hidden imports (a frozen build previously lost
  them).
* A console that cannot encode the UI glyphs (cp1252/cp437) no longer crashes a
  run: the console detects the encoding and falls back to `OK` / `XX` / `->`.
* `resource` and `os.uname()` were imported unconditionally by the perf tests, so
  the whole Windows test leg failed; peak-RSS measurement now lives in
  `memguard.peak_rss_mb()` with a Windows psapi path and an explicit "unknown".
* `surreal/lock.py` no longer imports `socket` (it only wanted a hostname) — the
  "no network modules" lint rule now holds without an exception.
* The bench harness prints ASCII only and reports an unknown RSS as `n/a`.

### Other
* `collection apply --dry-run` (single-target and vault).
* Windows lock/permission errors during the swap now explain what to do instead
  of surfacing `[WinError 32]`.
* `surreal info` / `check` describe surgery hunks and layout changes.
* 277 tests, 17-step `selftest`, CI smoke steps for surgery, vault and repo.

## v0.4.0 — collections

* `surreal collection list|check|apply`: an ordered set of size-preserving
  bundles applied as one transaction (one backup, one journal entry, rollback on
  failure). Manifest paths confined to the collection directory.
* Members must be size-preserving, and the first member must match the pristine
  build exactly; later members keep full per-hunk byte verification.

## v0.3.0 — overlay size changes

* `op: append` / `op: truncate`: grow or shrink the overlay (the bytes after the
  last section's raw data), which needs no header edits.
* `surreal diff` classifies a size-changing pair instead of refusing it, and
  still refuses every change inside the mapped image.
* Refusals: mixing append and truncate, image locators on an overlay hunk,
  `--accept-drift` on any size change.
* Non-PE targets are patchable when a bundle is all raw offsets + EOF ops
  (`surreal diff --force`).

## v0.2.0 — identity, concurrency, ASLR

* ed25519 signatures over `.morph` bundles (pure standard library), trusted-key
  store, `surreal sign` / `verify` / `keys`, `--require-signature`.
* Crash-safe apply lock (`<dir>/.surreal/lock`) with `--force-unlock`.
* ASLR / relocation safety: warn (or refuse with `--allow-abs-address`) when a
  hunk overwrites an absolute field covered by the base-relocation table.
* `--max-mem` ceiling on any whole-file read.
* Documented what it means when a signature is valid but the bundle is still a
  bad idea.

## v0.1.0 — first usable tool

* PE32/PE32+ parser, byte/string scanner, `diff` → `.morph` bundle, `check`,
  `apply` (lock → backup → verify → patch a copy → checksum → atomic swap →
  journal), `revert`, `inspect`, `demo`, `selftest`.
* Acceptable-use policy gate and legal positioning.
* Pure standard library, mmap-based, constant memory; PyInstaller one-file build
  in CI for Windows x64.
