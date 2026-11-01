# Architecture

## Module map

| Module | Responsibility | Forbidden to |
|---|---|---|
| `surreal/cli.py` | argparse front-end, human + `--json` rendering, exit codes | touch file bytes |
| `surreal/pe.py` | parse PE32/PE32+, RVA↔offset, checksum, imports/exports, entropy, overlay, signature presence | write files |
| `surreal/scanner.py` | wildcard byte search, ASCII/UTF-16LE string search, notable strings | guess matches |
| `surreal/patchfile.py` | `.morph` schema: load, validate, save, policy flags | execute anything |
| `surreal/diffgen.py` | before/after → hunks, anchor selection with uniqueness proof | write to the target |
| `surreal/patcher.py` | plan → verify → backup → patch copy → checksum → atomic swap | skip verification |
| `surreal/surgery.py` | plan + post-write proof for the two header-surgery ops (`extend-section`, `add-section`) | execute anything, touch overlays |
| `surreal/journal.py` | `<dir>/.surreal/journal.json` + `backups/` | lose a backup silently |
| `surreal/policy.py` | acceptable-use acknowledgement gate | nag twice |
| `surreal/testkit.py` | synthetic PE builder, `selftest`, demo fixtures | ship real binaries |
| `surreal/util.py` | hex parsing, hashing, atomic JSON IO, hexdump | hold global state |

Dependency direction is strictly one-way: `cli → {diffgen, patcher, patchfile,
pe, scanner, policy}` and `patcher → {patchfile, pe, scanner, journal, surgery}`.
No module imports `cli`.

## Invariants

1. **Read-only analysis.** `pe.py`, `scanner.py` and `diffgen.py` never open a
   target for writing.
2. **No write before full verification.** `patcher.apply_bundle` builds a plan
   (identity → anchors → hunks → expectations → overlaps → checksum prediction)
   before it creates a temp file, and backs up before it promotes that temp file.
3. **Atomicity.** The patched image is written to `<target>.surreal-*.tmp` in the
   *same directory* (same volume, so `os.replace` is atomic), fsynced, re-opened
   and re-parsed, then promoted.
4. **Reversibility.** Every apply records `sha256_before`, `sha256_after`, the
   backup path and the bundle id. `revert` requires the current hash to still
   equal `sha256_after`, so it will not clobber later edits.
5. **Constant memory.** File content is only ever accessed through `mmap` views,
   1 MiB IO chunks, or 8 MiB checksum slices. Nothing does `read()` on a whole
   executable.
6. **Fail closed.** Ambiguity → abort. Disagreement → abort. Unknown bundle
   fields → abort (unless `--lax`).

7. **Layout changes are explicit.** `append`/`truncate` only ever touch the
   overlay. Growing the mapped image (`extend-section`, `add-section`) is a
   separate op with its own planner (`surgery.py`), its own refusals (non-last
   section, existing overlay, last-section raw end ≠ EOF, RVA collision, header
   slack < 40 bytes) and a post-write proof: the temp file is re-parsed and
   `NumberOfSections`, `SizeOfImage`, file size, section bounds and the checksum
   must all match the prediction **before** `os.replace`. `surreal diff` emits
   such a hunk only when a replay through the applier reproduces the new build
   byte-for-byte, so the generator cannot invent a header edit.

## Data flow

```
 target.exe ──mmap──► pe.PE ──► scanner/diffgen ──► .morph (JSON, text, reviewable)
                                                        │
                          patcher.build_plan ◄───────────┘
                                   │  resolve + verify (no writes)
                                   ▼
             tmp copy ──patch──► checksum ──fsync──► os.replace ──► journal
                                                        │
                                                        ▼
                                              .surreal/backups/*.bak
```

## Concurrency

Single-process, single-threaded. Two applies of the same target at once are not
supported and not detected (there is no lock file in v1): the journal's hash
check on `revert` is the only cross-run guard. A `.surreal/lock` is on the M1
list.

## Performance design notes

* `bytes.find` on a `mmap` is `memmem`: the pattern's longest literal run is the
  needle, wildcard positions are verified afterwards. A pattern with no fixed
  byte is rejected rather than scanned byte-by-byte.
* The PE checksum uses `array('H')` + `sum()` over 8 MiB slices — the Python
  per-word loop was ~20× slower (0.17 s vs 4.0 s for 50 MB).
* `diff` reads both files exactly once, in lockstep chunks, and keeps only
  ranges — never the bytes.
* `apply` streams `shutil.copyfile` (which uses `sendfile`/`CopyFileEx` where
  available) and then seeks per hunk; total IO is 2 passes + a backup.
* The PE checksum after patching is *predicted* from delta sums of the touched
  word-aligned windows, so `--dry-run` reports the exact post-patch checksum
  without writing anything.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | usage error (argparse) |
| 3 | target mismatch, unresolved/ambiguous anchor, expect mismatch, overlap, missing bundle |
| 4 | policy: not accepted, or bundle declares a prohibited category |
| 5 | IO failure (missing target, disk error, verification of written bytes failed) |
| 130 | interrupted |

## Testing strategy

* `tests/test_pe.py` — parser against generated PE32/PE32+ images, including
  truncated headers, high-entropy sections, overlays and a fake certificate
  directory; the fast checksum is cross-checked against a literal transcription
  of Microsoft's documented loop.
* `tests/test_scanner.py` — hex parsing (spaced/packed/wildcards/ascii), pattern
  and string search, UTF-16LE.
* `tests/test_diffgen.py` — range merging, chunk boundaries, anchor uniqueness,
  periodic-file fallback, checksum-field exclusion.
* `tests/test_patcher.py` — every abort path (bad anchor, expect mismatch,
  locator disagreement, overlap, out-of-file, policy block, drift), plus
  backup/prune/revert semantics.
* `tests/test_cli.py` — all commands, `--json` shapes, exit codes, policy gate.
* `tests/test_perf.py` — ceilings and, more importantly, "RSS must not scale with
  file size".
