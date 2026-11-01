# Surrealism Window

**`surreal`** — a Morphe-style, CLI-first patch workbench for Windows `.exe` files.
Inspect a binary, find the bytes that matter, turn a before/after pair into a
reviewable `.morph` patch bundle, and re-apply that bundle to *your own* copy of
the app — reproducibly, reversibly, and on a 4 GB machine.

```
  surreal inspect app.exe                 # what am I looking at?
  surreal scan    app.exe --string "..."  # where is it?
  surreal diff    old.exe new.exe -o my.morph --id me.my-patch
  surreal check   my.morph --target app.exe
  surreal apply   my.morph --target app.exe
  surreal revert  app.exe
```

> **Scope, in one line:** `surreal` is a deterministic byte-editor with a paper
> trail. It ships no cracks and no keys; it gives you a safe, auditable workflow
> for reverse engineering **software you own or are licensed to modify**. Read
> [`docs/LEGAL.md`](docs/LEGAL.md) before your first patch.

---

## Why another patcher?

Morphe-style tools (ReVanced, LuckyPatcher, xdelta patchers) teach one important
lesson: **a patch should describe intent, not a hard-coded file offset.** A raw
`0x1A2C4 = 90` breaks silently on the next build. `surreal` therefore makes
every hunk prove three things before it touches a byte:

1. **Where** — a unique literal *anchor* (or section + RVA, or file offset);
2. **What was there** — the expected original bytes (`expect`), wildcards allowed;
3. **What replaces it** — fixed-length bytes (`replace`).

If any proof fails, nothing is written. Ever.

## Install

Pick whichever fits your machine:

| Method | Command | Notes |
|---|---|---|
| Prebuilt binary | download `surreal.exe` from [Releases](../../releases) | no Python needed, ~11 MB, unsigned |
| From source (any OS) | `git clone … && cd Surrealism-Windows- && python -m surreal --help` | Python 3.9+, **stdlib only** — no pip install |
| Build your own exe | `powershell -ExecutionPolicy Bypass -File build/build_windows.ps1` | needs `pip install pyinstaller` |

Running from source on Windows:

```powershell
py -3 -m surreal selftest      # end-to-end check on a generated PE
py -3 -m surreal demo          # writes surreal-demo\ with a practice target
```

## Try it in 60 seconds (no real exe involved)

```
$ python -m surreal demo
  ✓ demo written to …\surreal-demo
  target: demo_app.exe
  bundle: demo-shorten-nag.morph
  hunks:  2 (all anchored: 2)

$ python -m surreal inspect surreal-demo/demo_app.exe
surreal 0.5.0 — Surrealism Window · windows patch workbench
  …\surreal-demo\demo_app.exe  (2.0 KiB)
  sha256 4d51cec411ac4bf2856d007044be52d8da0713e4abe227f02244193c66251408

  format:                PE32+ / x64 / console
  image base:            0x140000000
  entry point:           RVA 0x1000
  authenticode:          unsigned
  checksum:              0x000060A3 (valid)

  sections
    name          raw ptr   raw size        rva  flags        ent sha256
    .text             200        200       1000  X-          1.80 b8649f444afc99b4
    .rdata            400        200       2000  --          1.94 46ed15344afc99b4
    .data             600        200       3000  -W          1.49 9758628d2a46a254

$ python -m surreal scan surreal-demo/demo_app.exe --string "Trial"
  1 hit(s) for 'Trial' in demo_app.exe (2 ms)
  0x00000449  ascii  section .rdata  rva 0x2049
      00000445  65 6D 6F 00 54 72 69 61 6C 20 65 78 70           |emo.Trial exp|

$ python -m surreal check surreal-demo/demo-shorten-nag.morph `
        --target surreal-demo/demo_app.exe
  ✓ bundle org.surreal.demo.shorten-nag is applicable to demo_app.exe
```

## Commands

| Command | What it does |
|---|---|
| `init` | prints the acceptable-use policy; `--accept-policy` records it (required before the first write), `--revoke` forgets it |
| `inspect <exe>` | PE32/PE32+ headers, sections, entropy, checksum, overlay, Authenticode state, imports/exports, notable strings, and honest heuristics ("section .vmp0 present: looks like VMProtect") |
| `scan <exe> --pattern "48 8B ?? E8"` | wildcard byte search → file offset, RVA, section, hexdump |
| `scan <exe> --string "text" [--both]` | ASCII and/or UTF-16LE text search |
| `diff old new -o x.morph --id …` | builds a patch bundle from two builds (this is the "patch creator") |
| `info <morph>` | human + `--json` view of a bundle: anchors, hunks, policy flags |
| `check <morph> --target <exe>` | full preflight, writes nothing, exit code tells you if it would work |
| `apply <morph> --target <exe>` | lock → backup → verify → patch a copy → recompute checksum → atomic swap → journal |
| `revert <exe>` | restore the last backup (`--list` shows the journal) |
| `collection list/check/apply` | apply a set of bundles as one transaction (all-or-nothing, one backup); `target` per entry → multi-file vault |
| `repo index/list/show/apply` | index a folder of bundles (with hashes), list matches for a build, apply one by id |
| `sign <morph> --key me.key` | sign a bundle (ed25519); makes it tamper-evident |
| `verify <morph> [--require]` | check the signature and whether the key is trusted |
| `keys --generate/--trust/--untrust` | manage your signing key and trusted-key store |
| `demo` | generate a synthetic PE + bundle to practise on |
| `selftest` | runs build→diff→check→apply→revert on a generated PE and prints PASS/FAIL |

Every command accepts `--json` for scripting. Exit codes:
`0` ok · `2` usage · `3` mismatch / unresolved anchor / expect-byte mismatch ·
`4` policy · `5` IO.

## How a patch is made

```
1. inspect           learn the shape of the binary (sections, entropy, imports)
2. scan              locate a string or an instruction pattern
3. reverse           your tools: x64dbg, Ghidra, rizin, objdump, your own eyes
4. produce a fixed build   (from source, or an edit you are allowed to make)
5. diff              old.exe vs fixed.exe → my.morph
6. check             prove the bundle resolves and every expect-byte matches
7. commit the .morph  it is JSON — reviewers read it in the PR
```

`surreal diff` does the boring-but-critical part automatically:

* **streaming compare** (1 MiB chunks) → differing ranges, merged when they are
  closer than `--merge-gap` (default 16) so one logical edit is one hunk;
* **anchor proof**: the shortest literal context around each hunk that occurs
  **exactly once** in the whole binary — verified by a full scan;
* **corroboration**: section + RVA and file offset are recorded too, and all
  locators must agree at apply time;
* **checksum noise removed**: a differing PE `CheckSum` field is never turned
  into a hunk (it is recomputed on apply);
* **identity capture**: size, SHA-256, machine, timestamp, entrypoint, image
  base, per-section hashes, Authenticode state.

Result (trimmed):

```json
{
  "format": "surreal.morph", "format_version": 1,
  "id": "org.surreal.demo.shorten-nag",
  "name": "Demo: blank the trial nag + flip one branch",
  "target": { "filename": "demo_app.exe", "size": 2048, "sha256": "4d51ce…",
              "pe": { "machine": "0x8664", "entrypoint_rva": 4096 },
              "sections": [ { "name": ".text", "raw_sha256": "b8649f…" } ] },
  "anchors": [ { "name": "anchor_0", "pattern": "50 48 8D 15 F0 E0 D0 C0",
                 "unique": true, "file_offset": 577 } ],
  "hunks": [ { "anchor": 0, "delta": 8, "section": ".text", "rva": 4177,
               "offset": 593, "expect": "7F", "replace": "7E" } ],
  "policy": { "requires_rights_attestation": true, "forbidden_categories": [] }
}
```

Full normative spec: [`docs/PATCH_FORMAT.md`](docs/PATCH_FORMAT.md).

## How a patch is applied (the safety model)

```
load bundle → policy gate → mmap target
  → identity: size, sha256, machine, magic            (drift ⇒ abort, or --accept-drift)
  → resolve anchors: exactly-once proof per anchor    (ambiguous ⇒ abort)
  → resolve hunks: anchor▸section+RVA▸offset          (disagreement ⇒ abort)
  → verify expect bytes against disk                  (mismatch ⇒ abort)
  → reject overlapping hunks
  → warn: any Authenticode signature will be voided
  → backup to <dir>\.surreal\backups\
  → patch a temp copy in the same directory, fsync
  → recompute PE checksum, re-open the copy to prove it still parses
  → os.replace(tmp → app.exe)   ← atomic on NTFS
  → journal {bundle, sha before/after, backup, time}
```

`--dry-run` executes everything except the write, so you can see the exact
commitment first. `surreal revert` restores the backup and refuses if the file
changed since it was patched.

### Identity, concurrency and ASLR (v0.2)

* **Signed bundles.** `surreal sign` produces an ed25519 signature over the
  bundle's canonical JSON (pure-Python RFC 8032, validation against the RFC test
  vectors in CI). `surreal verify` reports `unsigned` / `untrusted` / `valid`;
  any tampering is fatal. `apply --require-signature` refuses anything not
  signed by a key you trust. `--trusted-key HEX` admits a key for one run (CI
  friendly). Details: [`docs/SIGNING.md`](docs/SIGNING.md).
* **One writer at a time.** `<dir>\.surreal\lock` is taken with
  `O_CREAT|O_EXCL` for every apply/revert; a crashed run's lock (dead PID, other
  host, or older than 15 min) is reclaimed automatically. `--force-unlock` is
  there for the day it guesses wrong.
* **ASLR safety.** If a hunk overwrites a field covered by a base relocation
  (`.reloc`), the patched image would only be correct at the base it was tested
  at. Such hunks are **refused** with the offending RVA and relocation type; the
  diff generator warns about them at authoring time; `--allow-abs-address`
  proceeds anyway once you have verified rebasing.
* **Memory ceiling.** `--max-mem MB` (default 256) bounds every whole-file read
  (`--force` non-PE diffs, fallbacks) *before* allocating, so surreal fails with
  a clear message instead of swapping a 4 GB machine to death.

### Collections (v0.4): "apply all my patches" as one transaction

```bash
surreal collection list  patches/
surreal collection check patches/ --target app.exe     # dry run on a temp copy
surreal collection apply patches/ --target app.exe -y   # one backup, all-or-nothing
surreal revert app.exe                                  # undo the whole set
```

Collection members must be **size-preserving** (so later RVAs stay valid), the
first patch must match the pristine build exactly, and every later patch still
gets full per-hunk byte verification. Any failure restores the single backup and
journals a rollback. Manifest format and semantics:
[`docs/COLLECTIONS.md`](docs/COLLECTIONS.md).

### Vaults (v0.5): several binaries, one transaction

Apps are not one file. If every patch entry names a `target`, the collection
becomes a **vault** over an application directory:

```json
{ "bundle": "main-theme.morph", "target": "app.exe",          "order": 10 }
{ "bundle": "plugin-fix.morph", "target": "plugins/scan.dll", "order": 20 }
```

```bash
surreal collection check vault/ --target "C:/Apps/BetterApp"
surreal collection apply vault/ --target "C:/Apps/BetterApp" -y
surreal revert "C:/Apps/BetterApp/plugins/scan.dll"      # undo one file
```

Each file gets its own backup and its own journal entry; if any file fails, every
file touched so far is restored. Target paths must stay inside the root (no
absolute paths, no `..`, no symlink escapes), and members must still be
size-preserving.

Patch entries can also declare `"depends_on": ["org.you.other"]` (topologically
sorted, cycles refused, and a disabled dependency blocks the dependent patch) and
`"conflicts_with": ["org.you.rival"]` (both applicable → the whole run is
refused). No scripting, no shell: ordering constraints are data too.

### Overlay size changes (v0.3)

`surreal diff` now also handles two builds whose **overlay** differs in size —
the bytes after the last section, which are not mapped into the image:

```bash
# old.exe and new.exe differ only by trailing overlay data
surreal diff old.exe new.exe -o add-config.morph --id me.add-config
#   hunks: 1   op=append   +88 bytes (overlay)
surreal apply add-config.morph --target old.exe     # file grows, checksum recomputed
surreal apply remove-config.morph --target old.exe  # op=truncate, file shrinks back
```

Size-changing bundles also refuse `--accept-drift`, because an append is only
meaningful on the exact build it was authored for.

### Local patch repos (v0.5): a curated set, one command

No network code exists in surreal (CI enforces it), so a repo is a JSON index of
bundles you already have on disk:

```bash
surreal repo index patches/ -o patches/surreal-repo.json
surreal repo list  patches/surreal-repo.json --target app.exe   # * = matches this build
surreal repo show  patches/surreal-repo.json --id org.you.dark-theme
surreal repo apply patches/surreal-repo.json --id org.you.dark-theme --target app.exe
```

The index stores each bundle's sha256, so a file edited after indexing is refused
instead of applied. Paths are relative and confined to the index (no absolute
paths, no `..`), and the index records who signed what — trust still comes from
your key store. Full details: [`docs/REPO.md`](docs/REPO.md).

### Header surgery (v0.5): growing the image on purpose

The overlay is not mapped, so growing it needs no header edits. Growing *inside*
the image does — and v0.5 does that as a separate, auditable operation rather
than a side effect:

| `op` | What it does | Header fields rewritten |
|---|---|---|
| `extend-section` | appends payload to the **last** section | its `VirtualSize`, `SizeOfRawData`, and `SizeOfImage` |
| `add-section` | appends a whole new section (needs ≥ 40 bytes of header slack) | `NumberOfSections`, new 40-byte header, `SizeOfImage` |

```bash
# old.exe → new.exe where new.exe has 60 extra bytes in .data
surreal diff old.exe new.exe -o grow.morph --id me.grow-data
#   hunks: 1   op=extend-section   section=.data   +512 bytes (padded to FileAlignment)
surreal check grow.morph --target old.exe
surreal apply grow.morph --target old.exe -y     # rewrites 3 header fields + checksum
surreal revert old.exe                           # restores the backup, size included
```

Still refused, with a message naming what moved: resizing a **non-last** section,
growing a file that already has an overlay, a last section whose raw data does not
end at EOF, an `rva` that collides with an existing section, and adding a section
when the headers are already full. There are no RVA fixups: growing the last
section moves nothing, which is exactly why it is the only resize allowed.

The safety story is a proof, not a promise:

* `surreal diff` emits a surgery hunk **only if** replaying it through the real
  applier on a temp copy reproduces the new build byte-for-byte (checksum field
  excepted). Otherwise it refuses and explains which section moved.
* After writing, the patcher re-parses the temp file and proves section count,
  `SizeOfImage`, file size, section bounds and the checksum **before** the atomic
  rename. A failed proof leaves the original untouched.
* A bundle may contain exactly one size-changing hunk, and never together with
  `--accept-drift`: these ops are positional, so identity is the whole safety net.

## Low-end by design (4 GB RAM, 2 cores, HDD)

| Concern | How |
|---|---|
| Never loads the file | `mmap` + `bytes.find` + 1 MiB IO chunks; checksum summed in 8 MiB slices |
| No pip dependencies | pure standard library → no wheels, no venv, no network at runtime |
| Small binary | PyInstaller one-file build, ~11 MB, no telemetry, no auto-update |
| Fast on old disks | one sequential read per phase; no random access storms |

Measured on a **2-core / 4 GB** container (identical workload: `tools/bench.py`):

| fixture | parse | checksum | scan | diff | apply | revert | peak RSS |
|---|---|---|---|---|---|---|---|
| 8 MiB | 0.00 s | 0.03 s | 0.00 s | 0.10 s | 0.11 s | 0.03 s | **34 MB** |
| 64 MiB | 0.00 s | 0.22 s | 0.00 s | 0.21 s | 0.82 s | 0.24 s | **89 MB** |

Peak RSS is dominated by mapped file pages the OS can reclaim; the tool's own
working set is a few MB. Reproduce with `python tools/bench.py --mb 64`.

## Legal, plainly

* Patch software **you own or are licensed to modify**. Reverse engineering for
  interoperability, security research, accessibility, translation, modding and
  repairing abandoned software is protected in many jurisdictions
  (DMCA 17 U.S.C. §1201(f); EU Directive 2009/24/EC Art. 6).
* `surreal` will **not** help you defeat licence activation, DRM, anti-cheat or
  anti-tamper. Bundles that declare such categories are refused (`exit 4`), and
  such bundles are not accepted into this project.
* **Share bundles, never patched binaries.** A `.morph` is a description; a
  patched `.exe` is redistributed copyrighted code.
* Patched binaries are unsigned: expect SmartScreen / AV friction. Keep backups.

Full policy, including the takedown process: [`docs/LEGAL.md`](docs/LEGAL.md).

## Repository map

```
PLAN.md                  design + roadmap (read this first)
surreal/                 the tool: pe.py, scanner.py, diffgen.py, patcher.py,
                         keys.py (ed25519), lock.py, reloc.py, memguard.py,
                         collection.py, testkit.py
surreal/testkit.py       synthetic PE builder + `surreal selftest`
tests/                   204 unit tests, incl. perf/RAM budget tests
tools/bench.py           low-end benchmark harness
examples/                three ready-made bundles + a collection + walkthrough
build/                   PyInstaller spec + Windows/macOS/Linux build scripts
docs/                    ARCHITECTURE · PATCH_FORMAT · SIGNING · COLLECTIONS
                         LEGAL · COMPATIBILITY
```

## Development

```bash
python run_tests.py            # 204 tests, no dependencies
python tools/bench.py          # performance budget
python -m surreal selftest     # end-to-end smoke test
```

Contributions welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). New patches
must come with a passing `surreal check` and must target software the
contributor is allowed to modify.

Release notes: [`CHANGELOG.md`](CHANGELOG.md).

## Roadmap

| Milestone | Scope |
|---|---|
| **M0 (shipped)** | PE parser, scanner, diff→bundle, apply/revert/journal, policy gate, CI, exe build |
| **M1 (shipped, v0.2)** | ed25519-signed bundles + trusted-key store, crash-safe apply lock, ASLR/relocation safety checks, `--max-mem` guard |
| **M2-lite (shipped, v0.3)** | `op: append` / `op: truncate` for overlay size changes; everything inside the image still refused |
| **M2+ (shipped, v0.5)** | `op: extend-section` / `op: add-section`: header rewriting, SizeOfImage growth, replay-proven generation, post-write proof |
| **M3-lite (shipped, v0.4)** | `surreal collection`: N size-preserving bundles applied as one transaction with a single backup |
| **M3 vault (shipped, v0.5)** | `target` per patch entry → N binaries patched as one transaction, per-file backups and journals |
| **M3 deps (shipped, v0.5)** | `depends_on` topological ordering, `conflicts_with` refusal, unique ids |
| **M4 repo (shipped, v0.5)** | `surreal repo index/list/show/apply`: local index with per-bundle integrity hashes and target matching |
| M3 | patch scripting (sandboxed, no shell) |
| M4 | `--tui` and `apply --repo` for curated bundle collections |

MIT licensed. Not affiliated with Morphe, ReVanced or any vendor whose software
you choose to patch.
