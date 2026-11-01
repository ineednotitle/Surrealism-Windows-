# Surrealism Window — Project & Engineering Plan

> **Surrealism Window** (`surreal`) — a Morphe-style, CLI-first patcher for Windows
> PE binaries: inspect an `.exe`, find the bytes that matter, generate a patch
> bundle from a before/after pair, and re-apply that bundle to *your own* copy of
> the app — deterministically, reversibly, and on 4 GB of RAM.

Status: plan v1 · Target platform: Windows 10/11 x86 & x64 (runs on any OS for
analysis) · License: MIT · Language: Python 3.9+ (stdlib only) → frozen to a
single `surreal.exe`.

---

## 1. What Morphe-style patchers actually do (and what we will do)

A Morphe/ReVanced-style tool is *not* a cracker. It is a **reproducible
byte-level modification pipeline** with three parts:

| Stage | Morphe equivalent | Surrealism Window |
|---|---|---|
| **Understand** | patch developer reads the app's code | `surreal inspect`, `surreal scan`, `surreal disasm` |
| **Describe** | patches are shipped as declarative bundles | `.morph` JSON bundles: metadata + anchors + byte hunks |
| **Apply** | the patcher verifies the target, patches, signs | `surreal apply` → preflight, backup, patch, checksum, journal, `revert` |

The key insight that makes such a tool *safe* and *maintainable* is that **the
patch never hard-codes a raw file offset**. It describes *what to look for*
(anchors / section-relative RVAs) and *what to change* (byte hunks with expected
original bytes). That is what allows a patch to survive small rebuilds of the
app instead of silently corrupting it.

### Design principles

1. **Declarative, reproducer-first patches.** A `.morph` bundle is text, diffable
   and reviewable in a PR. No opaque blobs, no "run this script as admin".
2. **Never patch blind.** Every hunk must be *located* (anchor / RVA / offset)
   and *verified* (expected original bytes) before anything is written.
3. **Never patch destructively.** Backup + atomic replace + journal + `revert`.
4. **Fail closed.** Ambiguous anchor → abort. Hash drift without
   `--accept-drift` → abort. Signature invalidated → loud warning *before* write.
5. **Low-end first.** 4 GB RAM / 2-core / HDD budget is a hard constraint, not
   an afterthought (§4).
6. **Legal by construction.** Only in-place byte edits to files the user
   legitimately possesses; no DRM/licence-check bypass recipes shipped, no
   redistribution of patched binaries (`docs/LEGAL.md`).

### Non-goals (v1)

- No unpacking/decrypting of protected binaries (`UPX -d` etc. stays an external
  tool; we detect and tell you).
- No code-signing bypass, no anti-cheat evasion, no licence-server spoofing.
- No Android/APK patching (that is Morphe's domain, not ours).
- No GUI. CLI only, plus machine-readable `--json` output for scripting.

---

## 2. Architecture

```
┌──────────────────────── surreal.exe (single file, ~11 MB, no deps) ─┐
│  cli.py      argparse front-end, --json everywhere, exit codes      │
│  pe.py       PE32/PE32+ parser: headers, sections, data dirs,        │
│              imports/exports, entropy, Authenticode presence,       │
│              overlay, checksum compute/verify, RVA ↔ file offset    │
│  scanner.py  wildcard byte-pattern search (48 8B ?? E8), string     │
│              search (ASCII + UTF-16LE), longest-literal needle      │
│              prefilter + chunked mmap window                        │
│  patchfile.py .morph schema load/validate/save, canonical JSON      │
│  diffgen.py  before/after → hunks: streaming compare, range merge,  │
│              automatic anchor selection with uniqueness proof       │
│  patcher.py  resolve → verify → backup → atomic write → checksum →  │
│              journal; dry-run, revert                               │
│  journal.py  per-directory .surreal/journal.json + backups/         │
│  policy.py   rights attestation gate (init --accept-policy)         │
└─────────────────────────────────────────────────────────────────────┘
```

### Commands

```
surreal init                       accept the usage policy (one time)
surreal inspect  app.exe [--json] [--imports] [--strings N]
surreal scan     app.exe --pattern "48 8B ?? E8"   [--context 16] [--json]
surreal scan     app.exe --string "Trial expired"  [--utf16]
surreal diff     old.exe new.exe -o tweak.morph --id me.tweak --name "…"
surreal info     tweak.morph
surreal check    tweak.morph --target app.exe          # preflight only
surreal apply    tweak.morph --target app.exe [--dry-run] [--no-backup]
surreal revert   app.exe [--list]
surreal disasm   app.exe --at rva:0x1234               # optional, uses objdump/rizin
```

Exit codes: `0` ok · `2` usage · `3` target mismatch / unfindable anchor ·
`4` policy not accepted · `5` write/IO error.

---

## 3. How a patch is created (the important part)

### 3.1 Developer workflow

```
1. surreal inspect app.exe
      → PE32+ x64, .text 0x1F000 bytes, no Authenticode, checksum OK
2. surreal scan app.exe --string "Trial expired" --context 24
      → 1 hit: file 0x1A2C4 / rva 0x1A6C4 / .text+0x9A6C4
3. Reverse the hit in your own tooling (x64dbg, Ghidra, rizin, objdump).
      Circle the smallest edit that changes behaviour *for files you own*.
4. Create the patched copy the same way you'd create any fixture
      (build from source, use the app's supported mod/plugin system,
       or apply an edit you have the legal right to make).
5. surreal diff app.exe app-patched.exe -o tweak.morph \
        --id com.you.tweak --name "Shorter trial banner"
6. surreal check tweak.morph --target app.exe      # must be green
7. Commit tweak.morph, open a PR. Reviewers read JSON, not binaries.
```

`diff` does the hard part automatically:

1. **Streaming compare** in 1 MiB chunks (constant memory) → list of differing
   `[start, end)` ranges; ranges closer than `--merge-gap` (default 16 bytes)
   are coalesced so a 4-byte constant edit yields *one* hunk, not four.
2. **Location proof** for every hunk, in this preference order:
   - **Anchor**: up to 64 bytes of literal context immediately before the hunk.
     The generator shrinks it to the shortest context that occurs **exactly
     once** in the whole binary (verified by a full scan, not by hope). Stored as
     `pattern` + `delta`.
   - **Section + RVA** (`".text" + 0x9A6C4`): survives file-layout shifts when
     the code is byte-identical but section padding moved.
   - **Raw file offset**: last resort, only for files that are byte-exact.
3. **Expectation capture**: original bytes (`expect`) recorded verbatim, so
   `apply` can refuse a hunk that no longer looks like what the author tested.
4. **Identity capture**: target filename, size, SHA-256, machine, timestamp,
   entrypoint RVA, image base, per-section fingerprints, Authenticode state.
5. **Same-size enforcement**: v1 refuses size-changing diffs (exit 3 with a
   clear message). Adding sections / resizing the image is v2 work — pretending
   to support it in v1 is how you ship corrupted executables.

### 3.2 Bundle format (`.morph`, JSON, canonical/stable ordering)

```json
{
  "format": "surreal.morph", "format_version": 1,
  "id": "com.you.tweak", "name": "Shorter trial banner",
  "description": "Replace the 12-byte nag string with a blank one.",
  "created_utc": "2026-11-01T00:00:00Z",
  "author": "you",
  "tool": { "name": "surreal", "version": "0.1.0" },
  "target": {
    "filename": "app.exe", "size": 233472, "sha256": "…",
    "pe": { "machine": "0x8664", "magic": "0x20b", "timestamp": 1700000000,
            "entrypoint_rva": 4096, "image_base": 5368709120 },
    "authenticode": false,
    "sections": [ { "name": ".text", "rva": 4096, "raw_size": 126976,
                    "raw_sha256": "…" } ]
  },
  "anchors": [ { "name": "banner", "pattern": "E8 ?? ?? ?? ?? 48 8D 15",
                 "file_offset": 110276, "unique": true } ],
  "hunks": [
    { "anchor": 0, "delta": 5, "section": ".text", "rva": 110281,
      "offset": 110276,
      "expect": "54 72 69 61 6C 20 65 78 70 69 72 65 64",
      "replace": "00 00 00 00 00 00 00 00 00 00 00 00 00",
      "comment": "blank the nag string in-place" }
  ],
  "policy": { "requires_rights_attestation": true }
}
```

Rules enforced by `patchfile.py`:
- `replace` is fixed bytes; `expect` may contain `??` wildcards;
  `len(expect) == len(replace)` — no implicit resizing.
- hunk address is **unioned**: anchor+delta, section+rva and offset must all
  agree when present (that disagreement check catches a mis-edited bundle).
- Unknown top-level keys are rejected in `--strict` mode so bundles can't smuggle
  behaviour the tool doesn't understand.

### 3.3 Patch application algorithm

```
load bundle → policy gate → open target (mmap, read-only)
  → identity: size, sha256 (or --accept-drift), PE machine/magic
  → resolve each anchor (exactly-once proof per anchor)
  → resolve each hunk address (anchor ▸ section+rva ▸ offset, all must agree)
  → verify each hunk's `expect` against the bytes on disk
  → detect overlap between hunks (abort)
  → checksum/signature preflight (Authenticode present ⇒ warn: signature dies)
  → backup original to .surreal/backups/<ts>/ (unless --no-backup)
  → copy to app.exe.surreal.tmp in the same directory
  → seek+write each hunk into the copy  (O(hunk) memory, never O(file))
  → recompute PE checksum (unless --no-checksum)
  → fsync, os.replace(tmp → app.exe)      ← atomic on NTFS
  → journal entry {bundle id, sha256 before/after, backup path, timestamp}
```

Early-exit conditions, all before any byte is written:
`unresolved anchor`, `anchor not unique`, `expect mismatch`, `overlapping hunks`,
`RVA outside section`, `size changed`, `not a PE`, `sha256 mismatch`
(unless `--accept-drift`), `policy not accepted`.

### 3.4 Revert

`surreal revert app.exe` restores the most recent backup for that path from the
journal and appends a `revert` record (revert of a revert re-applies the backup
chain in reverse). Backups are deleted only by `--prune-backups`.

---

## 4. Low-end budget (4 GB RAM, 2 cores, HDD, no AV exclusions)

| Concern | Decision |
|---|---|
| Never load the file | `mmap` the target read-only; scan/copy by offsets. Peak RSS is bounded by *hunk size + 1 MiB IO buffer*, not file size. |
| Hashing | streamed 1 MiB chunks; 50 MB binary ≈ 0.2 s. |
| Pattern search | longest-literal needle + `bytes.find` (C-speed) then wildcard verify; 50 MB scan ≈ 0.1–0.4 s. |
| Diff | two streaming passes, ranges only; a 50 MB pair peaks under ~40 MB RSS. |
| `--max-mem` guard | default 256 MB; refuses "read it all" fallbacks above it instead of swapping a 4 GB box (M1 — measured peaks are far below it today). |
| Binary size | PyInstaller onefile, `--exclude-module` everything optional → ~10–12 MB, ~25 MB RSS idle. |
| Startup | no network, no telemetry, no first-run index. < 400 ms cold start. |
| Disk | backups are the only growth: one copy per patched file, journal is text. |
| Anti-virus | we modify `.exe` files, so we document exclusions; we never hide, pack or unpack, and never touch signed system binaries. |

Measured targets (CI-enforced by `tests/test_perf.py`, generous ceilings so the
suite is stable): inspect 50 MB PE < 3 s, single-pattern scan < 4 s, apply of a
10-hunk bundle < 2 s, peak RSS < 128 MB.

**Actual measurements on the 2-core / 4 GB development container** (`tools/bench.py`):

| fixture | parse | checksum | scan | diff | apply | revert | peak RSS |
|---|---|---|---|---|---|---|---|
| 8 MiB | 0.00 s | 0.03 s | 0.00 s | 0.10 s | 0.11 s | 0.03 s | 34 MB |
| 64 MiB | 0.00 s | 0.22 s | 0.00 s | 0.21 s | 0.82 s | 0.24 s | 89 MB |

Peak RSS is mostly reclaimable mapped file pages. One real optimisation found
during implementation: the naive per-word Python checksum loop took **4.0 s** on
50 MB; the `array('H')` + `sum()` version over 8 MiB slices takes **0.17 s** and
is cross-checked against a literal transcription of Microsoft's algorithm in
`tests/test_pe.py`.

---

## 5. Legal & ethical scope

Full text in `docs/LEGAL.md`. Summary of what ships and what does not:

**In scope (legitimate reverse engineering / interoperability):**
- Analysis and modification of binaries the user owns or is licensed to modify
  (own software, open-source software, games with modding provisions, security
  research sandboxes, CTF/AV/malware-analysis fixtures).
- Interoperability and compatibility patches; accessibility tweaks; translation
  and string edits; bug workarounds for abandoned software (DMCA §1201(f) /
  EU Directive 2009/24/EC Art. 6 reasoning).
- Documenting *how* to patch, not *what* to pirate: every example bundle is
  generated against a binary we build ourselves in the test suite.

**Out of scope (blocked by policy, not shipped):**
- Bundles that defeat licence activation, DRM, anti-cheat, or trial timers.
  `apply` refuses to run on bundles whose `policy.forbidden_categories` is set,
  and the project will not accept such bundles upstream.
- Redistributing patched copies of third-party binaries (bundles only, never the
  patched app).
- Anything on a machine you do not own or are not authorised to test.

The tool itself performs no circumvention: it applies byte edits that a human
decided on for a file the human supplied. The responsibility for *which* edit is
the patch author's and the user's — stated plainly in the README, in `--help`,
and behind the `init --accept-policy` gate.

---

## 6. Repo layout

```
PLAN.md                    this document
README.md                  quick start, screenshots of output, install
docs/ARCHITECTURE.md       module map, invariants, exit codes
docs/PATCH_FORMAT.md       normative .morph spec + worked example
docs/LEGAL.md              policy, permitted/prohibited, takedown process
docs/COMPATIBILITY.md      which binaries, which PE features, hardening
surreal/                   stdlib-only package (the CLI)
tests/                     unittest suite + synthetic PE builder fixtures
examples/                  two reviewed example bundles (built from tests/)
build/surreal.spec         PyInstaller spec → surreal.exe
build/build_windows.ps1    one-liner Windows build
.github/workflows/ci.yml   tests on win+linux, exe artifact, release on tag
.gitignore
```

## 6b. What M0 actually shipped (status)

Everything in §6 exists except where noted, and the test suite (103 tests,
stdlib `unittest`) plus `surreal selftest` cover the pipeline end to end on
generated PE images — no third-party binaries anywhere in the repo.

```
surreal init | inspect | scan | diff | info | check | apply | revert | demo | selftest
```

* `diff` proves anchor uniqueness by full-file scan, records section+RVA and
  offset as corroborating locators, and drops PE-checksum noise from the diff.
* `apply` refuses to write until identity, anchors, expectations, overlaps and
  the predicted checksum all check out; then backup → temp copy → fsync →
  `os.replace` → journal.
* `revert` restores from the journal and refuses if the file changed since.
* Policy gate: `init --accept-policy` is required for any write; bundles that
  declare prohibited categories are refused with exit 4.
* CI: tests on Windows/Linux/macOS × py3.9/3.12, a "no network / no subprocess"
  source grep, PyInstaller build of `surreal.exe`, artifact + release upload.

Deliberately deferred to later milestones: `--max-mem`, ed25519 bundle
signatures, size-changing patches, multi-file vaults, TUI, repo client.

## 7. Milestones

| M | Scope | Done when |
|---|---|---|
| **M0 (this PR)** | plan, PE parser, scanner, diff→bundle, apply/revert/journal, policy gate, docs, CI, exe build | `python -m unittest` green on Windows & Linux; a bundle round-trips on a synthetic PE |
| M1 | section-aware diffs, reloc-aware wildcards, `.morph` signature (ed25519 via `cryptography` optional) | bundles are tamper-evident |
| M2 | size-changing patches (append section, extend overlay), manifest/vault for multi-file apps | patch a 3-file app atomically |
| M3 | optional patch scripting (sandboxed, no shell), patch dependencies/conflicts | community patch repo works |
| M4 | TUI (`--tui`) + patch repository client (`apply --repo repo.json`) | one-command "apply all trusted bundles" |

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Patch corrupts a binary | expect-bytes verification, atomic replace, backup, `revert`, dry-run |
| Anchor silently matches wrong place | prove uniqueness with a full-file scan; abort otherwise |
| Antivirus quarantine | documented exclusions; we never obfuscate the tool |
| Target updated upstream | sha256 drift gate + `--accept-drift` + section/RVA fallback |
| Misuse for piracy | policy gate, forbidden-category field, no such bundles upstream, clear docs |
| 4 GB box OOM | mmap + streaming + `--max-mem` guard, enforced by perf tests |

---

*Plan ends. Implementation of M0 follows in this branch.*
