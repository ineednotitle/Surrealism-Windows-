# Conditional patches: `requires` and `when`

A `.morph` bundle is data. It is never code: `surreal` has no `eval`, no shell, no
plugin DLL, and a CI rule fails the build if anything under `surreal/` starts a
process. What a bundle *can* do is describe the build it expects, and make its own
hunks conditional on facts it reads back from the image. That covers the useful
80% of "patch scripting" — *"apply this only if that text is still there"* —
without giving a downloaded JSON file a way to run anything.

Two places accept conditions:

| Field | Where | Effect |
|---|---|---|
| `requires` | bundle root | must **all** hold, or the bundle is refused before a byte is written (exit 3) |
| `when` | any hunk | that hunk is skipped (with a note) when it does not hold |

```json
{
  "format": "surreal.morph", "format_version": 1,
  "id": "com.you.quiet-nag", "name": "Quiet the nag",
  "target": {"filename": "app.exe", "size": 2048},
  "requires": [
    {"machine": "x64", "comment": "authored on the 64-bit build"},
    {"section": ".rdata"},
    {"string": "Version 1.0.0"}
  ],
  "hunks": [
    {"offset": 593, "expect": "7F", "replace": "7E"},
    {"offset": 1097, "expect": "54 72 69 61 6C", "replace": "00 00 00 00 00",
     "when": {"string": "Trial expired."}}
  ]
}
```

Author it without hand-editing JSON:

```
surreal diff old.exe new.exe -o quiet.morph --id com.you.quiet-nag \
    --requires-machine --requires-section .rdata --requires-string "Version 1.0.0"
```

## The vocabulary

Every condition is a JSON object with exactly one of these keys.

### Logic

| Condition | Meaning |
|---|---|
| `{"all": [c1, c2, …]}` | every child holds |
| `{"any": [c1, c2, …]}` | at least one child holds |
| `{"not": c}` | the child does not hold |

### Image facts

| Condition | Example | Meaning |
|---|---|---|
| `machine` | `{"machine": "x64"}`, `{"machine": ["x86", "x64"]}` | PE machine type (`x86`, `x64`, `arm`, `arm64`, case-insensitive) |
| `is_dotnet` | `{"is_dotnet": true}` | the CLR data directory is populated |
| `is_dll` | `{"is_dll": false}` | the image is (not) a DLL |
| `has_overlay` | `{"has_overlay": false}` | bytes exist after the last section |
| `has_signature` | `{"has_signature": true}` | an Authenticode directory is present |
| `section` | `{"section": ".vmp0", "exists": false}` | a section with that name (does not) exist |
| `section_is_executable` | `{"section_is_executable": ".text"}` | the section is marked executable |

### Content

| Condition | Example | Meaning |
|---|---|---|
| `string` | `{"string": "Trial expired."}` | the bytes occur in the file (exact, case-sensitive) |
| `utf16` | `{"utf16": "Trial expired."}` | the UTF-16LE encoding occurs in the file |
| `pattern` | `{"pattern": "48 8B ?? E8"}` | the hex pattern (with `??` wildcards) matches |
| `size_at_least` / `size_at_most` | `{"size_at_least": 1024}` | file size bounds, in bytes |

Every condition may carry a `"comment"` string, which is shown in `surreal info`
and in the refusal message.

## What happens when a condition fails

**`requires` fails** — nothing is written and the exit code is `3`:

```
  XX this patch does not fit this build: the image is x86, not x64 (needs machine is x64)
```

`surreal check`, `apply`, `collection`, `repo apply`, `tui` and easy mode all go
through the same planner, so the refusal is identical everywhere, and
`check --json` returns the per-condition result under `plan.requires`:

```json
"requires": [
  {"condition": "machine is x64", "holds": true,  "detail": "machine matches",   "comment": "…"},
  {"condition": "section .rdata exists", "holds": true, "detail": "section .rdata exists", "comment": ""}
]
```

**`when` fails** — the hunk is skipped and said so:

```
  note   hunk 1 skipped: the text "Trial expired." is present ("Trial expired." was not found)
```

If *every* hunk is skipped, that is an error, not a silent no-op:

```
  XX none of 2 hunk(s) apply to this build: hunk 0 needs …; hunk 1 needs …
```

because a patch that quietly does nothing is worse than one that refuses.

## Design rules (why it is safe)

* **No code.** Conditions are JSON objects; the evaluator is a small, auditable
  `if/else` chain in `surreal/script.py`.
* **Bounded.** At most 32 nodes per condition tree, 64 entries per `all`/`any`,
  4096 characters per search string, and a fixed nesting limit. A hostile bundle
  cannot turn `check` into a denial of service.
* **Read-only.** Conditions see the parsed image and its bytes; they cannot name
  another file, a path, an environment variable or a network host.
* **Fail closed.** On a non-PE target (raw-offset bundles) a condition that needs
  image structure cannot be proven, so it fails rather than being skipped.
* **Signed over.** Conditions are part of the bundle, so an ed25519 signature
  covers them: nobody can add or relax a `when` without invalidating the
  signature.

## Worked example

`examples/demo-conditional.morph` is the same edit as the demo patch, plus:

```
  requires: machine is x64 · section .rdata exists · the text "Version 1.0.0" is present
  hunk 1:   only if the text "Trial expired." is present
```

Try it against the generated demo app and against a build that lacks the text:

```
surreal demo --out demo
surreal info    examples/demo-conditional.morph
surreal check   examples/demo-conditional.morph --target demo/demo_app.exe --accept-drift
```

## Not included, on purpose

No loops, no arithmetic, no variables, no string manipulation, no "run this if
that section's entropy is above X". Anything that needs computation belongs in the
person authoring the patch (run `diff` again for the new build), not in a file
someone downloads and applies. Mid-image section moves and relocation rewriting are
out of scope for the same reason: they need a linker, and half a linker corrupts
binaries.
