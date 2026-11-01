# `.morph` patch bundle — format v1 (normative)

A `.morph` file is UTF-8 JSON. It is data only: no code, no shell, no URLs that
are fetched automatically. Anything a runtime does not understand is rejected
unless the user passes `--lax`.

```
top level
├── format            "surreal.morph"            (required)
├── format_version    1                          (required)
├── id                reverse-dns string         (required, e.g. com.you.tweak)
├── name              human name                 (defaults to id)
├── version           bundle version string      (default "1.0.0")
├── description, notes, author, homepage, license
├── created_utc       ISO-8601 UTC
├── tool              { "name": "surreal", "version": "0.1.0" }
├── target            identity of the authored build  (required)
├── anchors[]         named byte patterns with proven uniqueness
├── hunks[]           the actual edits                (at least one, required)
├── policy            { requires_rights_attestation, forbidden_categories[] }
└── signature         optional ed25519 block (see docs/SIGNING.md)
```

## `target`

| Field | Type | Meaning |
|---|---|---|
| `filename` | string | advisory; a mismatch is a warning, not an error |
| `size` | int | exact file size in bytes |
| `sha256` | string | hash of the authored build |
| `pe.magic` | `"0x20b"` / `"0x10b"` | PE32+ / PE32 |
| `pe.machine` | `"0x8664"`, `"0x14c"`, … | architecture |
| `pe.timestamp`, `pe.entrypoint_rva`, `pe.image_base` | int | structural identity |
| `authenticode` | bool | whether the authored build is signed |
| `sections[]` | `{name, rva, raw_size, raw_sha256}` | per-section fingerprints (warn-only) |

At apply time: `size` and `sha256` must match, otherwise the run aborts with
exit 3 unless `--accept-drift` is given. `machine` and `magic` must always match.
Moving entrypoint / differing sections produce warnings only, because that is
exactly the case anchors exist to survive.

## `anchors[]`

```json
{ "name": "anchor_0", "pattern": "50 48 8D 15 F0 E0 D0 C0",
  "unique": true, "file_offset": 577, "rva": 1025, "section": ".text",
  "comment": "8 bytes of literal context at file offset 0x241" }
```

* `pattern` — hex bytes, `??`/`?`/`*` are single-byte wildcards. At least 2 bytes.
* `unique` — the author asserts exactly one occurrence. If `true` and the runtime
  finds more than one, the apply **aborts** (it never picks "the first one").
* `file_offset`, `rva`, `section` — advisory corroboration used when a pattern is
  intentionally non-unique; also handy for debugging a shifted build.

## `hunks[]`

```json
{ "anchor": 0, "delta": 8,
  "section": ".text", "rva": 4177, "offset": 593,
  "expect": "7F", "replace": "7E",
  "comment": "bytes 593..594", "enabled": true }
```

| Field | Rules |
|---|---|
| `expect` | **required.** Original bytes; same length as `replace`; may contain `??` wildcards (those bytes are not compared). Never omit it — the loader rejects bundles without expectations, so no bundle can patch blind. |
| `replace` | **required.** Fixed bytes, no wildcards, non-empty. |
| `anchor` + `delta` | hunk starts at `anchor_match_offset + delta` |
| `section` + `rva` | hunk starts at the file offset of `rva` inside `section` |
| `offset` | absolute file offset (last resort, and for non-PE `--force` diffs) |
| `enabled` | `false` skips the hunk without editing the bundle |

### Locator resolution order

All **present** locators are resolved and must agree. If they disagree the apply
aborts: this is the check that catches a hand-edited or corrupted bundle.

```
candidates = []
if anchor != null:            candidates += anchor_offset + delta
if section && rva != null:    candidates += offset_of(section, rva)
if offset != null:            candidates += offset
if len(unique(candidates)) > 1: abort "locators disagree"
```

Then `expect` is compared against the bytes at that offset and the hunk is
applied only if every non-wildcard byte matches.

### Overlap

Resolved hunk ranges must not overlap; overlapping hunks abort the whole apply
(no partial writes, no "last one wins").

### Size changes

`len(expect) == len(replace)` is enforced by the loader. Format v1 is
**size-preserving by design**: writing into a PE can grow sections or the code
cave, but that changes the image, the section table and every RVA after it —
that is M2 work with its own explicit opt-in flag.

## `policy`

```json
{ "requires_rights_attestation": true,
  "forbidden_categories": ["drm", "license-bypass", "activation",
                           "anti-cheat", "anti-tamper", "trial-reset"] }
```

`forbidden_categories` is a **self-declaration**; if it names a prohibited
category, `apply` refuses with exit 4. The CLI also refuses bundles whose
id/name/description advertise keygens, cracks or activation bypasses. This is a
guardrail against this project being used as a piracy tool — the project will
not host or accept such bundles.

## `signature` (optional, additive within v1)

```json
"signature": {
  "alg": "ed25519",
  "public_key": "4f1c…c9",
  "signature": "…128 hex chars…",
  "signed_utc": "2026-11-01T00:00:00Z",
  "signer": "my handle",
  "payload_sha256": "…"
}
```

Rules:

* The signed payload is the **canonical JSON of the bundle with the `signature`
  key removed** (sorted keys, no whitespace, UTF-8). Adding, changing or
  removing a signature therefore never invalidates a *different* signature.
* `alg` must be `"ed25519"`; anything else is rejected outright.
* An invalid signature is **always** fatal (exit 4). An unsigned or untrusted
  bundle is a warning unless the user passes `--require-signature`.
* The signature says nothing about legality or safety — see
  [`SIGNING.md`](SIGNING.md) for the exact threat model.

## Canonical example (complete, 2 hunks)

```json
{
  "format": "surreal.morph",
  "format_version": 1,
  "id": "org.surreal.demo.shorten-nag",
  "name": "Demo: blank the trial nag + flip one branch",
  "version": "1.0.0",
  "created_utc": "2026-11-01T00:00:00Z",
  "tool": { "name": "surreal", "version": "0.1.0" },
  "target": {
    "filename": "demo_app.exe",
    "size": 2048,
    "sha256": "4d51cec411ac4bf2856d007044be52d8da0713e4abe227f02244193c66251408",
    "pe": {
      "magic": "0x20B", "machine": "0x8664", "timestamp": 1593835520,
      "entrypoint_rva": 4096, "image_base": 5368709120
    },
    "authenticode": false,
    "sections": [
      { "name": ".text", "rva": 4096, "raw_size": 512,
        "raw_sha256": "b8649f444afc99b4…" }
    ]
  },
  "anchors": [
    { "name": "anchor_0", "pattern": "50 48 8D 15 F0 E0 D0 C0",
      "unique": true, "file_offset": 577, "rva": 1025, "section": ".text" },
    { "name": "anchor_1", "pattern": "BF BD 20 64 65 6D 6F 00",
      "unique": true, "file_offset": 1089, "rva": 2049, "section": ".rdata" }
  ],
  "hunks": [
    { "anchor": 0, "delta": 8, "section": ".text", "rva": 4177,
      "offset": 593, "expect": "7F", "replace": "7E" },
    { "anchor": 1, "delta": 8, "section": ".rdata", "rva": 2089,
      "offset": 1097,
      "expect": "54 72 69 61 6C 20 65 78 70 69 72 65 64 2E 20 41 63 74 69 76 61 74 65 20 74 6F 20 63 6F 6E 74 69 6E 75 65 2E 00",
      "replace": "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" }
  ],
  "policy": { "requires_rights_attestation": true, "forbidden_categories": [] }
}
```

(`examples/demo-shorten-nag.morph` is this file, generated by `surreal demo`.)

## Versioning

* `format_version` is an integer. A newer `format_version` is refused, never
  guessed at.
* Additive fields are allowed within v1 only if listed above; anything else is an
  "unknown key" error unless `--lax`. That is deliberate: silently ignoring
  fields would let a bundle claim one thing and do another.
