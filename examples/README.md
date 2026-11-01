# Examples

## `demo-shorten-nag.morph`

A complete, working bundle — regenerated reproducibly by
`python tools/make_examples.py`. It targets `demo_app.exe`, the synthetic PE that
`surreal demo` writes, so it is safe to apply and involves no third-party binary.

Two hunks, both size-preserving:

| # | Where | Change | Why it demonstrates |
|---|---|---|---|
| 0 | `.text` | `7F` → `7E` (invert a conditional jump) | a one-byte code edit that must be anchored, not hand-offsetted |
| 1 | `.rdata` | 37-byte nag string → zeroes | a longer edit; anchor + expect-bytes still protect it |

```bash
python -m surreal demo --out /tmp/demo        # writes demo_app.exe
python -m surreal info  examples/demo-shorten-nag.morph
python -m surreal check examples/demo-shorten-nag.morph --target /tmp/demo/demo_app.exe
python -m surreal init --accept-policy
python -m surreal apply examples/demo-shorten-nag.morph --target /tmp/demo/demo_app.exe -y
python -m surreal revert /tmp/demo/demo_app.exe
```

Read the JSON before you run anything — that is the point of the format. Note how
each hunk carries an `anchor`, a corroborating `section`+`rva`, a raw `offset`,
the exact `expect` bytes and the `replace` bytes: four independent witnesses to
the same edit, all of which must agree.

## `demo-append-overlay.morph`

A size-changing bundle: it appends 88 bytes of overlay after the last section
(`op: "append"`). Overlay growth is the only size change that needs no header,
section-table or RVA edits. Its inverse (`op: "truncate"`) removes the same bytes
again — build it with `surreal diff grown.exe demo_app.exe -o remove.morph`.

## `demo-extend-section.morph`

A layout-changing bundle: it appends 60 bytes to the last section (`.data`) and
rewrites that section's `VirtualSize`/`SizeOfRawData` plus the image's
`SizeOfImage`. The file grows by one `FileAlignment` unit (512 bytes) because
section raw data is always mapped in whole pages.

```bash
python -m surreal demo --out /tmp/demo
python -m surreal check examples/demo-extend-section.morph --target /tmp/demo/demo_app.exe
python -m surreal init --accept-policy
python -m surreal apply examples/demo-extend-section.morph --target /tmp/demo/demo_app.exe -y
python -m surreal inspect /tmp/demo/demo_app.exe     # .data raw size 0x200 → 0x400
python -m surreal revert /tmp/demo/demo_app.exe      # size restored too
```

Only the **last** section can be grown this way, which is why no RVA fixups are
needed: nothing after it moves. A bundle may contain exactly one size/layout
hunk and refuses `--accept-drift`. `op: "add-section"` is the same machinery with
a new 40-byte section header instead of a resize — it needs free space before the
first section's raw data (see `docs/PATCH_FORMAT.md`).

## `surreal-collection.json`

A two-patch transaction over the same generated app:

```bash
python -m surreal demo --out /tmp/demo
python -m surreal collection check examples --target /tmp/demo/demo_app.exe
python -m surreal init --accept-policy
python -m surreal collection apply examples --target /tmp/demo/demo_app.exe -y
python -m surreal revert /tmp/demo/demo_app.exe
```

Collections refuse size-changing members (see `docs/COLLECTIONS.md`), which is
why neither the overlay example nor the surgery example is part of the set.

## Adding your own

1. `surreal diff old.exe fixed.exe -o my-patch.morph --id com.you.name`
2. `surreal check my-patch.morph --target old.exe` → must be green
3. Commit the `.morph`. **Never** commit the patched binary.
4. Make sure you have the right to modify that software (`docs/LEGAL.md`).
