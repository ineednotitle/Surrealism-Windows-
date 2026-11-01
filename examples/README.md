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

## Adding your own

1. `surreal diff old.exe fixed.exe -o my-patch.morph --id com.you.name`
2. `surreal check my-patch.morph --target old.exe` → must be green
3. Commit the `.morph`. **Never** commit the patched binary.
4. Make sure you have the right to modify that software (`docs/LEGAL.md`).
