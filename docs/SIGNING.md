# Signing bundles & the trust store

A `.morph` bundle is a set of instructions for changing an executable. Signing
makes those instructions **attributable and tamper-evident**: anyone can check
who wrote a bundle and whether it changed after signing.

## What signing proves (and what it does not)

| Proves | Does not prove |
|---|---|
| The bundle was signed by the holder of a specific private key | That the edits are legal in your jurisdiction |
| The bundle content has not changed since it was signed | That the target binary is what the author thinks it is |
| Who to blame / thank when a bundle misbehaves | That the key has not been stolen |

The signature covers the **canonical JSON** of the whole bundle (all keys except
`signature` itself, sorted, no whitespace), so any edit — a single byte in
`replace`, an added hunk, a changed target hash — invalidates it.

## Algorithm

ed25519 (RFC 8032), implemented in `surreal/keys.py` in pure Python, validated
against the RFC's published test vectors in `tests/test_keys.py`. Verification
costs ~5 ms; no `cryptography`/`nacl` dependency, so the frozen `surreal.exe`
stays a single file.

Signature is malleability-checked: `S < L` is enforced, so the classic
"S + group order" forgery variant is rejected (there is a test for it).

## Workflow for a patch author

```bash
# once: create a key pair (private seed stays on your machine)
surreal keys --generate publisher.key --label "my handle"

# for every release of your bundle
surreal sign my-patch.morph --key publisher.key --signer "my handle"

# publish only the public key, e.g. in your README:
#   public key: 4f1c…c9
```

Never commit `publisher.key`. `.gitignore` already covers `*.key`; treat a leaked
key like a leaked password (rotate it and tell your users).

## Workflow for a user

```bash
surreal verify  my-patch.morph                  # what does the signature say?
surreal keys    --trust 4f1c…c9 --label "my handle"
surreal verify  my-patch.morph --require        # now it must be trusted
surreal apply   my-patch.morph --target app.exe --require-signature
```

`--trusted-key HEX` admits a key for a single run without touching the store, so
CI can verify without persisting anything.

## States reported by `surreal verify` / `surreal apply`

| State | Meaning | Default behaviour |
|---|---|---|
| `unsigned` | no `signature` block | warning; blocked only with `--require-signature` |
| `valid` | signature verifies **and** the key is trusted | proceeds |
| `untrusted` | signature verifies but the key is unknown to you | warning; blocked with `--require-signature` |
| invalid | signature present but does not match | **always** fatal, exit 4 |

Trust store location: `%APPDATA%\surreal\trusted_keys.json` (Windows) or
`$XDG_CONFIG_HOME/surreal/trusted_keys.json` (POSIX). It is plain JSON — audit
it, edit it, delete it:

```json
{
  "format": "surreal.trust",
  "keys": [
    { "public_key": "4f1c…c9", "label": "my handle",
      "added_utc": "2026-11-01T00:00:00Z" }
  ]
}
```

## Reproducible authority (recommended for shared bundle repos)

Pin the keys you accept so a stale checkout cannot slip an unsigned bundle in:

```bash
surreal verify patches/*.morph --require          # in CI
surreal apply  patches/all.morph --target app.exe --require-signature
```

If you run a curated collection, publish `trusted_keys.json` in your repo and
tell users to copy it into their config directory — that is the entire "CA"
model: explicit, local, auditable, no network.

## Threat model, stated plainly

* **Constrained by the tool, not by the signature.** A signed bundle can still
  name a target hash that does not match your file (`apply` refuses), still be
  policy-blocked (exit 4), and still be un-applicable if a hunk's `expect` bytes
  are absent.
* **Not defended against:** a compromised signer machine, a stolen key, or a
  user who trusts a key without reading what it signs. Signing is attribution,
  not a safety guarantee.
* **No revocation list, no network, ever.** Removing a key from your trust store
  is the only revocation mechanism in v1, and that is deliberate: no phone-home.
