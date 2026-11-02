# Legal & acceptable use

`surreal` is a byte-level patch engine. It is not a crack, a keygen, a licence
bypass or a DRM circumvention tool, and this project will not host, merge or
distribute bundles that function as one. What follows is the policy this project
enforces in code, plus the reasoning behind it. **It is not legal advice.**

## What you are allowed to do with it

Reverse engineering and modification are lawful in many jurisdictions when you
have the right to work on the software. Examples this project supports:

* **Your own software**, or internal tooling you maintain.
* **Open-source software**, where you comply with its licence.
* **Interoperability / compatibility work** — making software talk to a protocol,
  file format or service it was not originally designed for
  (EU Directive 2009/24/EC Art. 6; U.S. DMCA §1201(f) for reverse engineering for
  interoperability).
* **Security research** on software you own or are authorised to test.
* **Accessibility, translation and localisation** fixes.
* **Modifying software with modding provisions** in its EULA/ToS.
* **Repairing abandoned or unmaintained software** on hardware you own.
* **CTF, malware analysis and training fixtures** in a sandbox.

Your jurisdiction, your contract (EULA/ToS) and your employer's policy all still
apply. If they forbid modification, they win.

## What this project will not help with

* Defeating **licence activation, serial checks, paywalls, DRM, anti-cheat or
  anti-tamper** mechanisms. These are the categories the code refuses
  (`policy.forbidden_categories`, exit code 4), and PRs containing them are
  rejected without discussion.
* Circumventing **technical protection measures** — in the EU this is separately
  unlawful under Directive 2001/29/EC Art. 6, and in the U.S. under DMCA §1201
  (with narrow exceptions that generally do not cover "make the trial unlimited").
* **Redistributing patched executables.** A `.morph` bundle is a description of
  edits; a patched `.exe` is someone's copyrighted binary with modifications.
  Share bundles. Never ship patched third-party binaries, and never ship a
  patcher plus a target.
* Anything on a system you do not own or are not authorised to test.
* "Unlocking" features behind a payment you have not made.

## Responsibilities the tool puts on you

1. **You acknowledge the policy once** (`surreal init --accept-policy`) before the
   first write. The acknowledgement is stored in `%APPDATA%\surreal\`.
2. **You keep backups.** `surreal` makes one automatically and can `revert`, but a
   patched binary is your responsibility after it lands.
3. **You accept unsigned output.** Any Authenticode signature is invalidated by
   the first byte you change. Windows may warn; some anti-cheat and some
   enterprise policies will refuse to run modified binaries.
4. **You verify before you run.** `surreal check` and `--dry-run` exist so that
   *nothing* is written until every hunk's expected bytes have matched.

## Signature, integrity and trust

`.morph` bundles are plain JSON: read them before applying them, exactly as you
would read a shell script. v1 has no cryptographic signature; M1 adds optional
ed25519 signing plus a `--require-signature` mode for curated collections.
`apply --accept-drift` weakens identity checks (size/hash) but never skips
per-hunk byte verification.

## Reporting and takedown

If you believe content in this repository infringes your rights, or that a
bundled example crosses the line above, open an issue titled `[takedown]` or
contact the maintainer via the repository's profile. Please include the bundle
id, the target software and the right you assert. Verified reports get the
bundle removed from the repo history view and added to a refusal list; the tool
itself contains no vendor-specific data, so no functionality is lost.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The authors are
not liable for damage, data loss, account bans, or legal consequences arising
from use. You are the one deciding which file to modify and which edit to apply.
