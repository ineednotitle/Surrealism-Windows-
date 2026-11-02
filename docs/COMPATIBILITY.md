# Compatibility & hardening notes

## What `surreal` understands

| Feature | Support |
|---|---|
| PE32 (x86), PE32+ (x64) | full parse, patch |
| ARM / ARM64 / IA64 | parsed, machine-checked; patching works if the bytes are reachable |
| DOS-only `.exe` | rejected (`not a PE file`) |
| .NET assemblies | parsed; `dotnet: yes` shown. Byte edits work, but metadata/RVA patching of IL is out of scope in v1 |
| DLLs, OCXs, CPL, SCR, SYS | parsed (`.exe` is just the common name; `--target` accepts any PE) |
| Files with overlay / installer payloads | parsed, overlay reported; edits inside the overlay are allowed but flagged. An overlay blocks `extend-section`/`add-section` (the image is not last in the file) |
| Authenticode-signed binaries | parsed, `authenticode: signed` shown, loud warning before write (signature becomes invalid) |
| Truncated / corrupt headers | rejected with a specific message, never "best effort" |

## Layout changes (v0.5)

| Change | Support |
|---|---|
| grow the overlay (`op: append`) | yes |
| shrink the overlay (`op: truncate`) | yes |
| grow the **last** section (`op: extend-section`) | yes — rewrites `VirtualSize`, `SizeOfRawData`, `SizeOfImage` |
| add a section at the end (`op: add-section`) | yes — needs ≥ 40 bytes of header slack |
| resize / remove a section that is not last | refused (would move every following RVA) |
| `virtual_size_after` below the current `VirtualSize` | refused (that is a shrink, not a grow) |
| any layout change with `--accept-drift` | refused |

Every layout change is proven twice: `diff` replays the hunk through the applier
and compares byte-for-byte, and the patcher re-parses the written temp file
(section count, `SizeOfImage`, file size, section bounds, checksum) before the
atomic rename.

## What the tool will not do (v1)

* Resize a section that is not the last one, insert a section in the middle,
  remove a section, rewrite relocations, or change the entry point.
* Unpack or decrypt protected images. If `.vmp0`, `.themida`, `.enigma1`,
  `UPX0/UPX1` or a >7.2 bits/byte section is detected, `inspect` tells you and
  points at the vendor's own unpacking path.
* Bypass code-signing checks, anti-cheat, anti-tamper or licence servers.
* Patch running processes (no debugger, no `WriteProcessMemory`). This is a
  static patcher on files you supply.
* Fetch anything from the network. Zero network code is present in the tool.

## Hardened-Windows reality check

| Symptom | Why | Fix |
|---|---|---|
| `PermissionError` / `WinError 32` during apply | the app is running, or AV holds the file | close the app; add an exclusion for the folder |
| Patched exe vanishes after apply | AV heuristics quarantine modified binaries | restore from `.surreal\backups`, add folder exclusion, report false positive |
| SmartScreen "unknown publisher" | Authenticode signature is void after any edit | expected; this tool does not re-sign |
| `os.replace` fails across volumes | temp file must be in the target's directory | it always is; do not move `.surreal` to another drive manually |
| Windows Defender flags `surreal.exe` | PyInstaller one-file executables look like packers | build from source, or use the `.pyz` distribution; report it upstream |

## Version drift playbook

When an app updates and a bundle stops applying, `check` tells you exactly why:

1. `size`/`sha256` differ → `exit 3` "target does not match this bundle".
2. Same build layout, moved bytes → anchors still resolve; if an `expect` byte
   changed, you get the offset, the expected bytes and the actual bytes, so you
   can re-author the hunk.
3. Section changed → warnings list which section's hash moved.
4. Anchors matched twice → the bundle's context is no longer unique; regenerate
   the bundle from the new build (`surreal diff`), which re-proves uniqueness.

Never use `--accept-drift` to force a bundle onto a build you have not inspected:
it downgrades identity checks, but the per-hunk `expect` checks still stand.
