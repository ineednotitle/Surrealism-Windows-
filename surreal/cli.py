"""Command line interface for ``surreal`` (Surrealism Window).

Exit codes
----------
0  success
2  usage / bad arguments
3  target mismatch, unresolved anchor, expect-byte mismatch
4  usage policy not accepted, or bundle policy-blocked
5  IO / write failure
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import time
from typing import Any, Dict, List, Optional

from . import FORMAT_NAME, TOOL_NAME, __version__
from . import diffgen, keys, memguard, patcher, policy, scanner
from .patchfile import Bundle, BundleError
from .pe import PE, PEError
from .util import format_hex, hexdump, human_size, read_json, sha256_file, write_json_atomic

EXIT_OK, EXIT_USAGE, EXIT_MISMATCH, EXIT_POLICY, EXIT_IO = 0, 2, 3, 4, 5

BANNER = "surreal %s — Surrealism Window · windows patch workbench" % __version__


# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #
class Console:
    def __init__(self, json_mode: bool = False, quiet: bool = False,
                 color: Optional[bool] = None):
        self.json_mode = json_mode
        self.quiet = quiet
        if color is None:
            color = _supports_color()
        self.color = color

    def c(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return "\x1b[%sm%s\x1b[0m" % (code, text)

    def say(self, text: str = "") -> None:
        if not self.quiet:
            print(text)

    def head(self, text: str) -> None:
        self.say(self.c(text, "1;36"))

    def ok(self, text: str) -> None:
        self.say(self.c("  ✓ ", "32") + text)

    def warn(self, text: str) -> None:
        print(self.c("  ! ", "33") + text, file=sys.stderr)

    def err(self, text: str) -> None:
        print(self.c("  ✗ ", "31") + text, file=sys.stderr)

    def kv(self, key: str, value: Any, indent: int = 2) -> None:
        self.say("%s%-22s %s" % (" " * indent, key + ":", value))

    def emit_json(self, obj: Any) -> None:
        print(json.dumps(obj, indent=2, sort_keys=False))


def _supports_color() -> bool:
    """ANSI colour only when it is useful: a TTY, honouring NO_COLOR."""
    if os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    # classic conhost swallows ANSI; Windows Terminal / ConEmu / mintty do not
    return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM"))


def _die(console: Console, message: str, code: int) -> int:
    if console.json_mode:
        console.emit_json({"ok": False, "error": message, "exit_code": code})
    console.err(message)
    return code


def _confirm(console: Console, question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        answer = input("  %s [y/N] " % question).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_init(args, console: Console) -> int:
    console.head(BANNER)
    if args.revoke:
        removed = policy.revoke_policy()
        console.say("policy acknowledgement removed." if removed
                    else "no acknowledgement was stored.")
        return EXIT_OK
    console.say(policy.POLICY_TEXT)
    if not args.accept_policy:
        console.say("\nNothing was changed. Re-run with --accept-policy to continue.")
        return EXIT_OK
    record = policy.accept_policy(user=args.user or os.environ.get("USERNAME", ""))
    console.ok("policy accepted at %s" % record["accepted_utc"])
    console.say("  stored in %s" % policy.acceptance_path())
    if console.json_mode:
        console.emit_json({"ok": True, "acceptance": record,
                           "path": policy.acceptance_path()})
    return EXIT_OK


def cmd_inspect(args, console: Console) -> int:
    try:
        pe = PE.open(args.file)
    except (PEError, OSError) as exc:
        return _die(console, "%s: %s" % (args.file, exc), EXIT_MISMATCH)
    try:
        info = pe.to_dict(with_hashes=args.hashes)
        info["sha256"] = sha256_file(args.file)
        imports = pe.imports() if args.imports else []
        exports = pe.exports() if args.exports else []
        notes = pe.heuristics()
        strings = scanner.find_best_strings(pe.data, args.strings) if args.strings else []
    finally:
        pe.close()

    if console.json_mode:
        info["imports"] = imports
        info["exports"] = exports
        info["notes"] = notes
        info["strings"] = strings
        console.emit_json(info)
        return EXIT_OK

    console.head(BANNER)
    console.say("  %s  (%s)" % (args.file, human_size(info["size"])))
    console.say("  sha256 %s" % info["sha256"])
    console.say("")
    console.kv("format", "%s / %s / %s" % (info["format"], info["machine_name"],
                                           info["subsystem"]))
    console.kv("image base", "0x%X" % info["image_base"])
    console.kv("entry point", "RVA 0x%X" % info["entrypoint_rva"])
    console.kv("timestamp", info["timestamp"])
    console.kv("dotnet", "yes" if info["dotnet"] else "no")
    console.kv("authenticode", "signed" if info["authenticode"] else "unsigned")
    console.kv("checksum", "0x%08X (%s)" % (info["computed_checksum"],
                                            "valid" if info["checksum_valid"] else "STALE"))
    console.kv("overlay", "%s at 0x%X" % (human_size(info["overlay"]["size"]),
                                          info["overlay"]["offset"]))
    console.say("")
    console.head("  sections")
    console.say("    %-10s %10s %10s %10s  %-10s %5s %s"
                % ("name", "raw ptr", "raw size", "rva", "flags", "ent", "sha256"))
    for sec in info["sections"]:
        flags = ("X" if sec["executable"] else "-") + ("W" if sec["writable"] else "-")
        console.say("    %-10s %10X %10X %10X  %-10s %5.2f %s"
                    % (sec["name"], sec["raw_ptr"], sec["raw_size"], sec["rva"],
                       flags, sec["entropy"], (sec.get("raw_sha256") or "")[:16]))
    if imports and not console.quiet:
        console.say("")
        console.head("  imports")
        for dll in imports:
            console.say("    %s (%d)" % (dll["dll"], len(dll["thunks"])))
            if args.verbose:
                for fn in dll["thunks"]:
                    console.say("        %s" % fn)
    if exports and exports[0]["names"]:
        console.say("")
        console.head("  exports (%d)" % len(exports[0]["names"]))
        for fn in exports[0]["names"][:args.limit]:
            console.say("    RVA 0x%-8X %s" % (fn["rva"], fn["name"]))
    if strings:
        console.say("")
        console.head("  notable strings")
        for s in strings:
            console.say("    %08X  %s" % (s["offset"], s["text"][:100]))
    if notes:
        console.say("")
        console.head("  notes")
        for note in notes:
            console.say("    · %s" % note)
    console.say("")
    console.say("  next: surreal scan %s --string \"some text\"" % os.path.basename(args.file))
    return EXIT_OK


def cmd_scan(args, console: Console) -> int:
    if not args.pattern and not args.string:
        return _die(console, "give --pattern \"48 8B ?? E8\" or --string \"text\"", EXIT_USAGE)
    try:
        pe = PE.open(args.file)
    except (PEError, OSError) as exc:
        return _die(console, "%s: %s" % (args.file, exc), EXIT_MISMATCH)
    try:
        data = pe.data
        hits: List[Dict[str, Any]] = []
        start = args.start if args.start is not None else 0
        end = args.end if args.end is not None else pe.size
        t0 = time.time()
        if args.pattern:
            pattern = scanner.parse_pattern(args.pattern)
            for off in scanner.find_pattern(data, pattern, start, end, args.limit):
                hits.append(_hit(pe, data, off, len(pattern), "pattern", args.context))
        else:
            utf16 = args.utf16
            min_len = 1
            if utf16:
                found = scanner.find_string(data, args.string, True, start, end,
                                            args.limit, min_len)
                for off in found:
                    hits.append(_hit(pe, data, off, len(args.string.encode("utf-16-le")),
                                     "utf16le", args.context))
            else:
                encodings = [("ascii", False)] if not args.both else [("ascii", False),
                                                                      ("utf16le", True)]
                for label, is16 in encodings:
                    needle_len = len(args.string) * (2 if is16 else 1)
                    for off in scanner.find_string(data, args.string, is16, start, end,
                                                   args.limit):
                        hits.append(_hit(pe, data, off, needle_len, label, args.context))
        elapsed = time.time() - t0
    finally:
        pe.close()

    if console.json_mode:
        console.emit_json({"file": args.file, "hits": hits, "count": len(hits),
                           "elapsed_ms": round(elapsed * 1000, 1)})
        return EXIT_OK

    what = args.pattern or args.string
    console.head(BANNER)
    console.say("  %d hit(s) for %r in %s (%.0f ms)"
                % (len(hits), what, os.path.basename(args.file), elapsed * 1000))
    if not hits:
        console.say("  nothing found — try a shorter or different string")
        return EXIT_OK
    for h in hits[:args.limit]:
        console.say("")
        console.say("  0x%08X  %s  section %s  rva 0x%X"
                    % (h["offset"], h["encoding"], h["section"], h["rva"]))
        for line in h["hexdump"].splitlines():
            console.say("      " + line)
    if len(hits) > args.limit:
        console.say("\n  … %d more (use --limit)" % (len(hits) - args.limit))
    console.say("\n  tip: patch authoring is `surreal diff old.exe new.exe -o my.morph`")
    return EXIT_OK


def _hit(pe: PE, data, offset: int, length: int, encoding: str, context: int) -> Dict[str, Any]:
    lo = max(0, offset - context)
    hi = min(pe.size, offset + length + context)
    rva = pe.offset_to_rva(offset)
    sec = pe.section_for_rva(rva) if rva is not None else None
    return {
        "offset": offset,
        "length": length,
        "encoding": encoding,
        "rva": rva if rva is not None else -1,
        "section": sec.name if sec else "(headers/overlay)",
        "hexdump": hexdump(bytes(data[lo:hi]), base=lo),
    }


def cmd_diff(args, console: Console) -> int:
    for path in (args.old, args.new):
        if not os.path.isfile(path):
            return _die(console, "file not found: %s" % path, EXIT_IO)
    if not args.id:
        return _die(console, "--id is required, e.g. --id com.you.tweak", EXIT_USAGE)
    try:
        bundle, stats = diffgen.build_bundle(
            args.old, args.new, bundle_id=args.id, name=args.name or args.id,
            author=args.author, description=args.description or "",
            merge_gap=args.merge_gap, require_pe=not args.force,
            version=args.bundle_version,
        )
    except diffgen.DiffError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)
    bundle.save(args.output)

    if console.json_mode:
        console.emit_json({"ok": True, "output": args.output, "bundle": bundle.to_dict(),
                           "stats": stats})
        return EXIT_OK

    console.head(BANNER)
    console.ok("wrote %s" % args.output)
    console.kv("id", bundle.id)
    console.kv("hunks", len(bundle.hunks))
    console.kv("anchored", "%d (unique literal context)" % stats["anchored"])
    console.kv("section+rva", stats["section_rva"])
    console.kv("bytes changed", sum(h.length for h in bundle.hunks
                                    if h.op != "append"))
    if stats.get("size_delta"):
        console.kv("size delta", "%+d bytes (overlay)" % stats["size_delta"])
    console.kv("target sha256", bundle.target.get("sha256", ""))
    for warn in stats["warnings"]:
        console.warn(warn)
    console.say("")
    console.say("  next: surreal check %s --target %s"
                % (os.path.basename(args.output), os.path.basename(args.old)))
    return EXIT_OK


def cmd_info(args, console: Console) -> int:
    try:
        bundle = Bundle.load(args.bundle, strict=not args.lax)
    except BundleError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)
    blocked = bundle.is_policy_blocked()
    if console.json_mode:
        console.emit_json({"ok": True, "blocked": blocked, "bundle": bundle.to_dict()})
        return EXIT_OK
    console.head(BANNER)
    console.kv("id", bundle.id)
    console.kv("name", bundle.name)
    console.kv("version", bundle.version)
    if bundle.description:
        console.kv("description", bundle.description)
    console.kv("author", bundle.author or "(none)")
    console.kv("created", bundle.created_utc or "(unknown)")
    console.kv("format", "%s v%d" % (FORMAT_NAME, 1))
    console.kv("target", "%s · %s · sha256 %s"
               % (bundle.target.get("filename", "?"),
                  human_size(int(bundle.target.get("size", 0) or 0)),
                  (bundle.target.get("sha256") or "")[:16]))
    console.say("")
    console.head("  anchors (%d)" % len(bundle.anchors))
    for i, a in enumerate(bundle.anchors):
        pat = " ".join("%02X" % v if v is not None else "??" for v in a.pattern)
        console.say("    [%d] %-12s %s" % (i, a.name, pat[:70]))
    console.head("  hunks (%d)" % len(bundle.hunks))
    for i, h in enumerate(bundle.hunks):
        where = []
        if h.op == "append":
            where.append("end of file (append +%d bytes)" % len(h.replace))
        elif h.op == "truncate":
            where.append("end of file (truncate -%d bytes)" % len(h.expect))
        if h.anchor is not None:
            where.append("anchor %d+%d" % (h.anchor, h.delta))
        if h.section and h.rva is not None:
            where.append("%s+0x%X" % (h.section, h.rva))
        if h.offset is not None:
            where.append("offset 0x%X" % h.offset)
        console.say("    [%d] %-34s %d bytes%s" %
                    (i, ", ".join(where) or "unlocated", h.length,
                     "" if not h.enabled else "" if h.enabled and h.op == "patch"
                     else ""))
        if h.expect:
            console.say("        - %s" % " ".join(
                "%02X" % v if v is not None else "??" for v in h.expect)[:100])
        if h.replace:
            console.say("        + %s" % format_hex(h.replace)[:100])
        if h.comment:
            console.say("        · %s" % h.comment)
    console.say("")
    if bundle.signature:
        state = ("trusted" if keys.is_trusted(policy.config_dir(),
                                              bundle.signature.get("public_key", ""))
                 else "NOT trusted")
        console.kv("signature", "ed25519, %s — %s" % (bundle.signer(), state))
    else:
        console.kv("signature", "unsigned")
    if blocked:
        console.say("")
        console.warn("this bundle is policy-blocked: %s" % blocked)
    return EXIT_OK


def cmd_check(args, console: Console) -> int:
    try:
        bundle = Bundle.load(args.bundle, strict=not args.lax)
    except BundleError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)
    blocked = bundle.is_policy_blocked()
    if blocked:
        return _die(console, "policy-blocked bundle: %s" % blocked, EXIT_POLICY)
    try:
        plan = patcher.build_plan(
            bundle, args.target, accept_drift=args.accept_drift,
            require_signature=args.require_signature,
            extra_trusted=args.trusted_key,
            allow_abs_address=args.allow_abs_address)
    except patcher.PatchError as exc:
        return _die(console, str(exc), exc.code)
    if console.json_mode:
        console.emit_json({"ok": True, "plan": plan.to_dict()})
        return EXIT_OK
    console.head(BANNER)
    console.ok("bundle %s is applicable to %s" % (bundle.id, os.path.basename(args.target)))
    for note in plan.notes:
        console.say("    · %s" % note)
    for warn in plan.warnings:
        console.warn(warn)
    console.kv("hunks", len(plan.resolved))
    if plan.new_checksum is None:
        console.kv("checksum", "recomputed on write (the file size is part of the sum)")
    else:
        console.kv("checksum", "0x%08X → 0x%08X" % (plan.old_checksum or 0,
                                                    plan.new_checksum))
    size_ops = [r for r in plan.resolved if r.op != "patch"]
    for r in size_ops:
        console.kv("size change", "%s %d bytes at end of file"
                   % (r.op, len(r.replace) if r.op == "append" else r.length))
    if plan.relocs:
        console.kv("aslr", "%d hunk(s) touch relocated fields (accepted)"
                   % len({r["hunk"] for r in plan.relocs}))
    console.say("\n  run: surreal apply %s --target %s"
                % (os.path.basename(args.bundle), os.path.basename(args.target)))
    return EXIT_OK


def cmd_apply(args, console: Console) -> int:
    if not args.dry_run:
        try:
            policy.require_acceptance()
        except PermissionError as exc:
            return _die(console, str(exc), EXIT_POLICY)
    try:
        bundle = Bundle.load(args.bundle, strict=not args.lax)
    except BundleError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)

    if not args.dry_run and not args.yes and not console.json_mode:
        if not _confirm(console, "write changes to %s?" % os.path.abspath(args.target),
                        args.yes):
            console.err("aborted (no changes written)")
            return EXIT_MISMATCH

    try:
        result = patcher.apply_bundle(
            bundle, args.target, dry_run=args.dry_run, no_backup=args.no_backup,
            no_checksum=args.no_checksum, accept_drift=args.accept_drift,
            keep_backups=args.keep_backups, require_signature=args.require_signature,
            extra_trusted=args.trusted_key, allow_abs_address=args.allow_abs_address,
            force_unlock=args.force_unlock)
    except patcher.PatchError as exc:
        return _die(console, str(exc), exc.code)
    except OSError as exc:
        return _die(console, "IO error: %s" % exc, EXIT_IO)

    if console.json_mode:
        console.emit_json({"ok": True, **result})
        return EXIT_OK
    console.head(BANNER)
    sig = result.get("signature") or {}
    if sig.get("state") == "valid":
        console.ok("signature %s" % sig.get("message", ""))
    elif sig.get("message"):
        console.warn("signature: %s" % sig["message"])
    for note in result["notes"]:
        console.say("    · %s" % note)
    for warn in result["warnings"]:
        console.warn(warn)
    if args.dry_run:
        console.ok("dry run OK — %d hunk(s) would be written, nothing changed"
                   % result["hunks"])
        if result.get("new_checksum") is None:
            console.kv("checksum", "recomputed on write (file size changes)")
        else:
            console.kv("checksum", "0x%08X → 0x%08X"
                       % (result["old_checksum"] or 0, result["new_checksum"]))
        return EXIT_OK
    console.ok("patched %s (%d hunk(s), %d bytes)"
               % (os.path.basename(result["target"]), result["hunks"],
                  result.get("bytes_written", 0)))
    console.kv("sha256 before", result["sha256_before"])
    console.kv("sha256 after", result["sha256_after"])
    if result.get("size_after") is not None:
        console.kv("size after", "%d bytes" % result["size_after"])
    if result.get("bytes_removed"):
        console.kv("bytes removed", result["bytes_removed"])
    if result.get("backup"):
        console.kv("backup", result["backup"])
    console.say("\n  undo with: surreal revert %s" % os.path.basename(args.target))
    return EXIT_OK


def cmd_revert(args, console: Console) -> int:
    try:
        policy.require_acceptance()
    except PermissionError as exc:
        return _die(console, str(exc), EXIT_POLICY)
    from .journal import Journal

    if args.list:
        j = Journal(args.target)
        if console.json_mode:
            console.emit_json({"ok": True, "entries": j.entries})
            return EXIT_OK
        console.head(BANNER)
        if not j.entries:
            console.say("  no journal entries for %s" % args.target)
            return EXIT_OK
        for e in j.entries:
            console.say("  %s  %-7s %s  %s" % (e.get("time_utc"), e.get("action"),
                                               e.get("bundle_id", "-"),
                                               os.path.basename(e.get("backup") or "-")))
        return EXIT_OK
    try:
        result = patcher.revert(args.target, force_unlock=args.force_unlock)
    except patcher.PatchError as exc:
        return _die(console, str(exc), exc.code)
    except OSError as exc:
        return _die(console, "IO error: %s" % exc, EXIT_IO)
    if console.json_mode:
        console.emit_json({"ok": True, **result})
        return EXIT_OK
    console.head(BANNER)
    console.ok("restored %s" % os.path.basename(result["target"]))
    console.kv("sha256", result["restored_sha256"])
    console.kv("reverted bundle", result.get("bundle_id") or "-")
    return EXIT_OK


def cmd_sign(args, console: Console) -> int:
    from . import keys as k

    try:
        key = k.load_key_file(args.key)
    except k.SignatureError as exc:
        return _die(console, str(exc), EXIT_POLICY if "not found" in str(exc) else EXIT_MISMATCH)
    try:
        bundle = Bundle.load(args.bundle, strict=not args.lax)
    except BundleError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)

    raw = bundle.to_dict()
    signed = k.sign_bundle(raw, bytes.fromhex(key["private_seed"]),
                           signer=args.signer or key.get("signer", ""))
    if args.output:
        out = args.output
    else:
        out = args.bundle
    write_json_atomic(out, signed)
    block = signed["signature"]

    if console.json_mode:
        console.emit_json({"ok": True, "output": out, "signature": block})
        return EXIT_OK
    console.head(BANNER)
    console.ok("signed %s" % out)
    console.kv("signer", block["signer"] or "(unnamed)")
    console.kv("public key", block["public_key"])
    console.kv("payload sha256", block["payload_sha256"])
    console.say("")
    console.say("  share the public key so others can trust your bundles:")
    console.say("    surreal keys --trust %s --label \"%s\""
                % (block["public_key"], block["signer"] or "publisher"))
    return EXIT_OK


def cmd_keys(args, console: Console) -> int:
    from . import keys as k

    cfg = policy.config_dir()
    try:
        if args.generate:
            record = k.generate_key_file(args.generate, signer=args.label,
                                         force=args.force)
            if console.json_mode:
                console.emit_json({"ok": True, "key_file": args.generate,
                                   "public_key": record["public_key"]})
                return EXIT_OK
            console.head(BANNER)
            console.ok("wrote private key %s" % args.generate)
            console.kv("public key", record["public_key"])
            console.warn("this file is the private key: never commit or share it")
            console.say("  publish only the public key above (or run: surreal keys "
                        "--trust %s)" % record["public_key"])
            return EXIT_OK
        if args.trust:
            entry = k.trust_key(cfg, args.trust, label=args.label)
            if console.json_mode:
                console.emit_json({"ok": True, "entry": entry, "trust_file":
                                   k.trust_path(cfg)})
                return EXIT_OK
            console.head(BANNER)
            console.ok("trusted key %s…" % entry["public_key"][:16])
            if entry.get("label"):
                console.kv("label", entry["label"])
            console.kv("store", k.trust_path(cfg))
            return EXIT_OK
        if args.untrust:
            removed = k.untrust_key(cfg, args.untrust)
            if console.json_mode:
                console.emit_json({"ok": True, "removed": removed})
                return EXIT_OK
            console.head(BANNER)
            (console.ok if removed else console.warn)(
                "removed %s…" % args.untrust[:16] if removed
                else "key %s… was not trusted" % args.untrust[:16])
            return EXIT_OK
    except k.SignatureError as exc:
        return _die(console, str(exc), EXIT_POLICY)

    data = k.load_trust(cfg)
    if console.json_mode:
        console.emit_json({"ok": True, "config_dir": cfg, "trust": data})
        return EXIT_OK
    console.head(BANNER)
    console.kv("store", k.trust_path(cfg))
    if not data["keys"]:
        console.say("  no trusted keys yet")
        console.say("  add one with: surreal keys --trust <64-hex-public-key> --label \"name\"")
    for entry in data["keys"]:
        console.say("  %s  %s  (added %s)" % (entry["public_key"],
                                              entry.get("label") or "-",
                                              entry.get("added_utc", "?")))
    return EXIT_OK


def cmd_verify(args, console: Console) -> int:
    from . import keys as k

    try:
        bundle = Bundle.load(args.bundle, strict=not args.lax)
    except BundleError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)
    raw = bundle.to_dict()
    try:
        state, message, trusted = k.check_bundle_signature(
            raw, policy.config_dir(), require=args.require,
            extra_trusted=args.trusted_key)
    except k.SignatureError as exc:
        if console.json_mode:
            console.emit_json({"ok": False, "state": "invalid", "error": str(exc)})
        return _die(console, str(exc), EXIT_POLICY)
    sig = raw.get("signature") or {}
    if console.json_mode:
        console.emit_json({"ok": True, "state": state, "message": message,
                           "public_key": sig.get("public_key"),
                           "signer": sig.get("signer"),
                           "payload_sha256": sig.get("payload_sha256")})
        return EXIT_OK
    console.head(BANNER)
    icon = {"valid": console.ok, "unsigned": console.warn,
            "untrusted": console.warn}.get(state, console.warn)
    console.kv("state", state)
    icon(message)
    if sig:
        console.kv("signer", sig.get("signer") or "(unnamed)")
        console.kv("public key", sig.get("public_key", ""))
        console.kv("signed", sig.get("signed_utc", "?"))
    return EXIT_OK


def cmd_demo(args, console: Console) -> int:
    """Write a synthetic 'app' + a patch bundle to a directory, to try the flow."""
    from .testkit import make_pe_pair

    outdir = os.path.abspath(args.out or "surreal-demo")
    os.makedirs(outdir, exist_ok=True)
    old, new = make_pe_pair(outdir)
    bundle_path = os.path.join(outdir, "demo-shorten-nag.morph")
    try:
        bundle, stats = diffgen.build_bundle(
            old, new, bundle_id="org.surreal.demo.shorten-nag",
            name="Demo: blank the trial nag + flip one branch",
            author="surreal demo",
            description="Generated locally from a synthetic PE. Safe to apply: "
                        "it only targets surreal-demo/demo_app.exe.",
        )
    except diffgen.DiffError as exc:  # pragma: no cover - fixtures are stable
        return _die(console, str(exc), EXIT_MISMATCH)
    bundle.save(bundle_path)
    os.remove(new)  # keep the folder tidy: the bundle is what you need

    if console.json_mode:
        console.emit_json({"ok": True, "dir": outdir, "target": old,
                           "bundle": bundle_path, "hunks": len(bundle.hunks)})
        return EXIT_OK
    console.head(BANNER)
    console.ok("demo written to %s" % outdir)
    console.kv("target", os.path.basename(old))
    console.kv("bundle", os.path.basename(bundle_path))
    console.kv("hunks", "%d (all anchored: %d)" % (len(bundle.hunks), stats["anchored"]))
    console.say("")
    console.say("  try it:")
    console.say("    surreal inspect %s" % os.path.join(outdir, "demo_app.exe"))
    console.say("    surreal check   %s --target %s"
                % (os.path.join(outdir, "demo-shorten-nag.morph"),
                   os.path.join(outdir, "demo_app.exe")))
    console.say("    surreal init --accept-policy")
    console.say("    surreal apply   %s --target %s --dry-run"
                % (os.path.join(outdir, "demo-shorten-nag.morph"),
                   os.path.join(outdir, "demo_app.exe")))
    console.say("")
    console.say("  This is a generated PE for practice — never a real product.")
    return EXIT_OK


def cmd_selftest(args, console: Console) -> int:
    """Prove the toolchain works end to end on a synthetic PE built in memory."""
    from .testkit import make_pe_pair, run_selftest

    ok, report = run_selftest(keep=args.keep, workdir=args.workdir)
    if console.json_mode:
        console.emit_json({"ok": ok, "report": report})
        return EXIT_OK if ok else EXIT_MISMATCH
    console.head(BANNER)
    for line in report:
        console.say("  " + line)
    return EXIT_OK if ok else EXIT_MISMATCH


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Surrealism Window — inspect, diff and patch Windows PE "
                    "executables you are authorised to modify.",
        epilog=textwrap.dedent("""\
            exit codes: 0 ok · 2 usage · 3 mismatch/unresolved · 4 policy · 5 IO
            docs: PLAN.md (design) · docs/PATCH_FORMAT.md (bundle spec) ·
                  docs/LEGAL.md (what is in scope)
            """),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-V", "--version", action="version",
                   version="%s %s" % (TOOL_NAME, __version__))
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress chatter")
    p.add_argument("--max-mem", type=float, default=256.0, metavar="MB",
                   help="memory ceiling for whole-file reads (default 256)")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    def add(name, help_text):
        sp = sub.add_parser(name, help=help_text, description=help_text)
        sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="machine-readable output")
        sp.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS)
        sp.add_argument("--max-mem", type=float, default=argparse.SUPPRESS, metavar="MB",
                        help="memory ceiling in MB (default 256)")
        return sp

    sp = add("init", "read the usage policy and record your acknowledgement")
    sp.add_argument("--accept-policy", action="store_true")
    sp.add_argument("--revoke", action="store_true", help="forget the acknowledgement")
    sp.add_argument("--user", default="", help="name to record (optional)")
    sp.set_defaults(func=cmd_init)

    sp = add("inspect", "show PE headers, sections, imports and heuristic notes")
    sp.add_argument("file")
    sp.add_argument("--imports", action="store_true", help="list imported DLLs/functions")
    sp.add_argument("--exports", action="store_true", help="list exported functions")
    sp.add_argument("--strings", type=int, default=0, metavar="N",
                    help="print up to N notable strings")
    sp.add_argument("--no-hashes", dest="hashes", action="store_false",
                    help="skip per-section sha256 (faster on big files)")
    sp.add_argument("--verbose", action="store_true")
    sp.add_argument("--limit", type=int, default=64)
    sp.set_defaults(func=cmd_inspect)

    sp = add("scan", "search bytes or text; prints offset, RVA, section, hexdump")
    sp.add_argument("file")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--pattern", help='hex pattern, e.g. "48 8B ?? E8"')
    g.add_argument("--string", help="ASCII text to search for")
    sp.add_argument("--utf16", action="store_true", help="search UTF-16LE instead")
    sp.add_argument("--both", action="store_true", help="search ASCII and UTF-16LE")
    sp.add_argument("--context", type=int, default=16, help="hexdump context bytes")
    sp.add_argument("--start", type=lambda v: int(v, 0), default=None)
    sp.add_argument("--end", type=lambda v: int(v, 0), default=None)
    sp.add_argument("--limit", type=int, default=25)
    sp.set_defaults(func=cmd_scan)

    sp = add("diff", "create a .morph patch bundle from two builds of an app")
    sp.add_argument("old", help="original binary")
    sp.add_argument("new", help="modified binary (same size, this format version)")
    sp.add_argument("-o", "--output", required=True, help="bundle to write")
    sp.add_argument("--id", required=True, help="reverse-dns id, e.g. com.you.tweak")
    sp.add_argument("--name", default="", help="human name")
    sp.add_argument("--description", default="")
    sp.add_argument("--author", default="")
    sp.add_argument("--bundle-version", default="1.0.0")
    sp.add_argument("--merge-gap", type=int, default=16,
                    help="merge differences closer than N bytes (default 16)")
    sp.add_argument("--force", action="store_true", help="allow non-PE input")
    sp.set_defaults(func=cmd_diff)

    sp = add("info", "inspect a .morph bundle")
    sp.add_argument("bundle")
    sp.add_argument("--lax", action="store_true", help="accept unknown fields")
    sp.set_defaults(func=cmd_info)

    sp = add("check", "preflight: verify a bundle applies to a target, no writes")
    sp.add_argument("bundle")
    sp.add_argument("--target", required=True)
    sp.add_argument("--accept-drift", action="store_true",
                    help="allow size/hash drift from the authored build")
    sp.add_argument("--require-signature", action="store_true",
                    help="fail unless signed by a trusted key")
    sp.add_argument("--trusted-key", action="append", metavar="HEX", default=[],
                    help="trust this public key for this run (repeatable)")
    sp.add_argument("--allow-abs-address", action="store_true",
                    help="accept hunks that overwrite relocatable absolute fields")
    sp.add_argument("--lax", action="store_true")
    sp.set_defaults(func=cmd_check)

    sp = add("apply", "apply a bundle (backs up, verifies, journals, atomic swap)")
    sp.add_argument("bundle")
    sp.add_argument("--target", required=True)
    sp.add_argument("--dry-run", action="store_true", help="resolve+verify only")
    sp.add_argument("--yes", "-y", action="store_true", help="do not ask")
    sp.add_argument("--no-backup", action="store_true", help="skip the backup copy")
    sp.add_argument("--no-checksum", action="store_true",
                    help="leave the PE checksum stale")
    sp.add_argument("--accept-drift", action="store_true")
    sp.add_argument("--require-signature", action="store_true",
                    help="fail unless signed by a trusted key")
    sp.add_argument("--trusted-key", action="append", metavar="HEX", default=[],
                    help="trust this public key for this run (repeatable)")
    sp.add_argument("--allow-abs-address", action="store_true",
                    help="accept hunks that overwrite relocatable absolute fields")
    sp.add_argument("--force-unlock", action="store_true",
                    help="break a lock left by a crashed run")
    sp.add_argument("--lax", action="store_true")
    sp.add_argument("--keep-backups", type=int, default=3,
                    help="prune older backups, keep N (0 = keep all)")
    sp.set_defaults(func=cmd_apply)

    sp = add("revert", "restore the backup created by the last apply")
    sp.add_argument("target")
    sp.add_argument("--force-unlock", action="store_true",
                    help="break a lock left by a crashed run")
    sp.add_argument("--list", action="store_true", help="show the journal")
    sp.set_defaults(func=cmd_revert)

    sp = add("sign", "sign a bundle with an ed25519 key (tamper-evident patches)")
    sp.add_argument("bundle")
    sp.add_argument("--key", required=True, help="surreal.key file (created by `keys --generate`)")
    sp.add_argument("-o", "--output", default="", help="write here (default: in place)")
    sp.add_argument("--signer", default="", help="signer name shown to users")
    sp.add_argument("--lax", action="store_true")
    sp.set_defaults(func=cmd_sign)

    sp = add("keys", "manage signing keys and the trusted-key store")
    sp.add_argument("--generate", metavar="PATH", help="create a new key pair file")
    sp.add_argument("--trust", metavar="PUBHEX", help="trust a public key")
    sp.add_argument("--untrust", metavar="PUBHEX", help="forget a public key")
    sp.add_argument("--label", default="", help="name for the key")
    sp.add_argument("--force", action="store_true", help="overwrite an existing key file")
    sp.set_defaults(func=cmd_keys)

    sp = add("verify", "verify a bundle's ed25519 signature")
    sp.add_argument("bundle")
    sp.add_argument("--require", action="store_true",
                    help="fail if unsigned or signed by an untrusted key")
    sp.add_argument("--trusted-key", action="append", metavar="HEX", default=[])
    sp.add_argument("--lax", action="store_true")
    sp.set_defaults(func=cmd_verify)

    sp = add("demo", "write a synthetic demo app + patch bundle to a directory")
    sp.add_argument("--out", default="surreal-demo", help="output directory")
    sp.set_defaults(func=cmd_demo)

    sp = add("selftest", "end-to-end check on a synthetic PE (safe, no targets)")
    sp.add_argument("--keep", action="store_true", help="keep the temp workspace")
    sp.add_argument("--workdir", default=None)
    sp.set_defaults(func=cmd_selftest)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        parser.print_help()
        return EXIT_OK
    args = parser.parse_args(argv)
    console = Console(json_mode=getattr(args, "json", False),
                      quiet=getattr(args, "quiet", False))
    previous_budget = memguard.DEFAULT_BUDGET
    memguard.set_default(getattr(args, "max_mem", None))
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        return args.func(args, console)
    except KeyboardInterrupt:
        console.err("interrupted")
        return 130
    except memguard.MemoryLimitError as exc:
        return _die(console, str(exc), EXIT_IO)
    except BrokenPipeError:  # e.g. `surreal inspect x.exe | head`
        return EXIT_OK
    finally:
        memguard.restore(previous_budget)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
