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
from . import collection as collections
from . import repo as repos
from . import diffgen, keys, memguard, patcher, policy, scanner
from .patchfile import Bundle, BundleError
from .pe import PE, PEError
from .util import format_hex, hexdump, human_size, read_json, sha256_file, write_json_atomic

EXIT_OK, EXIT_USAGE, EXIT_MISMATCH, EXIT_POLICY, EXIT_IO = 0, 2, 3, 4, 5

BANNER = "surreal %s — Surrealism Window · windows patch workbench" % __version__


# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #
# A Windows console is often cp1252 (or cp437 in a legacy conhost). Printing "✓"
# there raises UnicodeEncodeError, which would crash the tool mid-report — so the
# glyphs degrade to ASCII instead.
_ASCII_FALLBACK = {
    ord("✓"): "+", ord("✗"): "x", ord("·"): "-", ord("→"): "->",
    ord("—"): "-", ord("…"): "...", ord("×"): "x", ord("≥"): ">=",
    ord("≤"): "<=", ord("•"): "*", ord("’"): "'", ord("“"): '"',
    ord("”"): '"',
}


def _supports_unicode(stream) -> bool:
    """Can this stream encode the characters the UI likes to use?"""
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        "✓✗·→—…".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _ascii_safe(text: str) -> str:
    return text.translate(_ASCII_FALLBACK)


class Console:
    def __init__(self, json_mode: bool = False, quiet: bool = False,
                 color: Optional[bool] = None):
        self.json_mode = json_mode
        self.quiet = quiet
        if color is None:
            color = _supports_color()
        self.color = color
        self.unicode = _supports_unicode(sys.stdout) and _supports_unicode(sys.stderr)

    def c(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return "\x1b[%sm%s\x1b[0m" % (code, text)

    def text(self, value: Any) -> str:
        """Sanitise for the current console encoding (no-op on a UTF-8 stream)."""
        text = value if isinstance(value, str) else str(value)
        return text if self.unicode else _ascii_safe(text)

    def say(self, text: str = "") -> None:
        if not self.quiet:
            print(self.text(text))

    def head(self, text: str) -> None:
        self.say(self.c(text, "1;36"))

    def ok(self, text: str) -> None:
        self.say(self.c("  ✓ " if self.unicode else "  OK ", "32") + text)

    def warn(self, text: str) -> None:
        print(self.text(self.c("  ! ", "33") + text), file=sys.stderr)

    def err(self, text: str) -> None:
        print(self.text(self.c("  ✗ " if self.unicode else "  XX ", "31") + text),
              file=sys.stderr)

    def kv(self, key: str, value: Any, indent: int = 2) -> None:
        self.say("%s%-22s %s" % (" " * indent, key + ":",
                                 value if isinstance(value, str) else value))

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
    bundle.requires = _author_requires(args, console)
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
    if bundle.requires:
        console.kv("preconditions", "%d (a target that fails one is refused)"
                   % len(bundle.requires))
        for cond in bundle.requires:
            console.say("    - %s" % _describe_condition(cond))
    for warn in stats["warnings"]:
        console.warn(warn)
    console.say("")
    console.say("  next: surreal check %s --target %s"
                % (os.path.basename(args.output), os.path.basename(args.old)))
    return EXIT_OK


def _hunk_amount(h) -> str:
    """Short human description of how big a hunk's effect is."""
    if h.op == "append":
        return "+%d bytes at EOF" % len(h.replace)
    if h.op == "truncate":
        return "-%d bytes at EOF" % len(h.expect)
    if h.op in ("extend-section", "add-section"):
        return "+%d bytes (padded to FileAlignment)" % len(h.replace)
    return "%d bytes" % h.length


def _describe_condition(cond: Dict[str, Any]) -> str:
    from . import script

    return script._describe(cond)


def _author_requires(args, console: Console) -> List[Dict[str, Any]]:
    """Turn --requires-* flags into conditions, using the *original* build."""
    from . import script as scriptmod

    conds: List[Dict[str, Any]] = []
    if getattr(args, "requires_machine", False):
        try:
            with PE.open(args.old) as image:
                machine = image.machine_name
        except (PEError, OSError) as exc:
            console.warn("cannot read the machine type: %s" % exc)
            machine = ""
        for known, aliases in scriptmod.MACHINES.items():
            if machine.lower() in aliases:
                conds.append({"machine": known,
                              "comment": "authored against %s" % machine})
                break
        else:
            console.warn("unknown machine type %r - no machine precondition"
                         % machine)
    for name in getattr(args, "requires_section", []) or []:
        conds.append({"section": name})
    for text in getattr(args, "requires_string", []) or []:
        conds.append({"string": text})
    return conds


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
    if bundle.requires:
        console.head("  preconditions (%d)" % len(bundle.requires))
        for cond in bundle.requires:
            console.say("    - %s" % _describe_condition(cond))
            if cond.get("comment"):
                console.say("        %s" % cond["comment"])
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
        elif h.op == "extend-section":
            where.append("header surgery: grow %s" % h.section)
        elif h.op == "add-section":
            where.append("header surgery: add %s" % h.name)
        if h.anchor is not None:
            where.append("anchor %d+%d" % (h.anchor, h.delta))
        if h.section and h.rva is not None:
            where.append("%s+0x%X" % (h.section, h.rva))
        if h.offset is not None:
            where.append("offset 0x%X" % h.offset)
        console.say("    [%d] %-46s %s%s"
                    % (i, ", ".join(where) or "unlocated",
                       _hunk_amount(h), "" if h.enabled else "   (disabled)"))
        if h.when:
            console.say("        only if %s" % _describe_condition(h.when))
        if h.expect:
            console.say("        - %s" % " ".join(
                "%02X" % v if v is not None else "??" for v in h.expect)[:100])
        if h.replace:
            console.say("        + %s" % format_hex(h.replace)[:100])
        if h.op in ("extend-section", "add-section"):
            detail = []
            if h.raw_size_before is not None:
                detail.append("raw_size_before 0x%X" % h.raw_size_before)
            if h.virtual_size_after is not None:
                detail.append("virtual_size_after 0x%X" % h.virtual_size_after)
            if h.characteristics is not None:
                detail.append("characteristics 0x%08X" % h.characteristics)
            if h.rva is not None:
                detail.append("rva 0x%X" % h.rva)
            if detail:
                console.say("        · " + ", ".join(detail))
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
        if r.op in ("extend-section", "add-section") and r.surgery is not None:
            console.kv("layout change", "%s %s → %d bytes, SizeOfImage 0x%X"
                       % (r.op, r.surgery.section_name, r.surgery.file_size_after,
                          r.surgery.image_size_after))
        else:
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
    if result.get("collection"):
        console.kv("reverted collection", result["collection"])
    else:
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


def cmd_collection(args, console: Console) -> int:
    try:
        coll = collections.load_collection(args.path, strict=not args.lax)
    except collections.CollectionError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)

    if args.action == "list":
        if console.json_mode:
            console.emit_json({"ok": True, "collection": coll.to_dict(),
                               "manifest": coll.path})
            return EXIT_OK
        console.head(BANNER)
        console.kv("collection", coll.name)
        if coll.description:
            console.kv("description", coll.description)
        console.kv("manifest", coll.path)
        console.kv("patches", len(coll.entries))
        if coll.is_vault:
            console.kv("kind", "vault (%d file(s) under one transaction)"
                       % len(coll.files()))
        for e in coll.entries:
            console.say("  [%3d] %-44s %s%s"
                        % (e.order, e.bundle.id, e.bundle_file,
                           "  →  %s" % e.target if e.target else ""))
            if e.description:
                console.say("        · %s" % e.description)
            if e.depends_on:
                console.say("        · requires %s" % ", ".join(e.depends_on))
            if e.conflicts_with:
                console.say("        · conflicts with %s"
                            % ", ".join(e.conflicts_with))
            if not e.enabled:
                console.say("        · disabled")
            if e.bundle.signature:
                trusted = keys.is_trusted(
                    policy.config_dir(), e.bundle.signature.get("public_key", ""))
                console.say("        · signed by %s%s"
                            % (e.bundle.signer(), "" if trusted
                               else "  (NOT trusted)"))
        console.say("")
        console.say("  next: surreal collection check %s --target %s"
                    % (os.path.basename(os.path.dirname(coll.path) or "."),
                       "<app directory>" if coll.is_vault else "app.exe"))
        return EXIT_OK

    if args.action == "graph":
        graph = collections.dependency_graph(coll)
        if console.json_mode:
            console.emit_json({"ok": True, "collection": coll.name,
                               "manifest": coll.path, "graph": graph})
            return EXIT_OK
        console.head(BANNER)
        console.kv("collection", coll.name)
        console.kv("patches", len(graph["nodes"]))
        if graph["cross_file_edges"]:
            console.kv("cross-file edges", len(graph["cross_file_edges"]))
        console.say("")
        for node in graph["nodes"]:
            where = node["file"] or "(single target)"
            console.say("  %-40s %s" % (node["id"], where))
            for dep in node["depends_on"]:
                console.say("      requires  %s" % dep)
            for other in node["conflicts_with"]:
                console.say("      conflicts %s" % other)
            if not node["enabled"]:
                console.say("      (disabled)")
        if graph["issues"]:
            console.say("")
            for issue in graph["issues"]:
                console.warn("%s: %s" % (issue["kind"], issue.get("detail", "")))
        console.say("")
        console.say("  next: surreal collection check %s --target %s"
                    % (os.path.basename(os.path.dirname(coll.path) or "."),
                       "<app directory>" if coll.is_vault else "app.exe"))
        return EXIT_OK

    # check / apply need a target
    target = args.target
    if not target:
        return _die(console, "collection %s requires --target%s"
                    % (args.action, " (the application directory)" if coll.is_vault
                       else " (the binary to patch)"), EXIT_USAGE)
    if coll.is_vault:
        if args.action == "check":
            try:
                report = collections.preflight_vault(
                    coll, target, require_signature=args.require_signature,
                    extra_trusted=args.trusted_key,
                    allow_abs_address=args.allow_abs_address)
            except (collections.CollectionError, patcher.PatchError) as exc:
                return _die(console, str(exc), getattr(exc, "code", EXIT_MISMATCH))
            if console.json_mode:
                console.emit_json({"ok": True, "collection": coll.name,
                                   "report": report})
                return EXIT_OK
            console.head(BANNER)
            console.ok("vault %r applies cleanly to %d file(s) under %s"
                       % (coll.name, len(report["files"]), report["root"]))
            for item in report["files"]:
                console.say("    · %-32s %d patch(es)" % (item["file"],
                                                         len(item["patches"])))
                for patch in item["patches"]:
                    console.say("        · %-38s %2d hunk(s)  signature: %s"
                                % (patch["bundle"], patch["hunks"],
                                   patch["signature"]))
                console.say("        · result sha256 %s"
                            % item["result_sha256"][:16] + "…")
            for item in report["skipped"]:
                console.warn("skipped %s (%s)" % (item["file"], item["reason"]))
            for warn in report["warnings"]:
                console.warn(warn)
            console.say("\n  run: surreal collection apply %s --target %s"
                        % (os.path.basename(os.path.dirname(coll.path) or "."),
                           report["root"]))
            return EXIT_OK

        try:
            policy.require_acceptance()
        except PermissionError as exc:
            return _die(console, str(exc), EXIT_POLICY)
        if not args.dry_run and not args.yes and not console.json_mode:
            if not _confirm(console, "apply vault %r to %s?"
                            % (coll.name, os.path.abspath(target)), args.yes):
                console.err("aborted (no changes written)")
                return EXIT_MISMATCH
        if args.dry_run:
            try:
                report = collections.preflight_vault(
                    coll, target, require_signature=args.require_signature,
                    extra_trusted=args.trusted_key,
                    allow_abs_address=args.allow_abs_address)
            except (collections.CollectionError, patcher.PatchError) as exc:
                return _die(console, str(exc), getattr(exc, "code", EXIT_MISMATCH))
            if console.json_mode:
                console.emit_json({"ok": True, "dry_run": True, "report": report})
                return EXIT_OK
            console.head(BANNER)
            console.ok("dry run: vault %r would patch %d file(s) under %s"
                       % (coll.name, len(report["files"]), report["root"]))
            for item in report["files"]:
                console.say("    · %-32s %d patch(es) → %s…"
                            % (item["file"], len(item["patches"]),
                               item["result_sha256"][:8]))
            return EXIT_OK
        try:
            vresult = collections.apply_vault(
                coll, target, require_signature=args.require_signature,
                extra_trusted=args.trusted_key,
                allow_abs_address=args.allow_abs_address,
                keep_backups=args.keep_backups)
        except (collections.CollectionError, patcher.PatchError) as exc:
            return _die(console, str(exc), getattr(exc, "code", EXIT_IO))
        except OSError as exc:
            return _die(console, "IO error: %s" % exc, EXIT_IO)
        if console.json_mode:
            console.emit_json({"ok": True, **vresult})
            return EXIT_OK
        console.head(BANNER)
        console.ok("applied vault %r to %d file(s)" % (coll.name,
                                                       len(vresult["files"])))
        for item in vresult["files"]:
            console.say("    · %-32s %d patch(es)  %s…"
                        % (item["file"], len(item["applied"]),
                           item["sha256_after"][:8]))
        for item in vresult["skipped"]:
            console.warn("skipped %s (%s)" % (item["file"], item["reason"]))
        console.say("\n  undo one file with: surreal revert <file>")
        return EXIT_OK

    if args.action == "check":
        try:
            report = collections.preflight(
                coll, target, require_signature=args.require_signature,
                extra_trusted=args.trusted_key,
                allow_abs_address=args.allow_abs_address)
        except (collections.CollectionError, patcher.PatchError) as exc:
            code = getattr(exc, "code", EXIT_MISMATCH)
            return _die(console, str(exc), code)
        if console.json_mode:
            console.emit_json({"ok": True, "collection": coll.name, "report": report})
            return EXIT_OK
        console.head(BANNER)
        console.ok("%d patch(es) from %r apply cleanly to %s"
                   % (len(report["applicable"]), coll.name,
                      os.path.basename(target)))
        for item in report["applicable"]:
            console.say("    · %-40s %2d hunk(s)  signature: %s"
                        % (item["bundle"], item["hunks"], item["signature"]))
        for item in report["skipped"]:
            console.warn("skipped %s (%s)" % (item["bundle"], item["reason"]))
        for warn in report["warnings"]:
            console.warn(warn)
        console.kv("result sha256", report["result_sha256"])
        console.say("\n  run: surreal collection apply %s --target %s"
                    % (os.path.basename(os.path.dirname(coll.path) or "."),
                       os.path.basename(target)))
        return EXIT_OK

    # apply
    try:
        policy.require_acceptance()
    except PermissionError as exc:
        return _die(console, str(exc), EXIT_POLICY)
    if not args.dry_run and not args.yes and not console.json_mode:
        if not _confirm(console, "apply %r to %s?"
                        % (coll.name, os.path.abspath(target)), args.yes):
            console.err("aborted (no changes written)")
            return EXIT_MISMATCH
    if args.dry_run:
        try:
            report = collections.preflight(
                coll, target, require_signature=args.require_signature,
                extra_trusted=args.trusted_key,
                allow_abs_address=args.allow_abs_address)
        except (collections.CollectionError, patcher.PatchError) as exc:
            return _die(console, str(exc), getattr(exc, "code", EXIT_MISMATCH))
        if console.json_mode:
            console.emit_json({"ok": True, "dry_run": True, "report": report})
            return EXIT_OK
        console.head(BANNER)
        console.ok("dry run: %d patch(es) from %r would apply to %s"
                   % (len(report["applicable"]), coll.name,
                      os.path.basename(target)))
        console.kv("result sha256", report["result_sha256"])
        return EXIT_OK
    try:
        result = collections.apply_collection(
            coll, target, require_signature=args.require_signature,
            extra_trusted=args.trusted_key,
            allow_abs_address=args.allow_abs_address,
            keep_backups=args.keep_backups)
    except (collections.CollectionError, patcher.PatchError) as exc:
        return _die(console, str(exc), getattr(exc, "code", EXIT_IO))
    except OSError as exc:
        return _die(console, "IO error: %s" % exc, EXIT_IO)

    if console.json_mode:
        console.emit_json({"ok": True, **result})
        return EXIT_OK
    console.head(BANNER)
    console.ok("applied %d patch(es) from %r to %s"
               % (len(result["applied"]), coll.name,
                  os.path.basename(result["target"])))
    for item in result["applied"]:
        console.say("    · %-40s %2d hunk(s)  %s…" % (item["bundle"], item["hunks"],
                                                     item["sha256_after"][:8]))
    for item in result["skipped"]:
        console.warn("skipped %s (%s)" % (item["bundle"], item["reason"]))
    console.kv("sha256 before", result["sha256_before"])
    console.kv("sha256 after", result["sha256_after"])
    if result.get("backup"):
        console.kv("backup", result["backup"])
    console.say("\n  undo with: surreal revert %s" % os.path.basename(target))
    return EXIT_OK


def cmd_repo(args, console: Console) -> int:
    cfg = policy.config_dir()
    if args.action == "index":
        try:
            index = repos.build_index(
                args.path, name=args.name or "", description=args.description or "",
                config_dir=cfg, created_utc=args.created or None,
                base_dir=os.path.dirname(os.path.abspath(args.output or
                        os.path.join(args.path, "surreal-repo.json"))),
                strict=not args.lax)
        except (repos.RepoError, OSError) as exc:
            return _die(console, str(exc), EXIT_MISMATCH)
        out = args.output or os.path.join(args.path, "surreal-repo.json")
        try:
            repos.write_index(index, out)
        except OSError as exc:
            return _die(console, "IO error: %s" % exc, EXIT_IO)
        if console.json_mode:
            console.emit_json({"ok": True, "index": out,
                               "summary": repos.summarize(index, cfg)})
            return EXIT_OK
        console.head(BANNER)
        console.ok("indexed %d bundle(s) → %s" % (len(index["bundles"]), out))
        for entry in index["bundles"]:
            console.say("    · %-40s %-28s %s"
                        % (entry["id"], entry["file"],
                           repos.trust_state(index, entry, cfg)))
        for skipped in index.get("skipped") or []:
            console.warn("skipped %s" % skipped)
        console.kv("next", "surreal repo list %s --target app.exe" % out)
        return EXIT_OK

    try:
        index = repos.load_index(args.path, strict=not args.lax)
    except (repos.RepoError, OSError) as exc:
        return _die(console, str(exc), EXIT_MISMATCH)

    if args.action == "list":
        matches = []
        if args.target:
            try:
                matches = repos.matching(index, args.target)
            except OSError as exc:
                return _die(console, "IO error: %s" % exc, EXIT_IO)
            matches = [e["id"] for e in matches]
        if console.json_mode:
            console.emit_json({"ok": True, "repo": repos.summarize(index, cfg),
                               "bundles": index["bundles"],
                               "matches": matches})
            return EXIT_OK
        console.head(BANNER)
        console.kv("repo", index.get("name"))
        console.kv("index", index.get("_index_path"))
        for key, value in repos.summarize(index, cfg).items():
            if key not in ("name", "path"):
                console.kv(key, value)
        console.say("")
        for entry in index["bundles"]:
            mark = "*" if entry["id"] in matches else " "
            console.say("  %s %-40s %-26s %s"
                        % (mark, entry["id"], entry["file"],
                           repos.trust_state(index, entry, cfg)))
            target = entry.get("target") or {}
            detail = "%s · %d hunk(s) · %s" % (
                target.get("filename") or "?",
                entry.get("hunks", 0),
                ", ".join(entry.get("ops") or ["patch"]))
            console.say("        · %s" % detail)
        if args.target:
            console.say("")
            if matches:
                console.ok("%d bundle(s) match %s (marked *)"
                           % (len(matches), os.path.basename(args.target)))
            else:
                console.warn("no bundle in this repo targets %s"
                             % os.path.basename(args.target))
        return EXIT_OK

    # show / apply need a bundle id
    if not args.bundle_id:
        return _die(console, "repo %s requires --id" % args.action, EXIT_USAGE)
    try:
        entry = repos.get(index, args.bundle_id)
        bundle, path = repos.load_bundle(index, entry, strict=not args.lax)
    except repos.RepoError as exc:
        return _die(console, str(exc), EXIT_MISMATCH)

    if args.action == "show":
        if console.json_mode:
            console.emit_json({"ok": True, "entry": entry,
                               "bundle": bundle.to_dict(), "path": path,
                               "trust": repos.trust_state(index, entry, cfg)})
            return EXIT_OK
        console.head(BANNER)
        console.kv("bundle", bundle.id)
        console.kv("name", bundle.name)
        console.kv("file", path)
        console.kv("sha256", entry["bundle_sha256"])
        console.kv("signature", repos.trust_state(index, entry, cfg))
        if entry.get("signer"):
            console.kv("signer", entry["signer"])
        target = entry.get("target") or {}
        console.kv("authored for", "%s · %s bytes · sha256 %s"
                   % (target.get("filename") or "?",
                      target.get("size"), (target.get("sha256") or "?")[:16]))
        console.kv("hunks", "%d (%s)" % (len(bundle.hunks),
                                        ", ".join(entry.get("ops") or ["patch"])))
        console.say("")
        console.say("  run: surreal repo apply %s --id %s --target app.exe"
                    % (os.path.basename(index["_index_path"]), bundle.id))
        return EXIT_OK

    # apply
    if entry.get("policy_blocked"):
        return _die(console, "bundle is policy-blocked: %s"
                    % entry["policy_blocked"], EXIT_POLICY)
    if not args.target:
        return _die(console, "repo apply requires --target", EXIT_USAGE)
    try:
        policy.require_acceptance()
    except PermissionError as exc:
        return _die(console, str(exc), EXIT_POLICY)
    if not args.dry_run and not args.yes and not console.json_mode:
        if not _confirm(console, "apply %r from %s to %s?"
                        % (bundle.id, os.path.basename(index["_index_path"]),
                           os.path.abspath(args.target)), args.yes):
            console.err("aborted (no changes written)")
            return EXIT_MISMATCH
    try:
        result = patcher.apply_bundle(
            bundle, args.target, dry_run=args.dry_run,
            accept_drift=args.accept_drift, no_checksum=args.no_checksum,
            require_signature=args.require_signature,
            extra_trusted=args.trusted_key,
            allow_abs_address=args.allow_abs_address,
            force_unlock=args.force_unlock, keep_backups=args.keep_backups)
    except patcher.PatchError as exc:
        return _die(console, str(exc), exc.code)
    except OSError as exc:
        return _die(console, "IO error: %s" % exc, EXIT_IO)
    if console.json_mode:
        console.emit_json({"ok": True, **result})
        return EXIT_OK
    console.head(BANNER)
    for note in result.get("notes") or []:
        console.say("    · %s" % note)
    for warn in result.get("warnings") or []:
        console.warn(warn)
    if args.dry_run:
        console.ok("dry run: %s would apply to %s"
                   % (bundle.id, os.path.basename(args.target)))
        return EXIT_OK
    console.ok("patched %s from repo %r (%d hunk(s))"
               % (os.path.basename(args.target), index.get("name"),
                  result["hunks"]))
    console.kv("sha256 after", result["sha256_after"])
    if result.get("backup"):
        console.kv("backup", result["backup"])
    console.say("\n  undo with: surreal revert %s" % os.path.basename(args.target))
    return EXIT_OK


def cmd_tui(args, console: Console) -> int:
    """A dependency-free interactive menu: pick bundles, then apply them.

    Deliberately not curses: plain ``input()`` works in every Windows console,
    over SSH and in the frozen ``surreal.exe``, and it can be scripted by piping
    lines into stdin (which is also how the tests drive it).
    """
    from . import collection as coll
    from .journal import Journal

    directory = os.path.abspath(args.dir or ".")
    if not os.path.isdir(directory):
        return _die(console, "not a directory: %s" % directory, EXIT_USAGE)
    target = os.path.abspath(args.target) if args.target else ""
    if not target or not os.path.isfile(target):
        return _die(console, "--target must be an existing file (the binary you "
                             "want to patch)", EXIT_USAGE)

    console.head(BANNER)
    names = sorted(f for f in os.listdir(directory) if f.lower().endswith(".morph"))
    if not names:
        return _die(console, "no .morph bundles in %s" % directory, EXIT_MISMATCH)
    sha = sha256_file(target)
    entries = []
    for filename in names:
        path = os.path.join(directory, filename)
        try:
            bundle = Bundle.load(path)
        except BundleError as exc:
            console.warn("skipping %s: %s" % (filename, exc))
            continue
        entries.append((filename, path, bundle, coll.matches(bundle, target, sha)))
    if not entries:
        return _die(console, "no readable bundles in %s" % directory, EXIT_MISMATCH)

    selected = set()
    while True:
        console.say("")
        console.kv("target", os.path.basename(target))
        console.kv("bundles", directory)
        console.say("")
        for i, (filename, _path, bundle, applies) in enumerate(entries, start=1):
            mark = "[x]" if (i - 1) in selected else "[ ]"
            state = "matches this build" if applies else "does NOT match this build"
            signed = ""
            if bundle.signature:
                trusted = keys.is_trusted(policy.config_dir(),
                                          bundle.signature.get("public_key", ""))
                signed = " · signed by %s%s" % (bundle.signer(),
                                                "" if trusted else " (untrusted)")
            console.say("  %s %d. %-44s %s%s"
                        % (mark, i, bundle.name[:44], state, signed))
            if bundle.is_policy_blocked():
                console.say("        · policy-blocked: %s" % bundle.is_policy_blocked())
        console.say("")
        console.say("  numbers toggle · a apply · r revert last · q quit")
        try:
            answer = input("  > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.say("")
            return EXIT_OK
        if answer in ("q", "quit", "exit"):
            return EXIT_OK
        if answer in ("r", "revert"):
            try:
                result = patcher.revert(target, force_unlock=args.force_unlock)
            except patcher.PatchError as exc:
                console.err(str(exc))
                continue
            console.ok("restored %s (%s…)" % (os.path.basename(target),
                                              result["restored_sha256"][:8]))
            continue
        if answer in ("a", "apply"):
            chosen = [entries[i] for i in sorted(selected)]
            if not chosen:
                console.warn("nothing selected")
                continue
            mismatched = [c for c in chosen if not c[3]]
            if mismatched:
                console.err("these do not match this build: %s"
                            % ", ".join(c[0] for c in mismatched))
                continue
            try:
                policy.require_acceptance()
            except PermissionError as exc:
                console.err(str(exc))
                continue
            if not _confirm(console, "apply %d bundle(s) to %s?"
                            % (len(chosen), target), args.yes):
                console.err("aborted (no changes written)")
                continue
            collection = coll.Collection(
                name="interactive: " + os.path.basename(directory),
                base_dir=directory,
                path=None,
                entries=[coll.Entry(bundle_file=filename, bundle=bundle, path=path,
                                    order=index * 10)
                         for index, (filename, path, bundle, _ok)
                         in enumerate(chosen, start=1)])
            try:
                result = coll.apply_collection(collection, target)
            except (coll.CollectionError, patcher.PatchError) as exc:
                console.err(str(exc))
                continue
            console.ok("applied %d bundle(s); target is now %s…"
                       % (len(result["applied"]), result["sha256_after"][:8]))
            console.kv("undo", "surreal revert %s" % os.path.basename(target))
            return EXIT_OK
        digits = [d for d in answer.replace(",", " ").split() if d.isdigit()]
        if not digits:
            console.warn("type numbers, 'a', 'r' or 'q'")
            continue
        for digit in digits:
            index = int(digit) - 1
            if not 0 <= index < len(entries):
                console.warn("no bundle %s" % digit)
                continue
            if index in selected:
                selected.remove(index)
            else:
                selected.add(index)


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


def cmd_easy(args, console: Console) -> int:
    """Guided mode: find patches, explain them, apply with a rollback."""
    from . import wizard

    if console.json_mode:
        return wizard.run_json(console, target=args.what or "",
                               patches=args.patch or [],
                               extra_dirs=args.dir or [],
                               apply_now=args.yes)
    try:
        return wizard.run(console, target=args.what or "",
                          patches=args.patch or [],
                          extra_dirs=args.dir or [],
                          assume_yes=args.yes)
    except wizard.WizardError as exc:
        if exc.code == EXIT_OK:
            console.err(str(exc))
            return EXIT_OK
        return _die(console, str(exc), exc.code)


def cmd_doctor(args, console: Console) -> int:
    """Say whether this machine, this file and these patches will work together."""
    from . import wizard

    if console.json_mode:
        return wizard.doctor_json(console, target=args.what or "",
                                  patches=args.patch or [],
                                  extra_dirs=args.dir or [])
    return wizard.doctor(console, target=args.what or "",
                         patches=args.patch or [],
                         extra_dirs=args.dir or [])


def cmd_undo(args, console: Console) -> int:
    """Plain-language alias for ``revert``: put the original file back."""
    console.head(BANNER)
    console.kv("restoring", os.path.abspath(args.target))
    try:
        result = patcher.revert(args.target, force_unlock=args.force_unlock)
    except patcher.PatchError as exc:
        if "nothing to revert" in str(exc) or "already a revert" in str(exc):
            console.warn("%s - the file already looks original" % exc)
            return EXIT_OK
        return _die(console, str(exc), exc.code)
    except OSError as exc:
        return _die(console, "IO error: %s" % exc, EXIT_IO)
    console.ok("restored %s from its backup" % os.path.basename(args.target))
    console.kv("sha256 now", result["restored_sha256"])
    if result.get("backup"):
        console.kv("backup used", result["backup"])
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
    sp.add_argument("--requires-machine", action="store_true",
                    help="record the build's machine type as a precondition")
    sp.add_argument("--requires-section", action="append", metavar="NAME",
                    default=[], help="require this section to exist (repeatable)")
    sp.add_argument("--requires-string", action="append", metavar="TEXT",
                    default=[], help="require this text in the target (repeatable)")
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

    sp = add("collection", "list/check/apply a set of bundles as one transaction")
    sp.add_argument("action", choices=["list", "graph", "check", "apply"])
    sp.add_argument("path", help="collection directory or manifest file")
    sp.add_argument("--target", help="binary to patch (check/apply)")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.add_argument("--require-signature", action="store_true")
    sp.add_argument("--trusted-key", action="append", metavar="HEX", default=[])
    sp.add_argument("--allow-abs-address", action="store_true")
    sp.add_argument("--keep-backups", type=int, default=3)
    sp.add_argument("--dry-run", action="store_true",
                    help="check only: preflight on a temp copy, write nothing")
    sp.add_argument("--lax", action="store_true")
    sp.set_defaults(func=cmd_collection)

    sp = add("repo", "index a folder of bundles / list / show / apply from it")
    sp.add_argument("action", choices=["index", "list", "show", "apply"])
    sp.add_argument("path", help="folder to index, or an existing repo index file")
    sp.add_argument("-o", "--output", default="", help="index to write (repo index)")
    sp.add_argument("--name", default="", help="repo name (index)")
    sp.add_argument("--description", default="", help="repo description (index)")
    sp.add_argument("--created", default="", help="created_utc stamp (index)")
    sp.add_argument("--id", dest="bundle_id", default="", help="bundle id (show/apply)")
    sp.add_argument("--target", default="", help="file to match (list) or patch (apply)")
    sp.add_argument("--dry-run", action="store_true", help="resolve+verify only")
    sp.add_argument("--yes", "-y", action="store_true")
    sp.add_argument("--accept-drift", action="store_true")
    sp.add_argument("--no-checksum", action="store_true")
    sp.add_argument("--require-signature", action="store_true")
    sp.add_argument("--trusted-key", action="append", metavar="HEX", default=[])
    sp.add_argument("--allow-abs-address", action="store_true")
    sp.add_argument("--force-unlock", action="store_true")
    sp.add_argument("--keep-backups", type=int, default=3)
    sp.add_argument("--lax", action="store_true")
    sp.set_defaults(func=cmd_repo)

    sp = add("tui", "pick bundles from a folder interactively, then apply them")
    sp.add_argument("--target", required=True, help="the binary you want to patch")
    sp.add_argument("--dir", default="", help="folder of .morph bundles (default: .)")
    sp.add_argument("--yes", "-y", action="store_true", help="do not ask again")
    sp.add_argument("--force-unlock", action="store_true")
    sp.set_defaults(func=cmd_tui)

    sp = add("demo", "write a synthetic demo app + patch bundle to a directory")
    sp.add_argument("--out", default="surreal-demo", help="output directory")
    sp.set_defaults(func=cmd_demo)

    sp = add("easy", "guided mode: pick a program, see your patches, apply safely")
    sp.add_argument("what", nargs="?", default="",
                    help="the .exe (or folder) to patch — dropped files welcome")
    sp.add_argument("--patch", action="append", metavar="FILE", default=[],
                    help="use this .morph file (repeatable)")
    sp.add_argument("--dir", action="append", metavar="DIR", default=[],
                    help="also look for .morph files here (repeatable)")
    sp.add_argument("--yes", "-y", action="store_true",
                    help="assume yes: apply every applicable patch")
    sp.set_defaults(func=cmd_easy)

    sp = add("doctor", "check that this machine, file and patches will work")
    sp.add_argument("what", nargs="?", default="",
                    help="the .exe (or folder) you are about to patch")
    sp.add_argument("--patch", action="append", metavar="FILE", default=[])
    sp.add_argument("--dir", action="append", metavar="DIR", default=[])
    sp.set_defaults(func=cmd_doctor)

    sp = add("undo", "put the original file back (same as revert, plainer)")
    sp.add_argument("target")
    sp.add_argument("--force-unlock", action="store_true",
                    help="break a lock left by a crashed run")
    sp.set_defaults(func=cmd_undo)

    sp = add("selftest", "end-to-end check on a synthetic PE (safe, no targets)")
    sp.add_argument("--keep", action="store_true", help="keep the temp workspace")
    sp.add_argument("--workdir", default=None)
    sp.set_defaults(func=cmd_selftest)

    return p


def _redirect_dropped_file(argv: List[str]) -> List[str]:
    """``surreal app.exe`` / drag-and-drop means easy mode, not an error.

    Windows hands a dropped file to the program as the first argument, and a
    first-time user will type the file name too. Anything that looks like a path
    and is not a known subcommand is routed to ``easy``.
    """
    if not argv or argv[0].startswith("-"):
        return argv
    known = {"init", "inspect", "scan", "diff", "info", "check", "apply",
             "revert", "undo", "sign", "keys", "verify", "collection", "repo",
             "tui", "demo", "selftest", "easy", "doctor", "help"}
    if argv[0] in known:
        return argv
    from . import wizard

    if wizard.looks_like_path(argv[0]):
        return ["easy"] + argv
    return argv


def _pause_if_double_clicked(code: int) -> None:
    """Keep the window open when the frozen .exe was started from Explorer.

    A console program that exits takes its window with it, so a first-time user
    who dragged a file onto ``surreal.exe`` and hit an error would see a flash and
    nothing else. Only in a frozen build with a real console attached, and only
    when something went wrong.
    """
    if code == EXIT_OK or not getattr(sys, "frozen", False):
        return
    try:
        if not (sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty()):
            return
    except (ValueError, OSError):
        return
    try:
        input("\n  Press Enter to close this window. ")
    except (EOFError, KeyboardInterrupt):
        pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    interactive = argv is None
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        # double-clicked .exe (or a bare `surreal` in a console): run easy mode
        # when somebody is there to answer, otherwise print the usage table
        if interactive and sys.stdin is not None and sys.stdin.isatty() \
                and sys.stdout is not None and sys.stdout.isatty():
            argv = ["easy"]
        else:
            parser.print_help()
            return EXIT_OK
    argv = _redirect_dropped_file(argv)
    args = parser.parse_args(argv)
    console = Console(json_mode=getattr(args, "json", False),
                      quiet=getattr(args, "quiet", False))
    for stream in (sys.stdout, sys.stderr):
        # never let an unencodable glyph crash a patch run; the Console already
        # downgrades to ASCII, this is the last line of defence
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    previous_budget = memguard.DEFAULT_BUDGET
    memguard.set_default(getattr(args, "max_mem", None))
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        code = args.func(args, console)
        _pause_if_double_clicked(code)
        return code
    except KeyboardInterrupt:
        console.err("interrupted")
        _pause_if_double_clicked(130)
        return 130
    except memguard.MemoryLimitError as exc:
        code = _die(console, str(exc), EXIT_IO)
        _pause_if_double_clicked(code)
        return code
    except BrokenPipeError:  # e.g. `surreal inspect x.exe | head`
        return EXIT_OK
    finally:
        memguard.restore(previous_budget)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
