"""Apply / check / revert a ``.morph`` bundle against a target binary.

Invariants (see PLAN.md §3.3):

* nothing is written until *every* hunk resolved and verified;
* the original is backed up before the first byte is written;
* the write goes to ``<target>.surreal.tmp`` in the same directory and is
  promoted with ``os.replace`` (atomic on NTFS and POSIX);
* the PE checksum is recomputed so the image still loads cleanly;
* every mutation is journalled with before/after hashes.
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .journal import Journal, fsync_dir
from .lock import LockError, TargetLock
from .patchfile import Bundle, Hunk
from .pe import PE, PEError, fold_checksum, sum_words
from .scanner import ScanError, find_pattern
from .util import format_hex, sha256_file, sha256_bytes


class PatchError(Exception):
    def __init__(self, message: str, code: int = 3):
        super().__init__(message)
        self.code = code


@dataclass
class Resolved:
    index: int
    offset: int
    length: int
    expect: bytes
    replace: bytes
    located_by: str
    op: str = "patch"
    surgery: Optional[Any] = None

    @property
    def grows_file(self) -> bool:
        return self.op == "append"

    @property
    def shrinks_file(self) -> bool:
        return self.op == "truncate"


@dataclass
class Plan:
    target: str
    original_sha256: str
    resolved: List[Resolved] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    new_checksum: Optional[int] = None
    old_checksum: Optional[int] = None
    signature: Optional[Dict[str, Any]] = None
    relocs: List[Dict[str, Any]] = field(default_factory=list)
    checksum_applicable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "original_sha256": self.original_sha256,
            "hunks": [
                {"index": r.index, "op": r.op, "offset": r.offset,
                 "length": r.length,
                 **({"surgery": r.surgery.to_dict()}
                    if r.surgery is not None and hasattr(r.surgery, "to_dict") else {}),
                 "expect": format_hex(r.expect), "replace": format_hex(r.replace),
                 "located_by": r.located_by}
                for r in self.resolved
            ],
            "old_checksum": self.old_checksum,
            "new_checksum": self.new_checksum,
            "signature": self.signature,
            "relocations": self.relocs,
            "notes": self.notes,
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------- #
# identity
# --------------------------------------------------------------------------- #
def check_identity(bundle: Bundle, pe: PE, target_path: str, sha: str,
                   accept_drift: bool = False) -> List[str]:
    """Verify the bundle was authored for this file. Returns warnings."""
    warnings: List[str] = []
    tgt = bundle.target
    problems: List[str] = []

    want_size = tgt.get("size")
    if want_size is not None and int(want_size) != pe.size:
        problems.append("size %d (bundle expects %s)" % (pe.size, want_size))

    want_sha = (tgt.get("sha256") or "").lower()
    if want_sha and want_sha != sha:
        problems.append("sha256 %s… (bundle expects %s…)" % (sha[:16], want_sha[:16]))

    peinfo = tgt.get("pe") or {}
    if peinfo:
        if peinfo.get("machine") and int(peinfo["machine"], 0) != pe.machine:
            problems.append("machine 0x%04X vs 0x%s"
                            % (pe.machine, peinfo["machine"]))
        if peinfo.get("magic") and int(peinfo["magic"], 0) != pe.magic:
            problems.append("optional-header magic mismatch")
        if peinfo.get("entrypoint_rva") is not None and \
                int(peinfo["entrypoint_rva"]) != pe.entrypoint_rva:
            warnings.append("entry point moved (0x%X → 0x%X)"
                            % (int(peinfo["entrypoint_rva"]), pe.entrypoint_rva))

    want_name = tgt.get("filename")
    if want_name and want_name.lower() != os.path.basename(target_path).lower():
        warnings.append("bundle was authored against %r, target is %r"
                        % (want_name, os.path.basename(target_path)))

    # per-section fingerprints: warn only, sections legitimately shift
    for want in tgt.get("sections") or []:
        name = want.get("name")
        match = next((s for s in pe.sections if s.name == name), None)
        if match is None:
            warnings.append("section %r from the bundle is missing" % name)
            continue
        if want.get("raw_sha256") and match.raw_sha256 and \
                want["raw_sha256"] != match.raw_sha256:
            warnings.append("section %s differs from the authored build" % name)

    if problems:
        if accept_drift:
            warnings.append("drift accepted (--accept-drift): " + "; ".join(problems))
        else:
            raise PatchError(
                "target does not match this bundle: " + "; ".join(problems) +
                "\n  → patch the build the bundle was written for, or re-run with "
                "--accept-drift if you accept the risk", code=3)
    return warnings


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #
def resolve_anchor(bundle: Bundle, anchor_index: int, pe: PE) -> int:
    anchor = bundle.anchors[anchor_index]
    try:
        hits = find_pattern(pe.data, anchor.pattern, limit=64)
    except ScanError as exc:
        raise PatchError("anchor %d (%s) is unusable: %s"
                         % (anchor_index, anchor.name, exc)) from exc
    if not hits:
        raise PatchError("anchor %d (%s) not found — this is a different build of "
                         "the target" % (anchor_index, anchor.name), code=3)
    if len(hits) > 1:
        if anchor.unique:
            raise PatchError(
                "anchor %d (%s) matches %d places (expected exactly 1): %s"
                % (anchor_index, anchor.name, len(hits),
                   ", ".join("0x%X" % h for h in hits[:8])), code=3)
        if anchor.file_offset is not None and anchor.file_offset in hits:
            return anchor.file_offset
        raise PatchError("anchor %d (%s) is ambiguous (%d matches) and has no "
                         "file_offset to disambiguate" % (anchor_index, anchor.name, len(hits)),
                         code=3)
    # An anchor that moved is still an anchor — that is the whole point: the
    # hunk's expect-bytes are the final authority, and they are checked next.
    return hits[0]


def resolve_hunk(bundle: Bundle, hunk: Hunk, index: int, pe: PE,
                 anchor_offsets: Dict[int, int]) -> Resolved:
    if hunk.op == "append":
        # Only the overlay can grow: mapped sections cannot change size without
        # rewriting the section table, SizeOfImage and every later RVA.
        if pe.size > pe.last_section_end:
            pass  # there is an overlay already; we append after it
        return Resolved(index=index, offset=pe.size, length=len(hunk.replace),
                        expect=b"", replace=hunk.replace, located_by="end of file",
                        op="append")
    if hunk.op == "truncate":
        start = pe.size - len(hunk.expect)
        if start < pe.last_section_end:
            raise PatchError(
                "hunk %d: truncate would cut into section data (offset 0x%X is "
                "before the end of the last section, 0x%X) — shrinking the image "
                "is not supported" % (index, start, pe.last_section_end), code=3)
        if start < 0:
            raise PatchError("hunk %d: truncate removes more bytes than the file has"
                             % index, code=3)
        actual = bytes(pe.data[start:pe.size])
        if actual != bytes(hunk.expect):
            raise PatchError(
                "hunk %d: the file does not end with the bytes this bundle removes\n"
                "    expected tail: %s\n    found tail:    %s"
                % (index, format_hex(bytes(hunk.expect)), format_hex(actual)), code=3)
        return Resolved(index=index, offset=start, length=len(hunk.expect),
                        expect=actual, replace=b"", located_by="end of file",
                        op="truncate")

    candidates: List[tuple] = []
    if hunk.anchor is not None:
        base = anchor_offsets.get(hunk.anchor)
        if base is None:
            raise PatchError("hunk %d references unresolved anchor %d" % (index, hunk.anchor))
        candidates.append((base + hunk.delta, "anchor %d+%d" % (hunk.anchor, hunk.delta)))
    if hunk.section is not None and hunk.rva is not None:
        sec = next((s for s in pe.sections if s.name == hunk.section), None)
        if sec is not None:
            off = pe.rva_to_offset(hunk.rva)
            if off is not None and sec.contains_rva(hunk.rva):
                candidates.append((off, "section %s+rva 0x%X" % (hunk.section, hunk.rva)))
    if hunk.offset is not None:
        candidates.append((hunk.offset, "file offset 0x%X" % hunk.offset))

    if not candidates:
        raise PatchError("hunk %d has no usable locator (need anchor, section+rva or offset)"
                         % index)

    usable = [(o, how) for o, how in candidates if 0 <= o and o + hunk.length <= pe.size]
    if not usable:
        raise PatchError("hunk %d resolves outside the file" % index, code=3)

    # all locators must agree; disagreement means the bundle was edited by hand
    # or the build shifted in a way we cannot prove is safe
    if len({o for o, _ in usable}) > 1:
        raise PatchError(
            "hunk %d: locators disagree (%s) — refusing to guess"
            % (index, ", ".join("%s→0x%X" % (how, o) for o, how in usable)), code=3)

    offset, how = usable[0]
    expect = bytes(v if v is not None else 0 for v in hunk.expect)
    actual = bytes(pe.data[offset:offset + hunk.length])
    wildcards = [i for i, v in enumerate(hunk.expect) if v is None]
    mismatch = [i for i in range(hunk.length)
                if i not in wildcards and actual[i] != hunk.expect[i]]
    if mismatch:
        preview = format_hex(actual)
        raise PatchError(
            "hunk %d at 0x%X (%s) does not contain the expected original bytes\n"
            "    expected: %s\n    found:    %s\n"
            "    first mismatch at byte %d — the bundle was made for a different build"
            % (index, offset, how,
               " ".join("%02X" % v if v is not None else "??" for v in hunk.expect),
               preview, mismatch[0]), code=3)

    return Resolved(index=index, offset=offset, length=hunk.length, expect=actual,
                    replace=hunk.replace, located_by=how)


def check_signature(bundle: Bundle, require: bool = False, config_dir: Optional[str] = None,
                    extra_trusted: Optional[List[str]] = None) -> Dict[str, Any]:
    """Verify the bundle signature (if any) and report the outcome.

    An *invalid* signature is always fatal. An *untrusted* or *missing* one is
    fatal only when ``require=True`` — otherwise it is surfaced as a warning, so
    local authoring keeps working without ceremony.
    """
    from . import keys, policy

    cfg = config_dir or policy.config_dir()
    try:
        state, message, trusted = keys.check_bundle_signature(
            bundle.to_dict(), cfg, require=require, extra_trusted=extra_trusted)
    except keys.SignatureError as exc:
        raise PatchError("bundle signature check failed: %s" % exc, code=4) from exc
    return {"state": state, "message": message, "trusted": trusted,
            "signer": bundle.signer()}


def _precheck_size_ops(bundle: Bundle, accept_drift: bool) -> None:
    size_ops = [h.op for h in bundle.hunks if h.enabled and h.op != "patch"]
    ops = set(size_ops)
    if len(ops) > 1:
        raise PatchError(
            "a bundle may contain only one kind of size-changing hunk (found %s); "
            "mixing them makes the resulting layout ambiguous"
            % ", ".join(sorted(ops)), code=3)
    if len(size_ops) > 1:
        raise PatchError(
            "a bundle may contain only one size-changing hunk (%d found: %s); "
            "each one is planned against the original image, so they cannot be "
            "combined — use a collection for size-preserving patches"
            % (len(size_ops), ", ".join(size_ops)), code=3)
    if ops & {"append", "truncate", "extend-section", "add-section"}:
        if accept_drift:
            raise PatchError(
                "this bundle changes the size or layout of the file, which is only "
                "safe against the exact build it was authored for — re-run without "
                "--accept-drift", code=3)
        if any(h.anchor is not None or h.offset is not None for h in bundle.hunks
               if h.op in ("append", "truncate")):
            raise PatchError("overlay hunks cannot carry image locators", code=3)


def build_plan(bundle: Bundle, target_path: str, accept_drift: bool = False,
               require_signature: bool = False, config_dir: Optional[str] = None,
               extra_trusted: Optional[List[str]] = None,
               allow_abs_address: bool = False) -> Plan:
    if not os.path.isfile(target_path):
        raise PatchError("target not found: %s" % target_path, code=5)
    sha = sha256_file(target_path)
    _precheck_size_ops(bundle, accept_drift)
    try:
        pe = PE.open(target_path)
    except (PEError, OSError) as exc:
        # Non-PE targets are allowed when the bundle only needs raw offsets and
        # EOF operations (that is what `diff --force` produces).
        if _is_raw_bundle(bundle):
            return _build_raw_plan(bundle, target_path, sha, accept_drift,
                                   require_signature, config_dir, extra_trusted)
        raise PatchError("target is not a readable PE image: %s" % exc, code=3) from exc
    try:
        plan = Plan(target=os.path.abspath(target_path), original_sha256=sha)
        sig = check_signature(bundle, require=require_signature, config_dir=config_dir,
                              extra_trusted=extra_trusted)
        plan.signature = sig
        if sig["state"] != "valid":
            plan.warnings.append("signature: %s" % sig["message"])
        else:
            plan.notes.append("signature: %s" % sig["message"])
        plan.warnings.extend(check_identity(bundle, pe, target_path, sha, accept_drift))

        if pe.has_signature:
            plan.warnings.append(
                "target carries an Authenticode signature — patching invalidates it "
                "(Windows SmartScreen may warn afterwards)")

        anchor_offsets: Dict[int, int] = {}
        for i in range(len(bundle.anchors)):
            anchor_offsets[i] = resolve_anchor(bundle, i, pe)
            plan.notes.append("anchor %d (%s) → 0x%X"
                              % (i, bundle.anchors[i].name, anchor_offsets[i]))

        for idx, hunk in enumerate(bundle.hunks):
            if not hunk.enabled:
                plan.notes.append("hunk %d disabled, skipped" % idx)
                continue
            if hunk.op in ("extend-section", "add-section"):
                plan.resolved.append(resolve_surgery_hunk(hunk, idx, pe, plan))
                continue
            plan.resolved.append(resolve_hunk(bundle, hunk, idx, pe, anchor_offsets))

        _check_size_ops(plan, accept_drift)
        _check_overlaps([r for r in plan.resolved if r.op == "patch"],
                        has_size_ops=any(r.op != "patch" for r in plan.resolved))
        _check_relocations(pe, [r for r in plan.resolved if r.op == "patch"],
                           plan, allow_abs_address)

        plan.old_checksum = pe.stored_checksum
        if any(r.op != "patch" for r in plan.resolved):
            plan.new_checksum = None  # depends on the new size; computed on write
            plan.notes.append("file size changes: the PE checksum is recomputed "
                              "from the written file (size is part of the sum)")
        else:
            plan.new_checksum = _predict_checksum(pe, plan.resolved)
        return plan
    finally:
        pe.close()


def _check_overlaps(resolved: List[Resolved], has_size_ops: bool = False) -> None:
    ordered = sorted(resolved, key=lambda r: r.offset)
    for a, b in zip(ordered, ordered[1:]):
        if a.offset + a.length > b.offset:
            raise PatchError("hunks %d and %d overlap at 0x%X"
                             % (a.index, b.index, b.offset), code=3)
    if not resolved and not has_size_ops:
        raise PatchError("nothing to patch", code=3)


def _is_raw_bundle(bundle: Bundle) -> bool:
    """True when no hunk needs PE knowledge (raw offsets and EOF ops only)."""
    for h in bundle.hunks:
        if not h.enabled:
            continue
        if h.op != "patch":
            continue
        if h.offset is None or h.section is not None or h.rva is not None \
                or h.anchor is not None:
            return False
    return True


def _build_raw_plan(bundle: Bundle, target_path: str, sha: str,
                    accept_drift: bool, require_signature: bool,
                    config_dir: Optional[str], extra_trusted: Optional[List[str]]
                    ) -> Plan:
    size = os.path.getsize(target_path)
    plan = Plan(target=os.path.abspath(target_path), original_sha256=sha)
    sig = check_signature(bundle, require=require_signature, config_dir=config_dir,
                          extra_trusted=extra_trusted)
    plan.signature = sig
    if sig["state"] != "valid":
        plan.warnings.append("signature: %s" % sig["message"])
    else:
        plan.notes.append("signature: %s" % sig["message"])

    problems = []
    want_size = bundle.target.get("size")
    if want_size is not None and int(want_size) != size:
        problems.append("size %d (bundle expects %s)" % (size, want_size))
    want_sha = (bundle.target.get("sha256") or "").lower()
    if want_sha and want_sha != sha:
        problems.append("sha256 %s… (bundle expects %s…)" % (sha[:16], want_sha[:16]))
    if problems:
        if accept_drift:
            plan.warnings.append("drift accepted (--accept-drift): " + "; ".join(problems))
        else:
            raise PatchError("target does not match this bundle: " + "; ".join(problems),
                             code=3)
    if bundle.target.get("pe"):
        plan.warnings.append(
            "bundle records PE metadata but the target is not a readable PE — "
            "checksum handling is skipped")

    with open(target_path, "rb") as fh:
        head_tail = {}
        for idx, hunk in enumerate(bundle.hunks):
            if not hunk.enabled:
                plan.notes.append("hunk %d disabled, skipped" % idx)
                continue
            if hunk.op == "append":
                plan.resolved.append(Resolved(index=idx, offset=size,
                                              length=len(hunk.replace), expect=b"",
                                              replace=hunk.replace,
                                              located_by="end of file", op="append"))
                continue
            if hunk.op == "truncate":
                start = size - len(hunk.expect)
                if start < 0:
                    raise PatchError("hunk %d: truncate removes more than the file has"
                                     % idx, code=3)
                fh.seek(start)
                actual = fh.read(len(hunk.expect))
                if actual != bytes(hunk.expect):
                    raise PatchError("hunk %d: file tail does not match 'expect'"
                                     % idx, code=3)
                plan.resolved.append(Resolved(index=idx, offset=start,
                                              length=len(hunk.expect), expect=actual,
                                              replace=b"", located_by="end of file",
                                              op="truncate"))
                continue
            offset = int(hunk.offset or 0)
            if offset + hunk.length > size:
                raise PatchError("hunk %d resolves outside the file" % idx, code=3)
            fh.seek(offset)
            actual = bytes(fh.read(hunk.length))
            mask = [v is not None for v in hunk.expect]
            if any(m and actual[i] != hunk.expect[i] for i, m in enumerate(mask)):
                raise PatchError(
                    "hunk %d at 0x%X does not contain the expected original bytes\n"
                    "    expected: %s\n    found:    %s"
                    % (idx, offset,
                       " ".join("%02X" % v if v is not None else "??"
                                for v in hunk.expect), format_hex(actual)), code=3)
            plan.resolved.append(Resolved(index=idx, offset=offset, length=hunk.length,
                                          expect=actual, replace=hunk.replace,
                                          located_by="file offset 0x%X" % offset))
    _check_size_ops(plan, accept_drift)
    _check_overlaps([r for r in plan.resolved if r.op == "patch"],
                    has_size_ops=any(r.op != "patch" for r in plan.resolved))
    plan.new_checksum = None
    plan.checksum_applicable = False
    plan.notes.append("non-PE target: PE checksum is not applicable")
    return plan


def resolve_surgery_hunk(hunk: Hunk, index: int, pe: PE, plan: Plan) -> Resolved:
    """Validate an extend-section / add-section hunk and record its plan."""
    from . import surgery

    try:
        plan_obj = surgery.plan_for_hunk(pe, hunk, index)
    except surgery.SurgeryError as exc:
        raise PatchError("hunk %d (%s): %s" % (index, hunk.op, exc), code=3) from exc
    plan.notes.extend("hunk %d: %s" % (index, note) for note in plan_obj.notes)
    plan.notes.append(
        "hunk %d: %s → file %d bytes, SizeOfImage 0x%X (headers rewritten: %d field(s))"
        % (index, plan_obj.kind, plan_obj.file_size_after,
           plan_obj.image_size_after, len(plan_obj.writes)))
    return Resolved(index=index, offset=pe.size, length=len(hunk.replace),
                    expect=b"", replace=hunk.replace,
                    located_by="%s (header surgery)" % plan_obj.kind,
                    op=hunk.op, surgery=plan_obj)


def _check_size_ops(plan: Plan, accept_drift: bool) -> None:
    ops = {r.op for r in plan.resolved}
    if "append" in ops and "truncate" in ops:
        raise PatchError("a bundle cannot both append and truncate", code=3)
    if (ops & {"append", "truncate"}) and accept_drift:
        raise PatchError(
            "this bundle changes the file size (append/truncate), which is only "
            "safe against the exact build it was authored for — re-run without "
            "--accept-drift", code=3)


def _check_relocations(pe: PE, resolved: List[Resolved], plan: Plan,
                       allow_abs_address: bool) -> None:
    """ASLR safety: a hunk that rewrites an absolute address needs a fixup.

    Windows rebases images at load time using ``.reloc``. Writing a raw absolute
    address into a field that has no relocation entry produces a binary that
    works at one base and crashes at another — the classic "works on my machine".
    """
    from .reloc import analyse_hunks

    if not resolved:
        return
    risks = analyse_hunks(pe, resolved)
    for risk in risks:
        if not risk.reloc_hits:
            continue
        plan.relocs.append({"hunk": risk.index, "offset": risk.offset,
                            "rva": pe.offset_to_rva(risk.offset),
                            "entries": [{"rva": rva, "type": typ}
                                        for rva, typ in risk.reloc_hits]})
        message = ("%s — you are writing an absolute address; the loader only "
                   "fixes it up on rebase if a .reloc entry covers it "
                   "(check the patched build under a different base)"
                   % risk.describe(pe))
        if allow_abs_address:
            plan.warnings.append("ASLR risk accepted (--allow-abs-address): " + message)
        else:
            raise PatchError(
                message + "\n  → if you have verified the patched image loads at "
                "another base, re-run with --allow-abs-address", code=3)
    if not pe.dir(5)[0] and any(r.in_code for r in risks):
        plan.warnings.append(
            "target has no .reloc directory: it is either fixed-base or "
            "relocations were stripped, so absolute-address edits are never "
            "rebased")


def _predict_checksum(pe: PE, resolved: List[Resolved]) -> int:
    """Checksum of the image after the hunks are applied (no file is written).

    Only the bytes that actually change are re-summed: word-aligned windows
    around each hunk, widened by one byte so a hunk starting at an odd offset
    still accounts for the words it straddles.
    """
    total = pe.word_sum()
    skip = pe._checksum_offset
    mv = memoryview(pe.data)

    regions: List[List[int]] = []
    for r in sorted(resolved, key=lambda x: x.offset):
        start = r.offset & ~1
        end = min((r.offset + r.length + 1) & ~1, pe.size)
        if regions and start <= regions[-1][1]:
            regions[-1][1] = max(regions[-1][1], end)
        else:
            regions.append([start, end])

    for start, end in regions:
        if start < skip + 4 and end > skip:
            continue  # the CheckSum field itself: overwritten at write time
        old_sum = sum_words(mv[start:end])
        buf = bytearray(mv[start:end])
        for r in resolved:
            lo = max(start, r.offset)
            hi = min(end, r.offset + r.length)
            if lo < hi:
                buf[lo - start:hi - start] = r.replace[lo - r.offset:hi - r.offset]
        total += sum_words(memoryview(bytes(buf))) - old_sum

    return fold_checksum(total, pe.size)


# --------------------------------------------------------------------------- #
# applying
# --------------------------------------------------------------------------- #
def apply_bundle(bundle: Bundle, target_path: str, dry_run: bool = False,
                 no_backup: bool = False, no_checksum: bool = False,
                 accept_drift: bool = False, keep_backups: int = 3,
                 require_signature: bool = False, config_dir: Optional[str] = None,
                 extra_trusted: Optional[List[str]] = None,
                 allow_abs_address: bool = False, force_unlock: bool = False) -> Dict[str, Any]:
    blocked = bundle.is_policy_blocked()
    if blocked:
        raise PatchError("refusing to apply: " + blocked, code=4)

    plan = build_plan(bundle, target_path, accept_drift=accept_drift,
                      require_signature=require_signature, config_dir=config_dir,
                      extra_trusted=extra_trusted,
                      allow_abs_address=allow_abs_address)
    result: Dict[str, Any] = {
        "bundle": bundle.id,
        "name": bundle.name,
        "target": plan.target,
        "dry_run": dry_run,
        "hunks": len(plan.resolved),
        "signature": plan.signature,
        "relocations": plan.relocs,
        "notes": plan.notes,
        "warnings": plan.warnings,
        "old_checksum": plan.old_checksum,
        "new_checksum": plan.new_checksum,
    }
    if dry_run:
        result["sha256_before"] = plan.original_sha256
        result["sha256_after"] = "(dry run)"
        return result

    target = os.path.abspath(target_path)
    directory = os.path.dirname(target)
    ext = os.path.splitext(target)[1] or ".bin"

    lock = TargetLock(target, action="apply", bundle_id=bundle.id, force=force_unlock)
    try:
        lock.acquire()
    except LockError as exc:
        raise PatchError(str(exc), code=5) from exc

    tmp_fd, tmp_path = tempfile.mkstemp(prefix=".surreal-", suffix=ext + ".tmp", dir=directory)
    os.close(tmp_fd)

    journal = Journal(target)
    backup_path: Optional[str] = None
    try:
        # 1. copy (streamed, 1 MiB) — never load the binary in memory
        shutil.copyfile(target, tmp_path)
        if sha256_file(tmp_path) != plan.original_sha256:
            raise PatchError("working copy is not identical to the target (disk error?)",
                             code=5)

        # 2. patch the copy
        size_changed = any(r.op != "patch" for r in plan.resolved)
        surgery_ops = [r for r in plan.resolved if r.op in ("extend-section",
                                                            "add-section")]
        with open(tmp_path, "r+b") as fh:
            for r in sorted(plan.resolved, key=lambda x: x.offset):
                if r.op in ("extend-section", "add-section"):
                    _write_surgery(fh, r)
                elif r.op == "append":
                    fh.seek(0, os.SEEK_END)
                    fh.write(r.replace)
                elif r.op == "truncate":
                    fh.seek(r.offset)
                    fh.truncate()
                else:
                    fh.seek(r.offset)
                    fh.write(r.replace)
            fh.flush()
            if not no_checksum and plan.checksum_applicable:
                csum = _checksum_of_file(tmp_path) if size_changed \
                    else (plan.new_checksum or 0)
                _write_checksum(fh, csum)
            fh.flush()
            os.fsync(fh.fileno())

        new_sha = sha256_file(tmp_path)

        # 3. verify the result still looks like what we aimed for
        if plan.checksum_applicable:
            try:
                with PE.open(tmp_path) as pe2:
                    if not no_checksum and not pe2.checksum_valid():
                        raise PatchError("post-patch checksum verification failed",
                                         code=5)
            except PEError as exc:
                raise PatchError("patched copy is no longer a valid PE (%s) — original "
                                 "untouched" % exc, code=5) from exc
        else:
            _verify_surgery(target, plan.resolved, tmp_path)
            # raw bundle: at least prove every written hunk reads back
            with open(tmp_path, "rb") as fh:
                for r in plan.resolved:
                    if r.op == "truncate":
                        continue
                    fh.seek(r.offset)
                    if fh.read(len(r.replace)) != r.replace:
                        raise PatchError("hunk %d did not read back after writing"
                                         % r.index, code=5)

        # 4. backup, then atomically swap in the patched copy
        if not no_backup:
            backup_path = journal.backup(bundle.id)
        os.replace(tmp_path, target)
        fsync_dir(directory)

        result.update({
            "sha256_before": plan.original_sha256,
            "sha256_after": new_sha,
            "backup": backup_path,
            "bytes_written": sum(len(r.replace) for r in plan.resolved
                                 if r.op != "truncate"),
            "bytes_removed": sum(r.length for r in plan.resolved
                                 if r.op == "truncate"),
            "size_after": os.path.getsize(target),
        })
        journal.record(
            "apply", bundle_id=bundle.id, bundle_name=bundle.name,
            bundle_sha256=sha256_file(bundle.path) if bundle.path else None,
            sha256_before=plan.original_sha256, sha256_after=new_sha,
            backup=backup_path, hunks=[r.index for r in plan.resolved],
            checksum_recomputed=not no_checksum,
        )
        if keep_backups > 0:
            result["pruned"] = journal.prune(keep_backups)
        return result
    except BaseException:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise
    finally:
        lock.release()


def _checksum_of_file(path: str) -> int:
    """Checksum of an arbitrary on-disk image (needed when the size changed)."""
    with PE.open(path) as pe:
        return pe.compute_checksum()


def _write_surgery(fh, resolved: Resolved) -> None:
    """Apply one header-surgery op to the working copy."""
    surg = resolved.surgery
    if surg is None:
        raise PatchError("hunk %d has no surgery plan" % resolved.index, code=5)
    for offset, data in surg.writes:
        fh.seek(offset)
        existing = fh.read(len(data))
        fh.seek(offset)
        fh.write(data)
        if existing == data:
            continue
    fh.seek(0, os.SEEK_END)
    fh.write(surg.payload)


def _verify_surgery(target_path: str, resolved: List[Resolved], tmp_path: str) -> None:
    """Prove the rewritten layout is exactly what the plan promised."""
    from . import surgery

    ops = [r for r in resolved if r.surgery is not None]
    if not ops:
        return
    try:
        with PE.open(target_path) as before:
            for r in ops:
                surgery.verify_after(before, r.surgery, tmp_path)
    except surgery.SurgeryError as exc:
        raise PatchError("%s — original untouched" % exc, code=5) from exc


def _write_checksum(fh, checksum: int) -> None:
    fh.seek(0x3C)
    lfanew = struct.unpack("<I", fh.read(4))[0]
    # CheckSum field lives at OptionalHeader + 64 == e_lfanew + 24 + 64
    fh.seek(lfanew + 88)
    fh.write(struct.pack("<I", checksum & 0xFFFFFFFF))


# --------------------------------------------------------------------------- #
# reverting
# --------------------------------------------------------------------------- #
def revert(target_path: str, force_unlock: bool = False) -> Dict[str, Any]:
    target = os.path.abspath(target_path)
    if not os.path.isfile(target):
        raise PatchError("target not found: %s" % target, code=5)
    lock = TargetLock(target, action="revert", force=force_unlock)
    try:
        lock.acquire()
    except LockError as exc:
        raise PatchError(str(exc), code=5) from exc
    try:
        return _revert_locked(target)
    finally:
        lock.release()


def _revert_locked(target: str) -> Dict[str, Any]:
    journal = Journal(target)
    entry = journal.last(actions=("apply", "apply-collection", "revert"))
    if entry is None:
        raise PatchError("no journal entries for %s — nothing to revert" % target, code=3)
    if entry.get("action") == "revert":
        raise PatchError("the last recorded action was already a revert", code=3)
    backup = entry.get("backup")
    if not backup or not os.path.isfile(backup):
        raise PatchError("backup missing: %s" % backup, code=5)

    current_sha = sha256_file(target)
    if entry.get("sha256_after") and current_sha != entry["sha256_after"]:
        raise PatchError(
            "target changed since it was patched (sha256 %s… vs expected %s…); "
            "refusing to overwrite — restore %s manually if you mean it"
            % (current_sha[:16], entry["sha256_after"][:16], backup), code=3)

    directory = os.path.dirname(target)
    ext = os.path.splitext(target)[1] or ".bin"
    fd, tmp_path = tempfile.mkstemp(prefix=".surreal-", suffix=ext + ".tmp", dir=directory)
    os.close(fd)
    try:
        shutil.copyfile(backup, tmp_path)
        if sha256_file(tmp_path) != entry.get("sha256_before"):
            raise PatchError("backup does not match the recorded pre-patch hash", code=5)
        os.replace(tmp_path, target)
        fsync_dir(directory)
    except BaseException:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise

    restored = sha256_file(target)
    journal.record("revert", bundle_id=entry.get("bundle_id"), backup=backup,
                   sha256_before=current_sha, sha256_after=restored)
    return {"target": target, "restored_sha256": restored,
            "was_sha256": current_sha, "backup": backup,
            "bundle_id": entry.get("bundle_id"),
            "collection": entry.get("collection"),
            "action": entry.get("action")}
