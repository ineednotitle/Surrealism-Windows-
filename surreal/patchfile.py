"""``.morph`` bundle: schema, validation and IO.

A bundle is ordinary JSON. It is intentionally boring: text, diffable in a PR,
and impossible to hold executable code. See ``docs/PATCH_FORMAT.md``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import FORMAT_NAME, FORMAT_VERSION, TOOL_NAME, __version__
from .util import format_hex, parse_hex_bytes, parse_hex_tokens, read_json, write_json_atomic

ALLOWED_KEYS = {
    "format", "format_version", "id", "name", "version", "description", "notes",
    "created_utc", "author", "homepage", "license", "tool", "target", "anchors",
    "hunks", "policy", "signature", "requires",
}
ALLOWED_TARGET_KEYS = {"filename", "size", "sha256", "pe", "authenticode", "sections"}
ALLOWED_HUNK_KEYS = {"op", "anchor", "delta", "section", "rva", "offset",
                     "expect", "replace", "comment", "enabled", "when",
                     "raw_size_before", "virtual_size_after", "characteristics",
                     "name"}
HUNK_OPS = {"patch", "append", "truncate", "extend-section", "add-section"}
IMAGE_OPS = {"extend-section", "add-section"}
ALLOWED_ANCHOR_KEYS = {"name", "pattern", "file_offset", "rva", "section", "unique",
                       "comment"}

FORBIDDEN_CATEGORIES = {
    "drm", "license-bypass", "licence-bypass", "activation", "anti-cheat",
    "anticheat", "anti-tamper", "antitamper", "trial-reset", "paywall",
    "telemetry-suppression-for-fraud",
}


class BundleError(Exception):
    """Bundle is malformed or fails validation."""


@dataclass
class Hunk:
    expect: List[Optional[int]]
    replace: bytes
    anchor: Optional[int] = None
    delta: int = 0
    section: Optional[str] = None
    rva: Optional[int] = None
    offset: Optional[int] = None
    comment: str = ""
    enabled: bool = True
    op: str = "patch"
    raw_size_before: Optional[int] = None
    virtual_size_after: Optional[int] = None
    characteristics: Optional[int] = None
    name: Optional[str] = None
    when: Optional[Dict[str, Any]] = None

    @property
    def length(self) -> int:
        return len(self.replace)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.op != "patch":
            out["op"] = self.op
        if self.anchor is not None:
            out["anchor"] = self.anchor
            out["delta"] = self.delta
        if self.section is not None:
            out["section"] = self.section
        if self.rva is not None:
            out["rva"] = self.rva
        if self.offset is not None:
            out["offset"] = self.offset
        if self.raw_size_before is not None:
            out["raw_size_before"] = self.raw_size_before
        if self.virtual_size_after is not None:
            out["virtual_size_after"] = self.virtual_size_after
        if self.characteristics is not None:
            out["characteristics"] = "0x%08X" % self.characteristics
        if self.name:
            out["name"] = self.name
        if self.expect:
            out["expect"] = " ".join("%02X" % v if v is not None else "??"
                                     for v in self.expect)
        out["replace"] = format_hex(self.replace)
        if self.comment:
            out["comment"] = self.comment
        if not self.enabled:
            out["enabled"] = False
        if self.when:
            out["when"] = self.when
        return out


@dataclass
class Anchor:
    name: str
    pattern: List[Optional[int]]
    file_offset: Optional[int] = None
    rva: Optional[int] = None
    section: Optional[str] = None
    unique: bool = True
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "name": self.name,
            "pattern": " ".join("%02X" % v if v is not None else "??" for v in self.pattern),
            "unique": self.unique,
        }
        if self.file_offset is not None:
            out["file_offset"] = self.file_offset
        if self.rva is not None:
            out["rva"] = self.rva
        if self.section is not None:
            out["section"] = self.section
        if self.comment:
            out["comment"] = self.comment
        return out


@dataclass
class Policy:
    requires_rights_attestation: bool = True
    forbidden_categories: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requires_rights_attestation": self.requires_rights_attestation,
            "forbidden_categories": list(self.forbidden_categories),
        }


@dataclass
class Bundle:
    id: str
    name: str
    target: Dict[str, Any]
    hunks: List[Hunk] = field(default_factory=list)
    anchors: List[Anchor] = field(default_factory=list)
    description: str = ""
    notes: str = ""
    version: str = "1.0.0"
    author: str = ""
    homepage: str = ""
    license: str = ""
    created_utc: str = ""
    tool: Dict[str, str] = field(default_factory=dict)
    policy: Policy = field(default_factory=Policy)
    requires: List[Dict[str, Any]] = field(default_factory=list)
    signature: Optional[Dict[str, Any]] = None
    path: Optional[str] = None
    strict: bool = True

    # -- serialisation ------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "format": FORMAT_NAME,
            "format_version": FORMAT_VERSION,
            "id": self.id,
            "name": self.name,
        }
        if self.version:
            out["version"] = self.version
        if self.description:
            out["description"] = self.description
        if self.notes:
            out["notes"] = self.notes
        if self.created_utc:
            out["created_utc"] = self.created_utc
        if self.author:
            out["author"] = self.author
        if self.homepage:
            out["homepage"] = self.homepage
        if self.license:
            out["license"] = self.license
        out["tool"] = self.tool or {"name": TOOL_NAME, "version": __version__}
        out["target"] = self.target
        if self.anchors:
            out["anchors"] = [a.to_dict() for a in self.anchors]
        out["hunks"] = [h.to_dict() for h in self.hunks]
        out["policy"] = self.policy.to_dict()
        if self.requires:
            out["requires"] = self.requires
        if self.signature:
            out["signature"] = self.signature
        return out

    def save(self, path: str) -> None:
        write_json_atomic(path, self.to_dict())
        self.path = path

    # -- loading ------------------------------------------------------------ #
    @classmethod
    def load(cls, path: str, strict: bool = True) -> "Bundle":
        if not os.path.isfile(path):
            raise BundleError("bundle not found: %s" % path)
        try:
            raw = read_json(path)
        except json.JSONDecodeError as exc:
            raise BundleError("bundle is not valid JSON: %s" % exc) from exc
        except UnicodeDecodeError as exc:
            raise BundleError("bundle is not UTF-8 text (a .morph is JSON, never "
                              "a binary): %s" % exc) from exc
        except OSError as exc:
            raise BundleError("cannot read bundle: %s" % exc) from exc
        if not isinstance(raw, dict):
            raise BundleError("bundle root must be a JSON object")
        b = cls.from_dict(raw, strict=strict)
        b.path = path
        return b

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], strict: bool = True) -> "Bundle":
        if strict:
            unknown = set(raw) - ALLOWED_KEYS
            if unknown:
                raise BundleError("unknown bundle keys: %s (use --lax to ignore)"
                                  % ", ".join(sorted(unknown)))
        fmt = raw.get("format", FORMAT_NAME)
        if fmt != FORMAT_NAME:
            raise BundleError("not a %s bundle (format=%r)" % (FORMAT_NAME, fmt))
        ver = raw.get("format_version", FORMAT_VERSION)
        if ver != FORMAT_VERSION:
            raise BundleError("unsupported format_version %r (this build reads %d)"
                              % (ver, FORMAT_VERSION))
        bid = raw.get("id")
        if not bid or not isinstance(bid, str):
            raise BundleError("bundle needs a string 'id'")
        target = raw.get("target")
        if not isinstance(target, dict):
            raise BundleError("bundle needs a 'target' object")
        if strict:
            unknown = set(target) - ALLOWED_TARGET_KEYS
            if unknown:
                raise BundleError("unknown target keys: %s" % ", ".join(sorted(unknown)))
        if not target.get("filename") and not target.get("sha256") and not target.get("size"):
            raise BundleError("target needs at least one of filename/size/sha256")

        anchors: List[Anchor] = []
        for i, a in enumerate(raw.get("anchors") or []):
            if strict and set(a) - ALLOWED_ANCHOR_KEYS:
                raise BundleError("anchor %d has unknown keys: %s"
                                  % (i, ", ".join(sorted(set(a) - ALLOWED_ANCHOR_KEYS))))
            if not isinstance(a.get("pattern", ""), str):
                raise BundleError("anchor %d pattern must be a hex string, not %s"
                                  % (i, type(a.get("pattern")).__name__))
            try:
                pattern = parse_hex_tokens(a.get("pattern", ""))
            except ValueError as exc:
                raise BundleError("anchor %d pattern: %s" % (i, exc)) from exc
            if len(pattern) < 2:
                raise BundleError("anchor %d pattern must be at least 2 bytes" % i)
            anchors.append(Anchor(
                name=str(a.get("name") or "anchor%d" % i), pattern=pattern,
                file_offset=_opt_int(a.get("file_offset")),
                rva=_opt_int(a.get("rva")),
                section=a.get("section"),
                unique=bool(a.get("unique", True)),
                comment=str(a.get("comment") or ""),
            ))

        hunks: List[Hunk] = []
        for i, h in enumerate(raw.get("hunks") or []):
            if not isinstance(h, dict):
                raise BundleError("hunk %d must be an object" % i)
            if strict and set(h) - ALLOWED_HUNK_KEYS:
                raise BundleError("hunk %d has unknown keys: %s"
                                  % (i, ", ".join(sorted(set(h) - ALLOWED_HUNK_KEYS))))
            op = str(h.get("op") or "patch")
            if op not in HUNK_OPS:
                raise BundleError("hunk %d: unknown op %r (expected one of %s)"
                                  % (i, op, ", ".join(sorted(HUNK_OPS))))
            if "replace" not in h:
                raise BundleError("hunk %d has no 'replace' bytes" % i)
            try:
                raw_replace = h["replace"]
                if not str(raw_replace).strip() and op == "truncate":
                    replace = b""
                else:
                    replace = parse_hex_bytes(raw_replace)
            except ValueError as exc:
                raise BundleError("hunk %d replace: %s" % (i, exc)) from exc
            expect_raw = h.get("expect")
            if expect_raw is None and op in ("append", "extend-section",
                                             "add-section"):
                expect_raw = ""
            if expect_raw is None:
                raise BundleError("hunk %d has no 'expect' bytes (refusing a blind patch)" % i)
            try:
                expect = parse_hex_tokens(expect_raw) if str(expect_raw).strip() else []
            except ValueError as exc:
                raise BundleError("hunk %d expect: %s" % (i, exc)) from exc

            if op == "patch":
                if not replace:
                    raise BundleError("hunk %d has an empty 'replace'" % i)
                if len(expect) != len(replace):
                    raise BundleError(
                        "hunk %d: expect is %d bytes but replace is %d — an "
                        "in-place hunk cannot change the size (use op "
                        "\"append\"/\"truncate\" for overlay changes)"
                        % (i, len(expect), len(replace)))
            elif op == "append":
                if not replace:
                    raise BundleError("hunk %d: append needs bytes to append" % i)
                if expect:
                    raise BundleError("hunk %d: append hunks carry no 'expect' "
                                      "(the target sha256 is the precondition)" % i)
                if h.get("anchor") is not None or h.get("section") is not None:
                    raise BundleError("hunk %d: append hunks attach to the end of "
                                      "the file and cannot be anchored" % i)
            elif op == "truncate":
                if not expect:
                    raise BundleError("hunk %d: truncate needs the bytes it removes "
                                      "in 'expect'" % i)
                if replace:
                    raise BundleError("hunk %d: truncate cannot replace bytes" % i)
            elif op in IMAGE_OPS:
                if expect:
                    raise BundleError(
                        "hunk %d: %s carries no 'expect' (the target identity and "
                        "the declared geometry are the preconditions)" % (i, op))
                if not replace:
                    raise BundleError("hunk %d: %s needs bytes to append" % (i, op))
                if h.get("anchor") is not None or h.get("offset") is not None:
                    raise BundleError("hunk %d: %s cannot be anchored or offset-based"
                                      % (i, op))
                if op == "extend-section" and not h.get("section"):
                    raise BundleError("hunk %d: extend-section needs a 'section' name"
                                      % i)
                if op == "add-section":
                    if not h.get("name"):
                        raise BundleError("hunk %d: add-section needs a 'name'" % i)
                    if h.get("characteristics") is None:
                        raise BundleError("hunk %d: add-section needs "
                                          "'characteristics'" % i)
            anchor_idx = _opt_int(h.get("anchor"))
            if anchor_idx is not None and not (0 <= anchor_idx < len(anchors)):
                raise BundleError("hunk %d references anchor %d which does not exist"
                                  % (i, anchor_idx))
            hunks.append(Hunk(
                op=op, expect=expect, replace=replace, anchor=anchor_idx,
                raw_size_before=_opt_int(h.get("raw_size_before")),
                virtual_size_after=_opt_int(h.get("virtual_size_after")),
                characteristics=_parse_characteristics(h.get("characteristics")),
                name=h.get("name"),
                delta=_opt_int(h.get("delta")) or 0,
                section=h.get("section"), rva=_opt_int(h.get("rva")),
                offset=_opt_int(h.get("offset")),
                comment=str(h.get("comment") or ""),
                enabled=bool(h.get("enabled", True)),
                when=_parse_condition(h.get("when"), "hunk %d when" % i),
            ))
        if not hunks:
            raise BundleError("bundle contains no hunks — nothing to do")

        requires = _parse_conditions(raw.get("requires"), "requires")

        pol_raw = raw.get("policy") or {}
        policy = Policy(
            requires_rights_attestation=bool(pol_raw.get("requires_rights_attestation", True)),
            forbidden_categories=[str(c).lower() for c in
                                  (pol_raw.get("forbidden_categories") or [])],
        )

        return cls(
            id=bid,
            name=str(raw.get("name") or bid),
            target=target,
            hunks=hunks,
            anchors=anchors,
            description=str(raw.get("description") or ""),
            notes=str(raw.get("notes") or ""),
            version=str(raw.get("version") or "1.0.0"),
            author=str(raw.get("author") or ""),
            homepage=str(raw.get("homepage") or ""),
            license=str(raw.get("license") or ""),
            created_utc=str(raw.get("created_utc") or ""),
            tool=raw.get("tool") or {},
            requires=requires,
            policy=policy,
            signature=raw.get("signature"),
            strict=strict,
        )

    # -- helpers ------------------------------------------------------------ #
    def is_policy_blocked(self) -> Optional[str]:
        """Return a human reason when the bundle declares a prohibited category."""
        cats = {c.lower() for c in self.policy.forbidden_categories}
        if cats & FORBIDDEN_CATEGORIES:
            return ("bundle declares prohibited category: %s"
                    % ", ".join(sorted(cats & FORBIDDEN_CATEGORIES)))
        haystack = " ".join([self.id, self.name, self.description, self.notes]).lower()
        for word in ("keygen", "crack", "activation bypass", "serial generator"):
            if word in haystack:
                return "bundle description advertises %r" % word
        return None

    def signer(self) -> str:
        """Human label for the signature block, or an empty string."""
        if not self.signature:
            return ""
        who = self.signature.get("signer") or "(unnamed)"
        key = (self.signature.get("public_key") or "")[:16]
        return "%s [%s…]" % (who, key)

    def summary(self) -> str:
        return "%s (%s) — %d hunk(s), target %s" % (
            self.name, self.id, len([h for h in self.hunks if h.enabled]),
            self.target.get("filename") or self.target.get("sha256", "?")[:12])


def _parse_condition(value, where: str):
    """Validate one declarative condition (see ``surreal/script.py``)."""
    if value is None:
        return None
    from . import script

    try:
        return script.validate(value, where)
    except script.ScriptError as exc:
        raise BundleError(str(exc)) from exc


def _parse_conditions(value, where: str):
    from . import script

    try:
        return script.validate_all(value, where)
    except script.ScriptError as exc:
        raise BundleError(str(exc)) from exc


def _parse_characteristics(v) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError as exc:
            raise BundleError("characteristics must be a number, got %r" % (v,)) from exc
    return _opt_int(v)


def _opt_int(v) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        raise BundleError("expected a number, got a boolean")
    try:
        return int(v)
    except (TypeError, ValueError) as exc:
        raise BundleError("expected an integer, got %r" % (v,)) from exc
