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
    "hunks", "policy",
}
ALLOWED_TARGET_KEYS = {"filename", "size", "sha256", "pe", "authenticode", "sections"}
ALLOWED_HUNK_KEYS = {"anchor", "delta", "section", "rva", "offset", "expect",
                     "replace", "comment", "enabled"}
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

    @property
    def length(self) -> int:
        return len(self.replace)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.anchor is not None:
            out["anchor"] = self.anchor
            out["delta"] = self.delta
        if self.section is not None:
            out["section"] = self.section
        if self.rva is not None:
            out["rva"] = self.rva
        if self.offset is not None:
            out["offset"] = self.offset
        out["expect"] = " ".join("%02X" % v if v is not None else "??" for v in self.expect)
        out["replace"] = format_hex(self.replace)
        if self.comment:
            out["comment"] = self.comment
        if not self.enabled:
            out["enabled"] = False
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
            if "replace" not in h:
                raise BundleError("hunk %d has no 'replace' bytes" % i)
            try:
                replace = parse_hex_bytes(h["replace"])
            except ValueError as exc:
                raise BundleError("hunk %d replace: %s" % (i, exc)) from exc
            if not replace:
                raise BundleError("hunk %d has an empty 'replace'" % i)
            expect_raw = h.get("expect")
            if expect_raw is None:
                raise BundleError("hunk %d has no 'expect' bytes (refusing a blind patch)" % i)
            try:
                expect = parse_hex_tokens(expect_raw)
            except ValueError as exc:
                raise BundleError("hunk %d expect: %s" % (i, exc)) from exc
            if len(expect) != len(replace):
                raise BundleError(
                    "hunk %d: expect is %d bytes but replace is %d (size-changing "
                    "patches are not supported yet)" % (i, len(expect), len(replace)))
            anchor_idx = _opt_int(h.get("anchor"))
            if anchor_idx is not None and not (0 <= anchor_idx < len(anchors)):
                raise BundleError("hunk %d references anchor %d which does not exist"
                                  % (i, anchor_idx))
            hunks.append(Hunk(
                expect=expect, replace=replace, anchor=anchor_idx,
                delta=_opt_int(h.get("delta")) or 0,
                section=h.get("section"), rva=_opt_int(h.get("rva")),
                offset=_opt_int(h.get("offset")),
                comment=str(h.get("comment") or ""),
                enabled=bool(h.get("enabled", True)),
            ))
        if not hunks:
            raise BundleError("bundle contains no hunks — nothing to do")

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
            policy=policy,
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

    def summary(self) -> str:
        return "%s (%s) — %d hunk(s), target %s" % (
            self.name, self.id, len([h for h in self.hunks if h.enabled]),
            self.target.get("filename") or self.target.get("sha256", "?")[:12])


def _opt_int(v) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        raise BundleError("expected a number, got a boolean")
    try:
        return int(v)
    except (TypeError, ValueError) as exc:
        raise BundleError("expected an integer, got %r" % (v,)) from exc
