"""Declarative conditions — the "scripting" a ``.morph`` bundle is allowed to have.

A patch bundle is data, and it stays data: there is no code to execute, no
``eval``, no shell, no file access beyond the target you already named. What a
bundle *can* do is describe the build it expects and make its own hunks
conditional on facts it can read back from the image:

.. code-block:: json

    "requires": [
        {"machine": "x64"},
        {"section": ".rdata"},
        {"string": "Free trial version"}
    ],
    "hunks": [
        {"offset": "0x1200", "expect": "74 12", "replace": "EB 12",
         "when": {"has_string": "Free trial version"}}
    ]

That gives patch authors the useful part of scripting — "apply this only if that
text is still there", "refuse on 32-bit builds", "skip the licence banner hunk if
this version moved it" — with none of the risk. Every atom is a read-only
question about the already-parsed image, and the whole expression is bounded so a
malicious bundle cannot turn ``check`` into a denial of service.

Vocabulary (each condition is a JSON object with exactly one of these keys):

====================  ============================================================
``all`` / ``any``     list of conditions, logical and / or
``not``               one condition to invert
``machine``           ``"x64"``, ``"x86"``, ``"arm64"`` (string or list)
``is_dotnet``         bool — managed assembly
``is_dll``            bool
``has_overlay``       bool — bytes after the last section
``has_signature``     bool — an Authenticode directory is present
``section``           section name must exist (``{"section": ".vmp0", "exists": false}`` to invert)
``section_is_executable``  section name must be marked executable
``string``            ASCII text occurs in the file
``utf16``             UTF-16LE text occurs in the file
``pattern``           hex pattern with ``??`` wildcards occurs in the file
``size_at_least``     file size in bytes (int)
``size_at_most``      file size in bytes (int)
====================  ============================================================
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

MAX_NODES = 32
MAX_TEXT = 4096          # longest string/pattern a condition may search for
MAX_LIST = 64            # longest all/any list

LOGIC_KEYS = {"all", "any", "not"}
ATOM_KEYS = {"machine", "is_dotnet", "is_dll", "has_overlay", "has_signature",
             "section", "section_is_executable", "string", "utf16", "pattern",
             "size_at_least", "size_at_most"}
ALLOWED_KEYS = LOGIC_KEYS | ATOM_KEYS | {"comment", "exists"}

MACHINES = {"x64": {"x64", "amd64", "0x8664"}, "x86": {"x86", "i386", "0x14C"},
            "arm64": {"arm64", "aarch64", "0xAA64"}, "arm": {"arm", "0x1C0"}}


class ScriptError(Exception):
    """A condition that cannot be understood — always refused, never guessed."""


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
def _count(node: Any, depth: int = 0) -> int:
    if not isinstance(node, dict) or depth > 8:
        return MAX_NODES + 1
    total = 1
    for key in ("all", "any"):
        if key in node:
            items = node[key]
            if isinstance(items, list):
                for item in items:
                    total += _count(item, depth + 1)
    if "not" in node:
        total += _count(node["not"], depth + 1)
    return total


def validate(cond: Any, where: str = "condition") -> Dict[str, Any]:
    """Check a condition tree and return it unchanged; raise ``ScriptError``."""
    if not isinstance(cond, dict):
        raise ScriptError("%s must be a JSON object, not %s"
                          % (where, type(cond).__name__))
    unknown = set(cond) - ALLOWED_KEYS
    if unknown:
        raise ScriptError("%s has unknown keys: %s (allowed: %s)"
                          % (where, ", ".join(sorted(unknown)),
                             ", ".join(sorted(ALLOWED_KEYS))))
    if "exists" in cond and "section" not in cond:
        raise ScriptError("%s: 'exists' only makes sense with 'section'" % where)
    logic = [k for k in LOGIC_KEYS if k in cond]
    atoms = [k for k in ATOM_KEYS if k in cond]
    if not logic and not atoms:
        raise ScriptError("%s is empty — give it one of %s"
                          % (where, ", ".join(sorted(ALLOWED_KEYS
                                                     - {"comment", "exists"}))))
    if logic and atoms:
        raise ScriptError("%s mixes logic (%s) with a test (%s); nest them instead"
                          % (where, logic[0], atoms[0]))
    if len(logic) > 1:
        raise ScriptError("%s has more than one of all/any/not" % where)
    if _count(cond) > MAX_NODES:
        raise ScriptError("%s is too big (more than %d parts); split the patch"
                          % (where, MAX_NODES))

    for key in ("all", "any"):
        if key in cond:
            items = cond[key]
            if not isinstance(items, list) or not items:
                raise ScriptError("%s.%s must be a non-empty list" % (where, key))
            if len(items) > MAX_LIST:
                raise ScriptError("%s.%s has more than %d entries"
                                  % (where, key, MAX_LIST))
            for index, item in enumerate(items):
                validate(item, "%s.%s[%d]" % (where, key, index))
    if "not" in cond:
        validate(cond["not"], where + ".not")

    if "machine" in cond:
        value = cond["machine"]
        values = value if isinstance(value, list) else [value]
        if not values or not all(isinstance(v, str) for v in values):
            raise ScriptError("%s.machine must be a string or a list of strings"
                              % where)
        for item in values:
            if item.lower() not in MACHINES:
                raise ScriptError("%s.machine: unknown value %r (known: %s)"
                                  % (where, item, ", ".join(sorted(MACHINES))))
    for key in ("is_dotnet", "is_dll", "has_overlay", "has_signature"):
        if key in cond and not isinstance(cond[key], bool):
            raise ScriptError("%s.%s must be true or false" % (where, key))
    for key in ("size_at_least", "size_at_most"):
        if key in cond:
            value = cond[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ScriptError("%s.%s must be a non-negative integer"
                                  % (where, key))
    for key in ("section", "section_is_executable"):
        if key in cond:
            if not isinstance(cond[key], str) or not cond[key].strip():
                raise ScriptError("%s.%s must be a section name" % (where, key))
            if len(cond[key]) > 8:
                raise ScriptError("%s.%s: section names are at most 8 characters"
                                  % (where, key))
    if "section" in cond and "exists" in cond and not isinstance(cond["exists"], bool):
        raise ScriptError("%s.exists must be true or false" % where)
    for key in ("string", "utf16", "pattern"):
        if key in cond:
            value = cond[key]
            if not isinstance(value, str) or not value:
                raise ScriptError("%s.%s must be a non-empty string" % (where, key))
            if len(value) > MAX_TEXT:
                raise ScriptError("%s.%s is longer than %d characters"
                                  % (where, key, MAX_TEXT))
    if "comment" in cond and not isinstance(cond["comment"], str):
        raise ScriptError("%s.comment must be text" % where)
    return cond


def validate_all(conditions: Any, where: str = "requires") -> List[Dict[str, Any]]:
    if conditions is None:
        return []
    if not isinstance(conditions, list):
        raise ScriptError("%s must be a list of conditions" % where)
    if len(conditions) > MAX_LIST:
        raise ScriptError("%s has more than %d entries" % (where, MAX_LIST))
    return [validate(cond, "%s[%d]" % (where, i))
            for i, cond in enumerate(conditions)]


# --------------------------------------------------------------------------- #
# evaluation
# --------------------------------------------------------------------------- #
def _hex_to_regex(pattern: str) -> bytes:
    """Turn ``"48 8B ?? E8"`` into a compiled bytes regex."""
    tokens = pattern.replace(",", " ").split()
    parts = []
    for token in tokens:
        token = token.strip()
        if token in ("?", "??"):
            parts.append(b".")
            continue
        token = token.replace("?", "")
        if len(token) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", token):
            raise ScriptError("pattern %r is not hex (use bytes like \"48 8B ??\")"
                              % pattern)
        parts.append(b"".join(re.escape(bytes([int(token[i:i + 2], 16)]))
                              for i in range(0, len(token), 2)))
    if not parts:
        raise ScriptError("pattern is empty")
    return re.compile(b"".join(parts), re.DOTALL)


class _View:
    """Read-only facts about one image, computed lazily and at most once."""

    def __init__(self, data, pe=None) -> None:
        self.data = data
        self._provided_pe = pe
        self._cache: Dict[str, Any] = {}

    @property
    def pe(self):
        """Parse the image on first use; ``None`` when it is not a PE at all."""
        if "pe" not in self._cache:
            if self._provided_pe is not None:
                self._cache["pe"] = self._provided_pe
            else:
                from .pe import PE, PEError

                try:
                    self._cache["pe"] = PE(self.data)
                except (PEError, ValueError, Exception):  # noqa: BLE001
                    self._cache["pe"] = None
        return self._cache["pe"]

    # -- facts -------------------------------------------------------------- #
    @property
    def size(self) -> int:
        return len(self.data)

    def bytes(self) -> bytes:
        if "bytes" not in self._cache:
            self._cache["bytes"] = bytes(self.data)
        return self._cache["bytes"]

    def machines(self) -> set:
        if self.pe is None:
            return set()
        name = (self.pe.machine_name or "").lower()
        return {name, "0x%04x" % self.pe.machine} | ({"x64"} if name == "x64" else set())

    def section(self, name: str):
        if self.pe is None:
            return None
        for section in self.pe.sections:
            if section.name == name:
                return section
        return None

    def has(self, needle: bytes) -> bool:
        return needle in self.bytes()


def _describe(cond: Dict[str, Any]) -> str:
    """A short phrase for a human: what this condition asks for."""
    if "all" in cond:
        return "all of (" + ", ".join(_describe(c) for c in cond["all"]) + ")"
    if "any" in cond:
        return "any of (" + ", ".join(_describe(c) for c in cond["any"]) + ")"
    if "not" in cond:
        return "not " + _describe(cond["not"])
    if "machine" in cond:
        value = cond["machine"]
        return "machine is %s" % (value if isinstance(value, str)
                                  else " or ".join(value))
    if "section" in cond:
        want = cond.get("exists", True)
        return "section %s %s" % (cond["section"], "exists" if want else "is absent")
    if "section_is_executable" in cond:
        return "section %s is executable" % cond["section_is_executable"]
    if "string" in cond:
        return 'the text "%s" is present' % cond["string"][:40]
    if "utf16" in cond:
        return 'the UTF-16 text "%s" is present' % cond["utf16"][:40]
    if "pattern" in cond:
        return "the pattern %s matches" % cond["pattern"][:40]
    if "size_at_least" in cond:
        return "the file is at least %d bytes" % cond["size_at_least"]
    if "size_at_most" in cond:
        return "the file is at most %d bytes" % cond["size_at_most"]
    for key in ("is_dotnet", "is_dll", "has_overlay", "has_signature"):
        if key in cond:
            word = {"is_dotnet": "a .NET assembly", "is_dll": "a DLL",
                    "has_overlay": "carrying an overlay",
                    "has_signature": "carrying an Authenticode signature"}[key]
            return "%s is %s%s" % ("the file", word, "" if cond[key] else " (must not be)")
    return "a condition"


def evaluate(cond: Dict[str, Any], view: _View) -> Tuple[bool, str]:
    """(result, explanation). The explanation says why it failed."""
    if "all" in cond:
        for item in cond["all"]:
            ok, why = evaluate(item, view)
            if not ok:
                return False, why
        return True, "all conditions hold"
    if "any" in cond:
        reasons = []
        for item in cond["any"]:
            ok, why = evaluate(item, view)
            if ok:
                return True, "one alternative holds"
            reasons.append(why)
        return False, "; ".join(reasons[:3]) or "no alternative holds"
    if "not" in cond:
        ok, why = evaluate(cond["not"], view)
        if ok:
            return False, "not (%s) fails because %s" % (_describe(cond["not"]), why)
        return True, "the inner condition does not hold"
    if "machine" in cond:
        want = cond["machine"] if isinstance(cond["machine"], list) else [cond["machine"]]
        wanted = set()
        for item in want:
            wanted |= MACHINES[item.lower()]
        have = view.machines()
        if have & wanted:
            return True, "machine matches"
        return False, ("the image is %s, not %s"
                       % (", ".join(sorted(have)) or "unknown", " or ".join(want)))
    if "is_dotnet" in cond:
        actual = bool(view.pe is not None and view.pe.is_dotnet)
        return (actual == cond["is_dotnet"],
                "is_dotnet is %s" % actual)
    if "is_dll" in cond:
        actual = bool(view.pe is not None and view.pe.is_dll)
        return (actual == cond["is_dll"], "is_dll is %s" % actual)
    if "has_overlay" in cond:
        actual = bool(getattr(view.pe, "overlay_size", 0)) if view.pe is not None else False
        return (actual == cond["has_overlay"], "has_overlay is %s" % actual)
    if "has_signature" in cond:
        actual = bool(view.pe is not None and view.pe.has_signature)
        return (actual == cond["has_signature"], "has_signature is %s" % actual)
    if "section" in cond:
        found = view.section(cond["section"]) is not None
        want = bool(cond.get("exists", True))
        return (found == want,
                "section %s %s" % (cond["section"],
                                   "exists" if found else "is missing"))
    if "section_is_executable" in cond:
        section = view.section(cond["section_is_executable"])
        if section is None:
            return False, "section %s is missing" % cond["section_is_executable"]
        return (bool(section.executable),
                "section %s is %sexecutable"
                % (section.name, "" if section.executable else "not "))
    if "string" in cond:
        found = view.has(cond["string"].encode("utf-8", "surrogateescape"))
        return found, ('"%s" %s' % (cond["string"][:40],
                                    "is present" if found else "was not found"))
    if "utf16" in cond:
        found = view.has(cond["utf16"].encode("utf-16-le", "surrogateescape"))
        return found, ('UTF-16 "%s" %s' % (cond["utf16"][:40],
                                          "is present" if found else "was not found"))
    if "pattern" in cond:
        regex = _hex_to_regex(cond["pattern"])
        found = regex.search(view.bytes()) is not None
        return found, ("pattern %s %s" % (cond["pattern"][:40],
                                         "matches" if found else "did not match"))
    if "size_at_least" in cond:
        ok = view.size >= cond["size_at_least"]
        return ok, "the file is %d bytes" % view.size
    if "size_at_most" in cond:
        ok = view.size <= cond["size_at_most"]
        return ok, "the file is %d bytes" % view.size
    raise ScriptError("cannot evaluate condition %r" % (cond,))


def check(conditions: List[Dict[str, Any]], data, pe=None) -> List[Dict[str, Any]]:
    """Evaluate a REQUIRE list; return one result per condition.

    Each result is ``{"condition", "holds", "detail", "comment"}`` so callers can
    print it or put it in JSON without re-deriving anything.
    """
    view = _View(data, pe)
    out: List[Dict[str, Any]] = []
    for cond in conditions:
        validate(cond)
        ok, detail = evaluate(cond, view)
        out.append({"condition": _describe(cond), "holds": ok, "detail": detail,
                    "comment": cond.get("comment") or ""})
    return out


def first_failure(results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for item in results:
        if not item["holds"]:
            return item
    return None
