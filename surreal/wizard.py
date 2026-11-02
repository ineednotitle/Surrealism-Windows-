"""Easy mode: the guided flow behind a bare ``surreal`` / a dragged-and-dropped file.

Someone who has never seen this tool should be able to double-click ``surreal.exe``,
drag an ``.exe`` onto the window and be told, in plain language, what can be done
to it and what the risks are. That is what this module is: no new patching logic,
only the words and the ordering around the parts that already exist.

Three rules it follows:

* **It never guesses.** A bundle whose target hash or size does not match the file
  is shown as "made for a different build", never silently skipped and never
  forced on.
* **It never leaves a half-patched file.** Every applied bundle is journalled, and
  if a later one fails, the ones already applied are rolled back to the pristine
  bytes.
* **It works without a TTY.** ``--yes`` and piped answers both drive it, so the
  same code path is what CI exercises.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import patcher, pe, policy
from .patchfile import Bundle, BundleError
from .util import sha256_file

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_MISMATCH = 3
EXIT_POLICY = 4
EXIT_IO = 5

PATCH_ENV = "SURREAL_PATCHES"
PATCH_SUFFIXES = (".morph", ".json")
BINARY_SUFFIXES = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".node", ".efi")


class WizardError(Exception):
    """A problem worth explaining to a human, with an exit code."""

    def __init__(self, message: str, code: int = EXIT_MISMATCH):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- #
# input helpers (patchable in tests, forgiving in real consoles)
# --------------------------------------------------------------------------- #
def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""
    except KeyboardInterrupt:      # pragma: no cover - interactive only
        raise


def _question(console, text: str, default: str = "") -> str:
    """Ask once; an empty answer takes ``default``; EOF/quits become ''."""
    suffix = " [%s]" % default if default else ""
    console.say("")
    console.say("  " + text)
    try:
        answer = _ask("  > ").strip()
    except KeyboardInterrupt:
        console.say("")
        return ""
    return answer or default


def _confirm(console, text: str, default: str = "y") -> bool:
    answer = _question(console, text + " (%s)" % ("Y/n" if default == "y"
                                                  else "y/N")).lower()
    if not answer:
        return default == "y"
    return answer in ("y", "yes", "ok", "sure", "1")


def _is_quit(answer: str) -> bool:
    return answer.strip().lower() in ("q", "quit", "exit", "n", "no", "cancel")


# --------------------------------------------------------------------------- #
# discovering what is on disk
# --------------------------------------------------------------------------- #
def is_patch_file(path: str) -> bool:
    return path.lower().endswith(PATCH_SUFFIXES)


def is_binary_path(path: str) -> bool:
    return path.lower().endswith(BINARY_SUFFIXES)


def looks_like_path(token: str) -> bool:
    """True when an unknown first argument is probably a dropped file/folder."""
    if not token or token.startswith("-"):
        return False
    if os.path.exists(token):
        return True
    if os.sep in token or (os.altsep and os.altsep in token):
        return True
    return token.lower().endswith(PATCH_SUFFIXES + BINARY_SUFFIXES)


def search_dirs(target: str = "", extra: Sequence[str] = ()) -> List[str]:
    """Where easy mode looks for ``.morph`` files, most local first."""
    dirs: List[str] = []

    def add(path: str) -> None:
        if not path:
            return
        full = os.path.abspath(path)
        if full not in dirs and os.path.isdir(full):
            dirs.append(full)

    for item in extra:
        add(item)
    base = os.path.dirname(os.path.abspath(target)) if target else ""
    add(base)
    add(os.path.join(base, "patches") if base else "")
    add(os.path.join(base, "surreal-patches") if base else "")
    for item in (os.environ.get(PATCH_ENV) or "").split(os.pathsep):
        add(item.strip())
    # people download a .morph and leave it in Downloads; meeting them there is
    # the difference between "it works" and "it says no patch files"
    home = os.path.expanduser("~")
    add(os.path.join(home, "Downloads"))
    add(os.path.join(home, "Desktop"))
    try:
        cwd = os.getcwd()
    except OSError:            # a deleted working directory should not crash us
        cwd = ""
    add(cwd)
    add(os.path.join(cwd, "patches") if cwd else "")
    add(os.path.join(policy.config_dir(), "patches"))
    return dirs


def find_patches(target: str = "", extra: Sequence[str] = ()) -> List[str]:
    """Every readable ``.morph`` file in the search path, de-duplicated."""
    found: List[Tuple[float, str]] = []
    seen = set()
    for directory in search_dirs(target, extra):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not name.lower().endswith(".morph"):
                continue
            path = os.path.join(directory, name)
            real = os.path.realpath(path)
            if real in seen or not os.path.isfile(path):
                continue
            seen.add(real)
            try:
                found.append((os.path.getmtime(path), path))
            except OSError:
                found.append((0.0, path))
    # newest first: a patch you just made or downloaded should be on top
    found.sort(key=lambda item: (-item[0], item[1].lower()))
    return [path for _mtime, path in found]


# --------------------------------------------------------------------------- #
# plain-language verdicts
# --------------------------------------------------------------------------- #
class Candidate:
    __slots__ = ("path", "bundle", "applies", "reason", "blocked")

    def __init__(self, path: str, bundle: Bundle, applies: bool, reason: str,
                 blocked: str = "") -> None:
        self.path = path
        self.bundle = bundle
        self.applies = applies
        self.reason = reason
        self.blocked = blocked

    @property
    def usable(self) -> bool:
        return self.applies and not self.blocked

    @property
    def title(self) -> str:
        name = self.bundle.name or self.bundle.id
        return "%s  (%s)" % (name, self.bundle.id)


def describe(bundle: Bundle, target_path: str) -> Tuple[bool, str]:
    """(applies?, short reason a non-technical person can act on)."""
    tgt = bundle.target or {}
    if not os.path.isfile(target_path):
        return False, "target is not a file"
    size = os.path.getsize(target_path)
    want_size = tgt.get("size")
    if want_size is not None and int(want_size) != size:
        return False, ("made for a different version of this program "
                       "(%s bytes vs %s here)" % (want_size, size))
    want_sha = (tgt.get("sha256") or "").lower()
    if want_sha:
        sha = sha256_file(target_path)
        if want_sha != sha:
            return False, "made for a different build of this program"
    name = tgt.get("filename")
    if not want_sha and name and name.lower() != os.path.basename(target_path).lower():
        return False, "made for a different file name (%s)" % name
    return True, "works with this build"


def evaluate(target: str, extra_dirs: Sequence[str] = (),
             explicit: Sequence[str] = ()) -> List[Candidate]:
    """Load every patch we can find and judge it against the target."""
    paths = list(explicit) if explicit else find_patches(target, extra_dirs)
    out: List[Candidate] = []
    for path in paths:
        try:
            bundle = Bundle.load(path)
        except (BundleError, OSError, ValueError):
            continue
        applies, reason = describe(bundle, target)
        blocked = bundle.is_policy_blocked() or ""
        out.append(Candidate(path, bundle, applies, reason, blocked))
    return out


# --------------------------------------------------------------------------- #
# policy + target prompt
# --------------------------------------------------------------------------- #
POLICY_POINTS = [
    "you own the file, or its licence / the author allows this kind of change;",
    "you are not defeating activation, DRM, anti-cheat or anti-tamper;",
    "patched files are unsigned - antivirus and SmartScreen may complain;",
    "you share patch files (.morph), never patched copies of someone's software;",
    "you keep a backup and you accept the result.",
]


def ensure_policy(console, assume_yes: bool = False) -> bool:
    """Explain the policy in five lines and record the acknowledgement."""
    if policy.policy_accepted():
        return True
    console.say("")
    console.say("  Before the first change, one confirmation. Please read the five")
    console.say("  points (full text: surreal init):")
    console.say("")
    for number, point in enumerate(POLICY_POINTS, start=1):
        console.say("    %d. %s" % (number, point))
    console.say("")
    if assume_yes:
        accepted = True
    else:
        accepted = _confirm(console, "Do all five apply to you?", "n")
    if not accepted:
        console.say("")
        console.say("  Nothing was changed. You can read the whole policy with")
        console.say("  `surreal init`, and accept it later with")
        console.say("  `surreal init --accept-policy`.")
        return False
    try:
        policy.accept_policy(user=os.environ.get("USERNAME")
                             or os.environ.get("USER") or "")
    except OSError as exc:
        console.warn("could not save the acknowledgement: %s" % exc)
        return True          # in-memory acceptance is enough for this run
    console.ok("recorded - this is asked once per machine")
    return True


def _looks_like_pe(path: str) -> Optional[str]:
    """'' when the file parses as PE, else a sentence saying what it is."""
    try:
        image = pe.PE.open(path)
        image.close()
    except Exception as exc:                      # noqa: BLE001 - any parse error
        detail = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        if os.path.getsize(path) == 0:
            return "this file is empty (0 bytes)"
        return ("this does not look like a Windows program (%s). If it came as a "
                "zip or installer, extract it first." % detail)
    return ""


def resolve_target(console, raw: str) -> Tuple[str, bool]:
    """Turn what the user dropped into (path, is_directory)."""
    cleaned = raw.strip().strip('"').strip("'")
    if not cleaned:
        raise WizardError("no file given", EXIT_USAGE)
    cleaned = os.path.expandvars(os.path.expanduser(cleaned))
    if not os.path.exists(cleaned):
        raise WizardError(
            "there is nothing at %s\n"
            "  Drag the file into this window instead of typing it, or check the "
            "path for typos." % cleaned, EXIT_USAGE)
    path = os.path.abspath(cleaned)
    if os.path.isdir(path):
        return path, True
    problem = _looks_like_pe(path)
    if problem:
        raise WizardError("%s: %s" % (os.path.basename(path), problem), EXIT_USAGE)
    return path, False


def _ask_target(console, start: str = "") -> Tuple[str, bool]:
    console.say("")
    console.say("  Which program do you want to patch?")
    console.say("  Drag its .exe (or its folder) into this window and press Enter,")
    console.say("  or type the path. 'q' quits without changing anything.")
    hint = os.path.abspath(start) if start else ""
    for _attempt in range(3):
        answer = _question(console, "path:", hint)
        if _is_quit(answer):
            raise WizardError("cancelled - nothing was changed", EXIT_OK)
        try:
            return resolve_target(console, answer)
        except WizardError as exc:
            console.warn(str(exc))
    raise WizardError("cancelled - nothing was changed", EXIT_OK)


# --------------------------------------------------------------------------- #
# rollback helpers
# --------------------------------------------------------------------------- #
def _restore(backup: str, target: str, want_sha: str) -> bool:
    directory = os.path.dirname(target) or "."
    tmp = os.path.join(directory, ".surreal-wizard-restore.tmp")
    try:
        shutil.copyfile(backup, tmp)
        if sha256_file(tmp) != want_sha:
            os.remove(tmp)
            return False
        os.replace(tmp, target)
        return True
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def _undo_applied(console, applied: List[Dict[str, Any]], target: str) -> None:
    """Put back the pristine bytes after a later bundle failed."""
    pristine = applied[0].get("sha256_before", "")
    backup = applied[0].get("backup") or ""
    if not backup or not pristine:
        console.err("no backup to roll back to - restore %s manually" % target)
        return
    if _restore(backup, target, pristine):
        console.ok("rolled back: %s is byte-for-byte the file you started with"
                   % os.path.basename(target))
    else:
        console.err("automatic rollback failed - copy %s back over %s yourself"
                    % (backup, target))


# --------------------------------------------------------------------------- #
# the flow
# --------------------------------------------------------------------------- #
def run(console, target: str = "", patches: Sequence[str] = (),
        extra_dirs: Sequence[str] = (), assume_yes: bool = False,
        force: bool = False) -> int:
    console.head("surreal easy mode - paste or drag a file")
    console.say("  Patch a Windows program you own. Everything happens on this")
    console.say("  computer: the tool has no network code at all.")

    if target and is_patch_file(target):
        patches = list(patches) + [os.path.abspath(target)]
        target = ""

    is_dir = False
    if target:
        target, is_dir = resolve_target(console, target)
    else:
        target, is_dir = _ask_target(console)

    if is_dir:
        return _run_folder(console, target, patches, extra_dirs, assume_yes, force)
    return _run_file(console, target, patches, extra_dirs, assume_yes, force)


def _collect(console, target: str, patches: Sequence[str],
             extra_dirs: Sequence[str], is_folder: bool) -> List[Candidate]:
    if is_folder:
        files = [os.path.join(target, name) for name in sorted(os.listdir(target))
                 if name.lower().endswith((".exe", ".dll"))]
        verdicts = []
        for path in files:
            verdicts.extend(c for c in evaluate(path, extra_dirs, ())
                            if c.applies and not c.blocked)
        if verdicts:
            return verdicts
        raise WizardError(
            "no patch file matches the programs in %s.\n"
            "  Put the .morph patch files inside that folder (or in a "
            "'patches' folder next to it),\n"
            "  then run this again. `surreal doctor %s` shows what is missing."
            % (target, target), EXIT_MISMATCH)
    candidates = evaluate(target, extra_dirs, patches)
    if not candidates:
        raise WizardError(
            "no patch files (.morph) found.\n"
            "  I looked in: %s\n"
            "  Download or copy the patch file next to %s and run this again.\n"
            "  You can also make one yourself: `surreal diff old.exe new.exe -o "
            "mine.morph --id com.you.mine`."
            % (", ".join(search_dirs(target, extra_dirs)[:4]),
               os.path.basename(target)), EXIT_MISMATCH)
    return candidates


def _render(console, candidates: List[Candidate], target: str) -> List[int]:
    console.say("")
    console.kv("program", os.path.basename(target))
    console.kv("bytes", "{:,}".format(os.path.getsize(target)))
    console.say("")
    usable: List[int] = []
    for index, cand in enumerate(candidates, start=1):
        marks = []
        if cand.usable:
            usable.append(index)
            marks.append("can be applied")
        elif cand.blocked:
            marks.append("refused by policy: %s" % cand.blocked)
        else:
            marks.append("skipped - %s" % cand.reason)
        if cand.bundle.signature:
            marks.append("signed by %s" % cand.bundle.signer())
        console.say("    [%d] %-52s %s" % (index, cand.title, marks[0]))
        for extra in marks[1:]:
            console.say("        %s" % extra)
    console.say("")
    return usable


def _run_file(console, target: str, patches: Sequence[str],
              extra_dirs: Sequence[str], assume_yes: bool,
              force: bool) -> int:
    candidates = _collect(console, target, patches, extra_dirs, False)
    usable = _render(console, candidates, target)
    if not usable:
        console.say("")
        console.warn("none of these patches fit this exact build of the program.")
        console.say("  That usually means a different version is installed. Options:")
        console.say("    - find the patch made for this version;")
        console.say("    - make one yourself from two builds you own:")
        console.say("        surreal diff original.exe modified.exe -o mine.morph "
                    "--id com.you.mine")
        console.say("    - `surreal doctor %s` lists what each patch expects."
                    % os.path.basename(target))
        return EXIT_MISMATCH

    # ask for the one-time acknowledgement before asking what to do, so the
    # whole flow reads: policy -> which patches -> confirm -> done
    if not ensure_policy(console, assume_yes):
        return EXIT_POLICY

    chosen = usable
    if not assume_yes:
        console.say("  Apply which? 'a' = all of the above, '1 3' = those numbers,")
        console.say("  Enter = all, 'q' = quit.")
        answer = _question(console, "choice:", "a").lower()
        if _is_quit(answer):
            raise WizardError("cancelled - nothing was changed", EXIT_OK)
        if answer not in ("", "a", "all"):
            picked: List[int] = []
            for token in answer.replace(",", " ").split():
                if not token.isdigit() or int(token) not in usable:
                    console.warn("'%s' is not one of the applicable patches - "
                                 "ignoring it" % token)
                    continue
                picked.append(int(token))
            if not picked:
                raise WizardError("nothing selected - nothing was changed", EXIT_OK)
            chosen = sorted(set(picked))

    selected = [candidates[i - 1] for i in chosen]
    console.say("")
    console.kv("about to patch", os.path.basename(target))
    for cand in selected:
        console.kv("  with", "%s (%d change(s))" % (cand.title, len(cand.bundle.hunks)))
    console.kv("backup", "yes - a copy is written before anything changes")
    if not assume_yes and not _confirm(console, "Go ahead?"):
        raise WizardError("cancelled - nothing was changed", EXIT_OK)

    applied: List[Dict[str, Any]] = []
    try:
        for cand in selected:
            result = patcher.apply_bundle(cand.bundle, target)
            applied.append(result)
            console.ok("applied %s" % cand.bundle.name or cand.bundle.id)
    except patcher.PatchError as exc:
        console.err(str(exc))
        if applied:
            _undo_applied(console, applied, target)
        return exc.code or EXIT_MISMATCH
    except OSError as exc:
        console.err("IO error: %s" % exc)
        if applied:
            _undo_applied(console, applied, target)
        return EXIT_IO

    backup = applied[0].get("backup") if applied else ""
    console.say("")
    console.ok("done - %s is patched" % os.path.basename(target))
    if backup:
        console.kv("original saved as", backup)
    console.say("")
    console.say("  To undo, run:  surreal undo %s" % os.path.basename(target))
    console.say("  Keep the backup until you are sure the result works.")
    return EXIT_OK


def _run_folder(console, folder: str, patches: Sequence[str],
                extra_dirs: Sequence[str], assume_yes: bool,
                force: bool) -> int:
    """A whole application folder: patch every file that has a matching bundle."""
    from . import collection as coll

    manifest = None
    for name in ("surreal-collection.json", "collection.json"):
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate):
            manifest = candidate
            break
    if not manifest:
        raise WizardError(
            "this folder has no patch set in it.\n"
            "  A folder patch set is a 'surreal-collection.json' listing the "
            ".morph files.\n"
            "  Run `surreal collection list <folder>` to check one, or drag the "
            "single .exe instead.", EXIT_USAGE)
    loaded = coll.load_collection(manifest)
    console.say("")
    console.kv("patch set", loaded.name)
    console.kv("files", ", ".join(loaded.files()) or "(none)")
    if not ensure_policy(console, assume_yes):
        return EXIT_POLICY
    if not assume_yes and not _confirm(console, "Patch this folder now?"):
        raise WizardError("cancelled - nothing was changed", EXIT_OK)
    try:
        report = coll.preflight_vault(loaded, folder)
    except coll.CollectionError as exc:
        console.err(str(exc))
        return EXIT_MISMATCH
    for note in report.get("warnings") or []:
        console.warn(note)
    try:
        result = coll.apply_vault(loaded, folder)
    except coll.CollectionError as exc:
        console.err(str(exc))
        return EXIT_MISMATCH
    console.say("")
    for item in result["files"]:
        console.kv("patched", "%s (%d change(s))"
                   % (item["file"], sum(a["hunks"] for a in item["applied"])))
    console.ok("done - %d file(s) patched as one transaction" % len(result["files"]))
    console.say("")
    console.say("  Each patched file has its own backup; undo them one at a time:")
    for item in result["files"]:
        console.say("    surreal undo %s" % item["file"])
    return EXIT_OK


# --------------------------------------------------------------------------- #
# machine-readable variant (--json)
# --------------------------------------------------------------------------- #
def run_json(console, target: str = "", patches: Sequence[str] = (),
             extra_dirs: Sequence[str] = (), apply_now: bool = False) -> int:
    """Same judgement as easy mode, as one JSON object and no prompts."""
    if not target:
        console.emit_json({"ok": False, "error": "easy --json needs a file path",
                           "exit_code": EXIT_USAGE})
        return EXIT_USAGE
    try:
        path, is_dir = resolve_target(console, target)
    except WizardError as exc:
        console.emit_json({"ok": False, "error": str(exc), "exit_code": exc.code})
        return exc.code

    payload: Dict[str, Any] = {"ok": True, "target": path, "is_dir": is_dir,
                               "patches": [], "applied": [], "dry_run": not apply_now}
    if is_dir:
        manifest = ""
        for name in ("surreal-collection.json", "collection.json"):
            if os.path.isfile(os.path.join(path, name)):
                manifest = os.path.join(path, name)
                break
        if not manifest:
            console.emit_json({"ok": False, "target": path,
                               "error": "no patch set (surreal-collection.json) in "
                                        "this folder", "exit_code": EXIT_MISMATCH})
            return EXIT_MISMATCH
        from . import collection as coll

        try:
            loaded = coll.load_collection(manifest)
            report = coll.preflight_vault(loaded, path)
        except coll.CollectionError as exc:
            console.emit_json({"ok": False, "target": path, "error": str(exc),
                               "exit_code": EXIT_MISMATCH})
            return EXIT_MISMATCH
        payload.update({"collection": loaded.name, "files": loaded.files(),
                        "report": report})
        if apply_now:
            if not policy.policy_accepted():
                console.emit_json({"ok": False, "error": "usage policy not accepted "
                                   "(`surreal init --accept-policy`)",
                                   "exit_code": EXIT_POLICY})
                return EXIT_POLICY
            try:
                payload["applied"] = coll.apply_vault(loaded, path)["files"]
            except coll.CollectionError as exc:
                console.emit_json({"ok": False, "target": path, "error": str(exc),
                                   "exit_code": EXIT_MISMATCH})
                return EXIT_MISMATCH
        console.emit_json(payload)
        return EXIT_OK

    candidates = evaluate(path, extra_dirs, patches)
    for cand in candidates:
        payload["patches"].append({
            "id": cand.bundle.id,
            "name": cand.bundle.name,
            "file": cand.path,
            "hunks": len(cand.bundle.hunks),
            "applies": cand.applies,
            "reason": "" if cand.applies else cand.reason,
            "policy_blocked": cand.blocked or None,
            "signed_by": cand.bundle.signer() if cand.bundle.signature else None,
        })
    usable = [c for c in candidates if c.usable]
    if not candidates:
        payload.update({"ok": False, "error": "no .morph patch files found",
                        "searched": search_dirs(path, extra_dirs)})
        console.emit_json(payload)
        return EXIT_MISMATCH
    if not usable:
        payload.update({"ok": False, "error": "no patch applies to this build"})
        console.emit_json(payload)
        return EXIT_MISMATCH
    if not apply_now:
        console.emit_json(payload)
        return EXIT_OK
    if not policy.policy_accepted():
        payload.update({"ok": False, "error": "usage policy not accepted "
                        "(`surreal init --accept-policy`)", "exit_code": EXIT_POLICY})
        console.emit_json(payload)
        return EXIT_POLICY
    done: List[Dict[str, Any]] = []
    try:
        for cand in usable:
            result = patcher.apply_bundle(cand.bundle, path)
            done.append({"id": cand.bundle.id, "backup": result.get("backup"),
                         "sha256_before": result.get("sha256_before"),
                         "sha256_after": result.get("sha256_after")})
    except patcher.PatchError as exc:
        if done:
            _undo_applied(console, done, path)
        payload.update({"ok": False, "error": str(exc), "applied": done,
                        "exit_code": getattr(exc, "code", EXIT_MISMATCH)})
        console.emit_json(payload)
        return getattr(exc, "code", EXIT_MISMATCH)
    payload["applied"] = done
    console.emit_json(payload)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
def doctor_checks(target: str = "", patches: Sequence[str] = (),
                  extra_dirs: Sequence[str] = ()) -> List[Tuple[str, str]]:
    """Everything that could stop a patch from working, as a list of findings."""
    console = _SilentConsole()
    from . import __version__
    from .journal import Journal
    from . import lock as lockmod

    checks: List[Tuple[str, str]] = []      # (state, line); state in ok/note/problem

    frozen = getattr(sys, "frozen", False)
    checks.append(("ok", "this is surreal %s, running %s"
                   % (__version__, "as a frozen .exe" if frozen
                      else "from source (Python %s)" % sys.version.split()[0])))
    if sys.maxsize <= 2 ** 32:
        checks.append(("note", "32-bit Python: files above ~2 GB cannot be patched"))

    # config dir / policy
    config = policy.config_dir()
    try:
        os.makedirs(config, exist_ok=True)
        probe = os.path.join(config, ".doctor-probe")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        checks.append(("ok", "settings folder is writable: %s" % config))
    except OSError as exc:
        checks.append(("problem", "cannot write to %s (%s)" % (config, exc)))
    if policy.policy_accepted():
        record = policy.read_acceptance() or {}
        checks.append(("ok", "usage policy accepted%s"
                       % (" on " + str(record.get("accepted_utc", ""))[:10]
                          if record.get("accepted_utc") else "")))
    else:
        checks.append(("note", "usage policy not accepted yet - "
                               "`surreal init --accept-policy` (easy mode asks once)"))

    # temp space for staged writes
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(prefix="surreal-doctor-", delete=True) as fh:
            fh.write(b"ok")
        checks.append(("ok", "temporary folder is writable"))
    except OSError as exc:
        checks.append(("problem", "no usable temp folder (%s)" % exc))

    if not target:
        checks.append(("note", "no program given - run `surreal doctor app.exe` "
                               "to check one"))
        return checks

    try:
        path, is_dir = resolve_target(console, target)
    except WizardError as exc:
        checks.append(("problem", str(exc).splitlines()[0]))
        return checks

    if is_dir:
        return checks + _doctor_folder(console, path, patches, extra_dirs, Journal)

    checks.append(("ok", "target: %s (%s bytes)"
                   % (path, "{:,}".format(os.path.getsize(path)))))
    try:
        with pe.PE.open(path) as image:
            checks.append(("ok", "PE image: %s, %s, %d section(s)"
                           % (image.machine_name, image.subsystem_name,
                              len(image.sections))))
    except Exception as exc:                      # noqa: BLE001
        checks.append(("problem", "cannot parse %s as PE (%s)"
                       % (os.path.basename(path), exc)))

    directory = os.path.dirname(path) or "."
    if os.access(directory, os.W_OK) and os.access(path, os.W_OK):
        checks.append(("ok", "the file and its folder are writable"))
    else:
        checks.append(("problem", "no write permission in %s - copy the program "
                                  "somewhere you can write, or run as an "
                                  "administrator" % directory))

    lock_file = lockmod.lock_path(path)
    if os.path.exists(lock_file):
        checks.append(("note", "a lock file exists (%s) - if no surreal is running, "
                               "`--force-unlock` clears it" % os.path.basename(lock_file)))

    journal = Journal(path)
    entries = [e for e in journal.entries
               if e.get("action") in ("apply", "apply-collection", "apply-vault",
                                      "revert")]
    if entries:
        last = entries[-1]
        text = "journal: %d recorded change(s), last was %s" % (len(entries),
                                                               last.get("action"))
        if last.get("action") == "apply" and last.get("backup"):
            text += " - `surreal undo %s` restores it" % os.path.basename(path)
        checks.append(("ok", text))
    else:
        checks.append(("ok", "no previous patching history for this file"))

    candidates = evaluate(path, extra_dirs, patches)
    usable = [c for c in candidates if c.usable]
    if not candidates:
        checks.append(("note", "no .morph patch files found; looked in %s"
                       % ", ".join(search_dirs(path, extra_dirs)[:3])))
    else:
        for cand in candidates:
            checks.append(("ok" if cand.usable else "note",
                           "%s: %s" % (cand.title, "works with this build"
                                       if cand.usable else cand.reason)))
    if usable:
        checks.append(("ok", "ready to patch with %d of %d patch file(s)"
                       % (len(usable), len(candidates))))
    else:
        checks.append(("note", "nothing applies to this exact build - "
                               "`surreal diff` can author one from two builds"))
    return checks


def _doctor_folder(console, folder: str, patches: Sequence[str],
                   extra_dirs: Sequence[str], Journal) -> List[Tuple[str, str]]:
    from . import collection as coll

    out: List[Tuple[str, str]] = [("ok", "target is a folder: %s" % folder)]
    manifest = None
    for name in ("surreal-collection.json", "collection.json"):
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate):
            manifest = candidate
            break
    if not manifest:
        out.append(("note", "no patch set here - single-file patching still works "
                            "if you drag the .exe itself"))
        return out
    try:
        loaded = coll.load_collection(manifest)
    except coll.CollectionError as exc:
        out.append(("problem", str(exc)))
        return out
    out.append(("ok", "patch set %r: %d patch(es) for %s"
                % (loaded.name, len(loaded.entries), ", ".join(loaded.files()))))
    try:
        report = coll.preflight_vault(loaded, folder)
    except coll.CollectionError as exc:
        out.append(("problem", "the set cannot be applied as-is: %s" % exc))
        return out
    out.append(("ok", "all %d file(s) simulate cleanly"
                % len(report.get("files") or [])))
    for note in report.get("warnings") or []:
        out.append(("note", note))
    graph = report.get("graph") or {}
    if graph.get("cross_file_edges"):
        out.append(("ok", "%d cross-file dependency(ies) resolved"
                    % len(graph["cross_file_edges"])))
    return out


class _SilentConsole:
    """Absorbs the chatter of the helpers doctor reuses (resolution messages)."""

    json_mode = False
    quiet = True
    unicode = True

    def say(self, *_args, **_kwargs) -> None:
        pass

    def head(self, *_args, **_kwargs) -> None:
        pass

    def ok(self, *_args, **_kwargs) -> None:
        pass

    def warn(self, *_args, **_kwargs) -> None:
        pass

    def err(self, *_args, **_kwargs) -> None:
        pass

    def kv(self, *_args, **_kwargs) -> None:
        pass


def doctor(console, target: str = "", patches: Sequence[str] = (),
           extra_dirs: Sequence[str] = ()) -> int:
    """Explain, in order, everything that could stop a patch from working."""
    return _report(console, doctor_checks(target, patches, extra_dirs))


def doctor_json(console, target: str = "", patches: Sequence[str] = (),
                extra_dirs: Sequence[str] = ()) -> int:
    checks = doctor_checks(target, patches, extra_dirs)
    problems = [line for state, line in checks if state == "problem"]
    console.emit_json({
        "ok": not problems,
        "checks": [{"state": state, "detail": line} for state, line in checks],
        "problems": problems,
        "exit_code": EXIT_MISMATCH if problems else EXIT_OK,
    })
    return EXIT_MISMATCH if problems else EXIT_OK


def _report(console, checks: List[Tuple[str, str]]) -> int:
    console.head("surreal doctor - can this machine patch this file?")
    problems = [line for state, line in checks if state == "problem"]
    for state, line in checks:
        if state == "problem":
            console.err(line)
        elif state == "note":
            console.say("  note   %s" % line)
        else:
            console.say("  ok     %s" % line)
    console.say("")
    if problems:
        console.say("  %d thing(s) need attention before patching will work."
                    % len(problems))
        return EXIT_MISMATCH
    console.ok("everything needed is in place")
    return EXIT_OK
