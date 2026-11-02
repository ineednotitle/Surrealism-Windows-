"""Usage-policy gate.

The tool edits executables, so it asks once, in plain language, that you have
the right to modify the file you point it at. The answer is stored next to the
user config (``%APPDATA%\\surreal\\acceptance.json`` on Windows) together with
the policy version — changing the policy text forces a fresh acknowledgement.
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Dict, Optional

from .util import read_json, write_json_atomic

POLICY_VERSION = 1

POLICY_TEXT = """\
SURREALISM WINDOW — ACCEPTABLE USE

surreal changes bytes inside executable files. It cannot know whether you are
allowed to change a given file, so it asks you to confirm, once, that:

  1. You own the file, or its licence permits modification and reverse
     engineering in your jurisdiction, or you have the author's permission.
  2. You will not use it to defeat licence activation, DRM, anti-cheat or
     anti-tamper mechanisms, nor to pirate software, nor to bypass payments.
  3. You accept that patched binaries are unsigned: they may be quarantined by
     anti-virus or SmartScreen, and any Authenticode signature is void.
  4. You will not redistribute patched copies of third-party software. Share
     patch bundles (the .morph files), not modified executables.
  5. You are responsible for the edits you apply, and for keeping a backup.

Reverse engineering for interoperability, security research, accessibility,
translation, modding and repairing abandoned software is legitimate work in
many jurisdictions (e.g. DMCA 17 U.S.C. §1201(f), EU Directive 2009/24/EC
Art. 6). Circumventing technical protection measures usually is not.

Type `surreal init --accept-policy` to record that you have read and accept
this. Nothing in this tool is legal advice.
"""


def config_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
            os.path.expanduser("~"), ".config")
    return os.path.join(base, "surreal")


def acceptance_path() -> str:
    return os.path.join(config_dir(), "acceptance.json")


def read_acceptance() -> Optional[Dict[str, Any]]:
    data = read_json(acceptance_path())
    if isinstance(data, dict) and data.get("accepted"):
        return data
    return None


def policy_accepted() -> bool:
    data = read_acceptance()
    return bool(data and data.get("policy_version") == POLICY_VERSION)


def _hostname() -> str:
    """Best-effort host label for the acknowledgement record (no network)."""
    if os.environ.get("COMPUTERNAME"):
        return os.environ["COMPUTERNAME"]
    try:
        import platform

        return platform.node()
    except Exception:  # pragma: no cover
        return ""


def accept_policy(user: str = "") -> Dict[str, Any]:
    record = {
        "accepted": True,
        "policy_version": POLICY_VERSION,
        "accepted_utc": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "user": user,
        "host": _hostname(),
    }
    write_json_atomic(acceptance_path(), record)
    return record


def revoke_policy() -> bool:
    path = acceptance_path()
    if os.path.isfile(path):
        os.remove(path)
        return True
    return False


def require_acceptance() -> None:
    """Raise when the policy has not been accepted."""
    if not policy_accepted():
        raise PermissionError(
            "usage policy not accepted yet.\n"
            "  read it:  surreal init\n"
            "  accept:   surreal init --accept-policy")
