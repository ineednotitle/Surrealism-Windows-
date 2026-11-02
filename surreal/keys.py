"""Ed25519 signatures, a signing-key file, and a trusted-key store.

Pure standard library: this is the RFC 8032 algorithm implemented on the
twisted-Edwards curve with extended coordinates. No ``cryptography``/``nacl``
dependency, so the frozen ``surreal.exe`` stays dependency-free and small.

Why signatures at all? A ``.morph`` bundle is instructions for modifying an
executable. Signing makes bundles *tamper-evident*: a curator can sign, a user
can pin the curator's public key, and any edit to the JSON is caught before a
single byte of the target is touched.

Threat model, stated plainly: this proves **who authored a bundle and that it
has not changed since** — it says nothing about whether the edits are legal or
wise. Keys live in files; if your machine is compromised, your key is too.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# curve constants (RFC 8032 §5.1)
# --------------------------------------------------------------------------- #
P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493  # group order
_D = -121665 * pow(121666, P - 2, P) % P
_I = pow(2, (P - 1) // 4, P)

Point = Tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _recover_x(y: int) -> int:
    if y >= P:
        raise ValueError("point y out of range")
    xx = (y * y - 1) * _inv(_D * y * y + 1) % P
    if xx == 0:
        if _I * xx % P:
            raise ValueError("invalid point")
        return 0
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * _I % P
    if (x * x - xx) % P != 0:
        raise ValueError("invalid point: not on curve")
    if x & 1:
        x = P - x
    return x


_BY = 4 * _inv(5) % P
_BX = _recover_x(_BY)
BASE: Point = (_BX, _BY, 1, _BX * _BY % P)
IDENTITY: Point = (0, 1, 1, 0)


def _add(a: Point, b: Point) -> Point:
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * _D % P
    D = 2 * a[2] * b[2] % P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _scalarmult(point: Point, scalar: int) -> Point:
    if scalar == 0 or point == IDENTITY:
        return IDENTITY
    result = IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _encode(point: Point) -> bytes:
    x, y, z, _t = point
    zinv = _inv(z)
    x = x * zinv % P
    y = y * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode(data: bytes) -> Point:
    if len(data) != 32:
        raise ValueError("point must be 32 bytes")
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y)
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for part in parts:
        h.update(part)
    return h.digest()


def _expand(seed: bytes) -> Tuple[int, bytes, bytes]:
    if len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8          # clamp
    a |= 1 << 254
    return a, h[32:], h[:32]


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def public_key(seed: bytes) -> bytes:
    a, _prefix, _ = _expand(seed)
    return _encode(_scalarmult(BASE, a))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix, _ = _expand(seed)
    pub = _encode(_scalarmult(BASE, a))
    r = int.from_bytes(_sha512(prefix, message), "little") % Q
    big_r = _encode(_scalarmult(BASE, r))
    k = int.from_bytes(_sha512(big_r, pub, message), "little") % Q
    s = (r + k * a) % Q
    return big_r + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        a_point = _decode(public)
        r_point = _decode(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        return False
    k = int.from_bytes(_sha512(signature[:32], public, message), "little") % Q
    left = _scalarmult(BASE, s)
    right = _add(r_point, _scalarmult(a_point, k))
    return _encode(left) == _encode(right)


def new_seed() -> bytes:
    return os.urandom(32)


# --------------------------------------------------------------------------- #
# canonical bundle bytes
# --------------------------------------------------------------------------- #
SIGNATURE_KEY = "signature"
SIGNED_EXCLUDED = {SIGNATURE_KEY}


def canonical_bytes(bundle_dict: Dict[str, Any]) -> bytes:
    """Deterministic bytes for signing: sorted keys, no whitespace.

    The ``signature`` field itself is excluded, so re-signing or stripping a
    signature never invalidates a *different* signature's coverage.
    """
    payload = {k: v for k, v in bundle_dict.items() if k not in SIGNED_EXCLUDED}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_bundle(bundle_dict: Dict[str, Any], seed: bytes, signer: str = "") -> Dict[str, Any]:
    payload = canonical_bytes(bundle_dict)
    pub = public_key(seed)
    sig = sign(seed, payload)
    import datetime

    out = dict(bundle_dict)
    out[SIGNATURE_KEY] = {
        "alg": "ed25519",
        "public_key": pub.hex(),
        "signature": sig.hex(),
        "signed_utc": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "signer": signer,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    return out


class SignatureError(Exception):
    pass


def verify_bundle(bundle_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the embedded signature. Returns the signature block.

    Raises :class:`SignatureError` when missing or invalid — callers decide
    whether *unsigned* is acceptable; an invalid signature never is.
    """
    sig = bundle_dict.get(SIGNATURE_KEY)
    if not isinstance(sig, dict):
        raise SignatureError("bundle is not signed")
    if sig.get("alg") != "ed25519":
        raise SignatureError("unsupported signature algorithm %r" % sig.get("alg"))
    try:
        pub = bytes.fromhex(sig.get("public_key") or "")
        signature = bytes.fromhex(sig.get("signature") or "")
    except ValueError as exc:
        raise SignatureError("signature block is malformed: %s" % exc) from exc
    payload = canonical_bytes(bundle_dict)
    if not verify(pub, payload, signature):
        raise SignatureError(
            "signature does not match the bundle content — the file was edited "
            "after signing, or it was signed by a different key")
    digest = sig.get("payload_sha256")
    if digest and digest != hashlib.sha256(payload).hexdigest():
        raise SignatureError("payload_sha256 mismatch")
    return sig


# --------------------------------------------------------------------------- #
# key files
# --------------------------------------------------------------------------- #
KEY_FILE_VERSION = 1


def generate_key_file(path: str, signer: str = "", force: bool = False) -> Dict[str, Any]:
    if os.path.exists(path) and not force:
        raise SignatureError("%s already exists (use --force to overwrite)" % path)
    seed = new_seed()
    record = {
        "format": "surreal.key",
        "format_version": KEY_FILE_VERSION,
        "alg": "ed25519",
        "public_key": public_key(seed).hex(),
        "private_seed": seed.hex(),
        "created_utc": _now(),
        "signer": signer,
        "warning": "PRIVATE KEY. Never commit this file. Never share it.",
    }
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, indent=2)
        fh.write("\n")
    try:
        os.chmod(tmp, 0o600)
    except OSError:  # pragma: no cover - Windows ACLs
        pass
    os.replace(tmp, path)
    return record


def load_key_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            record = json.load(fh)
    except FileNotFoundError as exc:
        raise SignatureError("key file not found: %s" % path) from exc
    except json.JSONDecodeError as exc:
        raise SignatureError("key file is not valid JSON: %s" % exc) from exc
    if record.get("format") != "surreal.key":
        raise SignatureError("%s is not a surreal.key file" % path)
    if record.get("alg") != "ed25519":
        raise SignatureError("unsupported key algorithm %r" % record.get("alg"))
    try:
        seed = bytes.fromhex(record.get("private_seed") or "")
    except ValueError as exc:
        raise SignatureError("private_seed is not hex") from exc
    if len(seed) != 32:
        raise SignatureError("private_seed must be 32 bytes")
    derived = public_key(seed).hex()
    if record.get("public_key") and record["public_key"] != derived:
        raise SignatureError("key file is inconsistent: private seed does not "
                             "derive the recorded public key")
    return record


# --------------------------------------------------------------------------- #
# trusted keys
# --------------------------------------------------------------------------- #
TRUST_FILE = "trusted_keys.json"


def trust_path(config_dir: str) -> str:
    return os.path.join(config_dir, TRUST_FILE)


def _now() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")


def load_trust(config_dir: str) -> Dict[str, Any]:
    path = trust_path(config_dir)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("format", "surreal.trust")
    data.setdefault("keys", [])
    return data


def save_trust(config_dir: str, data: Dict[str, Any]) -> None:
    os.makedirs(config_dir, exist_ok=True)
    path = trust_path(config_dir)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def trust_key(config_dir: str, public_hex: str, label: str = "") -> Dict[str, Any]:
    public_hex = public_hex.lower()
    if len(public_hex) != 64:
        raise SignatureError("a public key is 64 hex characters (32 bytes)")
    try:
        bytes.fromhex(public_hex)
    except ValueError as exc:
        raise SignatureError("public key is not hex") from exc
    data = load_trust(config_dir)
    for entry in data["keys"]:
        if entry.get("public_key") == public_hex:
            entry["label"] = label or entry.get("label", "")
            save_trust(config_dir, data)
            return entry
    entry = {"public_key": public_hex, "label": label, "added_utc": _now()}
    data["keys"].append(entry)
    save_trust(config_dir, data)
    return entry


def untrust_key(config_dir: str, public_hex: str) -> bool:
    data = load_trust(config_dir)
    before = len(data["keys"])
    data["keys"] = [k for k in data["keys"]
                    if k.get("public_key") != public_hex.lower()]
    save_trust(config_dir, data)
    return len(data["keys"]) != before


def is_trusted(config_dir: str, public_hex: str) -> bool:
    return any(k.get("public_key") == public_hex.lower()
               for k in load_trust(config_dir).get("keys", []))


# --------------------------------------------------------------------------- #
# bundle-level checked verification (what apply/check use)
# --------------------------------------------------------------------------- #
def check_bundle_signature(bundle_dict: Dict[str, Any], config_dir: str,
                           require: bool = False,
                           extra_trusted: Optional[List[str]] = None
                           ) -> Tuple[str, str, List[str]]:
    """Return ``(state, message, trusted_keys)``.

    ``state`` is one of ``"unsigned"``, ``"valid"``, ``"untrusted"``.
    Raises :class:`SignatureError` when the signature is present but invalid,
    or when ``require=True`` and it is missing/untrusted.
    """
    extra = [k.lower() for k in (extra_trusted or [])]
    sig = bundle_dict.get(SIGNATURE_KEY)
    if sig is None:
        if require:
            raise SignatureError("bundle is not signed; this policy requires a "
                                 "signature from a trusted key")
        return "unsigned", "bundle is unsigned (no author identity)", []
    block = verify_bundle(bundle_dict)  # raises on tamper
    pub = (block.get("public_key") or "").lower()
    signer = block.get("signer") or "(unnamed signer)"
    if pub in extra or is_trusted(config_dir, pub):
        return "valid", "signed by %s (%s…)" % (signer, pub[:16]), [pub]
    if require:
        raise SignatureError(
            "bundle is signed by %s… which is not in your trusted keys\n"
            "  → trust it: surreal keys --trust %s --label \"%s\""
            % (pub[:16], pub, signer))
    return ("untrusted",
            "signature is valid but the key %s… is not trusted yet "
            "(`surreal keys --trust %s`)" % (pub[:16], pub), [pub])
