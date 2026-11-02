"""Ed25519 correctness (RFC 8032 vectors) plus signing/trust behaviour."""

import hashlib
import json
import os
import unittest

from helpers import TempDirCase

from surreal import keys
from surreal.patchfile import BundleError

# RFC 8032 §7.1 test vectors
VECTORS = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    },
    {
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": (
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    },
]


class TestEd25519(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for i, v in enumerate(VECTORS):
            seed = bytes.fromhex(v["seed"])
            msg = bytes.fromhex(v["message"])
            pub = keys.public_key(seed)
            self.assertEqual(pub.hex(), v["public"], "public key %d" % i)
            sig = keys.sign(seed, msg)
            self.assertEqual(sig.hex(), v["signature"], "signature %d" % i)
            self.assertTrue(keys.verify(pub, msg, sig), "verify %d" % i)

    def test_roundtrip_random(self):
        for _ in range(3):
            seed = keys.new_seed()
            pub = keys.public_key(seed)
            msg = os.urandom(200)
            sig = keys.sign(seed, msg)
            self.assertTrue(keys.verify(pub, msg, sig))

    def test_message_is_bound(self):
        seed = keys.new_seed()
        pub = keys.public_key(seed)
        sig = keys.sign(seed, b"a")
        self.assertFalse(keys.verify(pub, b"b", sig))

    def test_key_is_bound(self):
        seed = keys.new_seed()
        other = keys.new_seed()
        sig = keys.sign(seed, b"msg")
        self.assertFalse(keys.verify(keys.public_key(other), b"msg", sig))

    def test_tampered_signature_rejected(self):
        seed = keys.new_seed()
        pub = keys.public_key(seed)
        sig = bytearray(keys.sign(seed, b"msg"))
        sig[10] ^= 0xFF
        self.assertFalse(keys.verify(pub, b"msg", bytes(sig)))
        sig = bytearray(keys.sign(seed, b"msg"))[:63]
        self.assertFalse(keys.verify(pub, b"msg", bytes(sig)))

    def test_malleable_s_rejected(self):
        # S + group order must not verify (signature malleability)
        seed = keys.new_seed()
        pub = keys.public_key(seed)
        sig = keys.sign(seed, b"msg")
        s = int.from_bytes(sig[32:], "little") + keys.Q
        if s < 2 ** 256:
            forged = sig[:32] + int.to_bytes(s, 32, "little")
            self.assertFalse(keys.verify(pub, b"msg", forged))

    def test_bad_inputs(self):
        self.assertFalse(keys.verify(b"", b"m", b""))
        with self.assertRaises(ValueError):
            keys.public_key(b"short")


class TestBundleSignature(TempDirCase):
    def bundle_dict(self):
        return {
            "format": "surreal.morph", "format_version": 1,
            "id": "org.test.signed", "name": "Signed patch",
            "target": {"filename": "app.exe", "size": 100, "sha256": "ab" * 32},
            "hunks": [{"offset": 10, "expect": "90", "replace": "CC"}],
            "policy": {"requires_rights_attestation": True},
        }

    def test_canonical_bytes_ignore_signature(self):
        d = self.bundle_dict()
        signed = keys.sign_bundle(d, keys.new_seed())
        self.assertEqual(keys.canonical_bytes(d), keys.canonical_bytes(signed))

    def test_canonical_bytes_are_order_independent(self):
        d = self.bundle_dict()
        shuffled = dict(reversed(list(d.items())))
        self.assertEqual(keys.canonical_bytes(d), keys.canonical_bytes(shuffled))

    def test_sign_and_verify(self):
        seed = keys.new_seed()
        signed = keys.sign_bundle(self.bundle_dict(), seed, signer="me")
        block = keys.verify_bundle(signed)
        self.assertEqual(block["public_key"], keys.public_key(seed).hex())
        self.assertEqual(block["signer"], "me")
        self.assertEqual(block["payload_sha256"],
                         hashlib.sha256(keys.canonical_bytes(signed)).hexdigest())

    def test_any_edit_breaks_signature(self):
        signed = keys.sign_bundle(self.bundle_dict(), keys.new_seed())
        for mutate in (
            lambda d: d.update(name="evil"),
            lambda d: d["hunks"][0].update(replace="C3"),
            lambda d: d["target"].update(sha256="cd" * 32),
            lambda d: d["hunks"].append({"offset": 20, "expect": "90",
                                         "replace": "C3"}),
        ):
            tampered = json.loads(json.dumps(signed))
            mutate(tampered)
            with self.assertRaises(keys.SignatureError):
                keys.verify_bundle(tampered)

    def test_unsigned(self):
        with self.assertRaises(keys.SignatureError) as ctx:
            keys.verify_bundle(self.bundle_dict())
        self.assertIn("not signed", str(ctx.exception))

    def test_malformed_signature_block(self):
        for bad in ({"alg": "rsa"}, {"alg": "ed25519", "public_key": "zz",
                                     "signature": "00"},
                    {"alg": "ed25519", "public_key": "00" * 32, "signature": "00"}):
            d = self.bundle_dict()
            d["signature"] = bad
            with self.assertRaises(keys.SignatureError):
                keys.verify_bundle(d)

    # -- key files ---------------------------------------------------------- #
    def test_key_file_roundtrip(self):
        path = self.path("me.key")
        record = keys.generate_key_file(path, signer="me")
        self.assertEqual(len(record["private_seed"]), 64)
        loaded = keys.load_key_file(path)
        self.assertEqual(loaded["public_key"], record["public_key"])

    def test_key_file_refuses_overwrite(self):
        path = self.path("me.key")
        keys.generate_key_file(path)
        with self.assertRaises(keys.SignatureError):
            keys.generate_key_file(path)
        keys.generate_key_file(path, force=True)

    def test_key_file_rejects_inconsistent_seed(self):
        path = self.path("bad.key")
        record = keys.generate_key_file(path)
        record["private_seed"] = keys.new_seed().hex()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        with self.assertRaises(keys.SignatureError) as ctx:
            keys.load_key_file(path)
        self.assertIn("inconsistent", str(ctx.exception))

    def test_key_file_rejects_junk(self):
        path = self.path("junk.key")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"format":"surreal.key","alg":"ed25519","private_seed":"00"}')
        with self.assertRaises(keys.SignatureError):
            keys.load_key_file(path)
        with self.assertRaises(keys.SignatureError):
            keys.load_key_file(self.path("missing.key"))

    # -- trust store -------------------------------------------------------- #
    def test_trust_store(self):
        cfg = self.path("cfg")
        pub = keys.public_key(keys.new_seed()).hex()
        self.assertFalse(keys.is_trusted(cfg, pub))
        keys.trust_key(cfg, pub, label="maintainer")
        self.assertTrue(keys.is_trusted(cfg, pub))
        self.assertTrue(keys.is_trusted(cfg, pub.upper()))
        self.assertEqual(keys.load_trust(cfg)["keys"][0]["label"], "maintainer")
        self.assertTrue(keys.untrust_key(cfg, pub))
        self.assertFalse(keys.is_trusted(cfg, pub))
        self.assertFalse(keys.untrust_key(cfg, pub))

    def test_trust_rejects_bad_keys(self):
        for bad in ("", "00" * 31, "zz" * 32):
            with self.assertRaises(keys.SignatureError):
                keys.trust_key(self.path("cfg"), bad)

    def test_check_bundle_signature_states(self):
        cfg = self.path("cfg")
        seed = keys.new_seed()
        signed = keys.sign_bundle(self.bundle_dict(), seed)
        pub = keys.public_key(seed).hex()

        self.assertEqual(keys.check_bundle_signature(signed, cfg)[0], "untrusted")
        self.assertEqual(keys.check_bundle_signature(self.bundle_dict(), cfg)[0],
                         "unsigned")
        keys.trust_key(cfg, pub)
        self.assertEqual(keys.check_bundle_signature(signed, cfg)[0], "valid")
        self.assertEqual(
            keys.check_bundle_signature(signed, self.path("other"),
                                        extra_trusted=[pub])[0], "valid")

        with self.assertRaises(keys.SignatureError):
            keys.check_bundle_signature(self.bundle_dict(), cfg, require=True)

        other = keys.new_seed()
        untrusted = keys.sign_bundle(self.bundle_dict(), other)
        with self.assertRaises(keys.SignatureError) as ctx:
            keys.check_bundle_signature(untrusted, cfg, require=True)
        self.assertIn("not in your trusted keys", str(ctx.exception))

    def test_invalid_signature_always_raises(self):
        cfg = self.path("cfg")
        signed = keys.sign_bundle(self.bundle_dict(), keys.new_seed())
        signed["name"] = "changed"
        with self.assertRaises(keys.SignatureError):
            keys.check_bundle_signature(signed, cfg)
        with self.assertRaises(keys.SignatureError):
            keys.check_bundle_signature(signed, cfg, require=True)


if __name__ == "__main__":
    unittest.main()
