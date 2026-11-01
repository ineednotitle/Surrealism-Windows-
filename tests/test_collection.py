"""Patch collections: selection, ordering, transactional apply and rollback."""

import hashlib
import json
import os
import unittest

from helpers import TempDirCase, sample_app, write

from surreal import collection as coll
from surreal import diffgen, patcher
from surreal.patchfile import Bundle
from surreal.util import sha256_file


def make_pair(name, edits):
    """Return (bytes) of sample_app with the given byte edits applied."""
    data = bytearray(sample_app())
    for offset, blob in edits.items():
        data[offset:offset + len(blob)] = blob
    return bytes(data)


class CollectionCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.dir = self.path("patches")
        os.makedirs(self.dir, exist_ok=True)
        self.target = write(self.path("app.exe"), sample_app())
        self.jump = make_pair("jump", {0x251: b"\x7E"})
        self.nag = make_pair("nag", {0x449: b"\0" * 36})

    def add_bundle(self, name, new_bytes, order=100, required=False, enabled=True):
        new = write(self.path(name + "_mod.exe"), new_bytes)
        bundle, _ = diffgen.build_bundle(self.target, new, "org.test." + name, name)
        path = os.path.join(self.dir, name + ".morph")
        bundle.save(path)
        return {"bundle": name + ".morph", "order": order, "required": required,
                **({} if enabled else {"enabled": False})}

    def write_manifest(self, patches, name="Test set"):
        manifest = os.path.join(self.dir, "surreal-collection.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"format": "surreal.collection", "format_version": 1,
                       "name": name, "patches": patches}, fh, indent=2)
        return manifest

    def load(self, patches, name="Test set"):
        self.write_manifest(patches, name)
        return coll.load_collection(self.dir)


class TestLoading(CollectionCase):
    def test_loads_and_orders(self):
        self.add_bundle("jump", self.jump, order=30)
        self.add_bundle("nag", self.nag, order=10)
        c = self.load([{"bundle": "jump.morph", "order": 30},
                       {"bundle": "nag.morph", "order": 10}])
        self.assertEqual([e.bundle.id for e in c.entries],
                         ["org.test.nag", "org.test.jump"])
        self.assertEqual(c.name, "Test set")

    def test_finds_manifest_in_directory(self):
        self.add_bundle("jump", self.jump)
        self.load([{"bundle": "jump.morph"}])
        self.assertTrue(coll.find_manifest(self.dir).endswith("surreal-collection.json"))

    def test_missing_manifest(self):
        with self.assertRaises(coll.CollectionError):
            coll.find_manifest(self.path("nope"))

    def test_rejects_path_traversal(self):
        self.add_bundle("jump", self.jump)
        for bad in ("../jump.morph", "C:\\windows\\x.morph", "/etc/passwd"):
            c = None
            with self.assertRaises(coll.CollectionError):
                self.load([{"bundle": bad}])

    def test_rejects_unknown_keys(self):
        self.add_bundle("jump", self.jump)
        manifest = self.write_manifest([{"bundle": "jump.morph"}])
        with open(manifest, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["surprise"] = True
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        with self.assertRaises(coll.CollectionError):
            coll.load_collection(self.dir)
        self.assertTrue(coll.load_collection(self.dir, strict=False).entries)

    def test_rejects_wrong_format(self):
        self.add_bundle("jump", self.jump)
        manifest = self.write_manifest([{"bundle": "jump.morph"}])
        with open(manifest, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["format"] = "something.else"
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        with self.assertRaises(coll.CollectionError):
            coll.load_collection(self.dir)

    def test_rejects_empty_and_broken_bundles(self):
        with self.assertRaises(coll.CollectionError):
            self.load([])
        manifest = self.write_manifest([{"bundle": "missing.morph"}])
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.load_collection(self.dir)
        self.assertIn("missing.morph", str(ctx.exception))

    def test_roundtrip_save(self):
        self.add_bundle("jump", self.jump)
        c = self.load([{"bundle": "jump.morph", "order": 5, "required": True}])
        out = os.path.join(self.dir, "copy.json")  # same dir: bundle paths resolve
        c.save(out)
        again = coll.load_collection(out)
        self.assertEqual(again.entries[0].order, 5)
        self.assertTrue(again.entries[0].required)


class TestSelection(CollectionCase):
    def test_select_and_skip(self):
        self.add_bundle("jump", self.jump, order=1)
        self.add_bundle("nag", self.nag, order=2, enabled=False)
        c = self.load([{"bundle": "jump.morph", "order": 1},
                       {"bundle": "nag.morph", "order": 2, "enabled": False}])
        ok, skipped = coll.select(c, self.target)
        self.assertEqual([e.bundle.id for e in ok], ["org.test.jump"])
        self.assertEqual(len(skipped), 1)

    def test_no_match_is_an_error(self):
        self.add_bundle("jump", self.jump)
        c = self.load([{"bundle": "jump.morph"}])
        other = write(self.path("other.exe"), make_pair("x", {0x251: b"\x7E"}))
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.preflight(c, other)
        self.assertIn("no patch", str(ctx.exception))


class TestTransactionalApply(CollectionCase):
    def two_patch_set(self, name="Test set"):
        self.add_bundle("jump", self.jump, order=10)
        self.add_bundle("nag", self.nag, order=20)
        return self.load([{"bundle": "jump.morph", "order": 10},
                          {"bundle": "nag.morph", "order": 20}], name)

    def test_applies_both_patches(self):
        c = self.two_patch_set()
        res = coll.apply_collection(c, self.target)
        self.assertEqual([a["bundle"] for a in res["applied"]],
                         ["org.test.jump", "org.test.nag"])
        expected = make_pair("both", {0x251: b"\x7E", 0x449: b"\0" * 36})
        with open(self.target, "rb") as fh:
            got = fh.read()
        # the PE checksum is recomputed, everything else must match
        skip = Bundle.load(os.path.join(self.dir, "jump.morph")).target["size"]
        self.assertEqual(len(got), len(expected))
        self.assertNotEqual(got, expected)  # checksum differs
        self.assertEqual(got[:100], expected[:100])

    def test_preflight_does_not_touch_the_target(self):
        c = self.two_patch_set()
        before = sha256_file(self.target)
        report = coll.preflight(c, self.target)
        self.assertEqual(len(report["applicable"]), 2)
        self.assertEqual(sha256_file(self.target), before)

    def test_single_journal_entry_for_the_whole_set(self):
        from surreal.journal import Journal

        c = self.two_patch_set()
        coll.apply_collection(c, self.target)
        entries = Journal(self.target).entries
        self.assertEqual([e["action"] for e in entries], ["apply-collection"])
        self.assertEqual(entries[0]["patches"], ["org.test.jump", "org.test.nag"])

    def test_revert_undoes_the_whole_set(self):
        c = self.two_patch_set()
        before = sha256_file(self.target)
        coll.apply_collection(c, self.target)
        patcher.revert(self.target)
        self.assertEqual(sha256_file(self.target), before)

    def test_rollback_on_failure(self):
        self.add_bundle("jump", self.jump, order=10)
        # author the second patch against a *different* build whose bytes are
        # absent here, then point the collection at it
        other = write(self.path("other.exe"), make_pair("x", {0x251: b"\xEB"}))
        broken_new = write(self.path("broken.exe"), make_pair("y", {0x300: b"\xFF"}))
        broken, _ = diffgen.build_bundle(other, broken_new, "org.test.broken", "broken")
        broken.target["sha256"] = sha256_file(self.target)  # pass selection
        broken.target["size"] = os.path.getsize(self.target)
        broken.save(os.path.join(self.dir, "broken.morph"))
        c = self.load([{"bundle": "jump.morph", "order": 10},
                       {"bundle": "broken.morph", "order": 20}])
        before = sha256_file(self.target)
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.apply_collection(c, self.target)
        self.assertIn("restored from backup", str(ctx.exception))
        self.assertEqual(sha256_file(self.target), before)

    def test_size_changing_patch_refused(self):
        with open(self.target, "rb") as fh:
            base = fh.read()
        grown = write(self.path("grown.exe"), base + b"OVERLAY")
        bundle, _ = diffgen.build_bundle(self.target, grown, "org.test.grow", "grow")
        bundle.save(os.path.join(self.dir, "grow.morph"))
        c = self.load([{"bundle": "grow.morph"}])
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.preflight(c, self.target)
        self.assertIn("size or layout", str(ctx.exception))

    def test_policy_blocked_member_refuses_whole_set(self):
        self.add_bundle("jump", self.jump)
        manifest = self.write_manifest([{"bundle": "jump.morph"}])
        bundle_path = os.path.join(self.dir, "jump.morph")
        raw = Bundle.load(bundle_path).to_dict()
        raw["policy"] = {"requires_rights_attestation": True,
                         "forbidden_categories": ["drm"]}
        with open(bundle_path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        c = coll.load_collection(self.dir)
        before = sha256_file(self.target)
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.apply_collection(c, self.target)
        self.assertIn("policy-blocked", str(ctx.exception))
        self.assertEqual(sha256_file(self.target), before)

    def test_required_flag_is_recorded(self):
        self.add_bundle("jump", self.jump)
        c = self.load([{"bundle": "jump.morph", "required": True}])
        self.assertTrue(c.entries[0].required)

    def test_signed_collection_with_require_signature(self):
        from surreal import keys, policy

        self.add_bundle("jump", self.jump)
        bundle_path = os.path.join(self.dir, "jump.morph")
        seed = keys.new_seed()
        raw = Bundle.load(bundle_path).to_dict()
        with open(bundle_path, "w", encoding="utf-8") as fh:
            json.dump(keys.sign_bundle(raw, seed, signer="tester"), fh, indent=2)
        c = self.load([{"bundle": "jump.morph"}])
        before = sha256_file(self.target)
        with self.assertRaises(patcher.PatchError):
            coll.preflight(c, self.target, require_signature=True)
        self.assertEqual(sha256_file(self.target), before)
        keys.trust_key(policy.config_dir(), keys.public_key(seed).hex())
        report = coll.preflight(c, self.target, require_signature=True)
        self.assertEqual(report["applicable"][0]["signature"], "valid")


if __name__ == "__main__":
    unittest.main()
