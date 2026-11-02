"""Collection dependencies and conflicts: ordering, validation, refusal."""

import json
import os
import unittest

from helpers import TempDirCase, sample_app, write

from surreal import collection as coll
from surreal import diffgen

from test_collection import make_pair


class DepCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.dir = self.path("patches")
        os.makedirs(self.dir, exist_ok=True)
        self.target = write(self.path("app.exe"), sample_app())
        # three unrelated size-preserving patches over the same fixture
        self.bundle("a", {0x251: b"\x7e"})
        self.bundle("b", {0x449: b"\0" * 36})
        self.bundle("c", {0x451: b"\0" * 4})

    def bundle(self, name, edit):
        new = write(self.path(name + "_mod.exe"), make_pair(name, edit))
        bundle, _ = diffgen.build_bundle(self.target, new, "org.dep." + name, name)
        bundle.save(os.path.join(self.dir, name + ".morph"))
        return name + ".morph"

    def load(self, patches):
        manifest = os.path.join(self.dir, "surreal-collection.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"format": "surreal.collection", "format_version": 1,
                       "name": "dep set", "patches": patches}, fh)
        return coll.load_collection(self.dir)

    def three(self):
        return [
            {"bundle": "a.morph", "order": 30},
            {"bundle": "b.morph", "order": 20},
            {"bundle": "c.morph", "order": 10},
        ]


class TestOrdering(DepCase):
    def test_dependency_moves_patch_earlier(self):
        c = self.load([
            {"bundle": "b.morph", "order": 10, "depends_on": ["org.dep.c"]},
            {"bundle": "c.morph", "order": 50},
            {"bundle": "a.morph", "order": 5},
        ])
        self.assertEqual([e.bundle.id for e in c.entries],
                         ["org.dep.a", "org.dep.c", "org.dep.b"])

    def test_plain_order_is_unchanged_without_dependencies(self):
        c = self.load(self.three())
        self.assertEqual([e.bundle.id for e in c.entries],
                         ["org.dep.c", "org.dep.b", "org.dep.a"])

    def test_cascading_dependencies(self):
        c = self.load([
            {"bundle": "a.morph", "order": 50, "depends_on": ["org.dep.b"]},
            {"bundle": "b.morph", "order": 40, "depends_on": ["org.dep.c"]},
            {"bundle": "c.morph", "order": 30},
        ])
        self.assertEqual([e.bundle.id for e in c.entries],
                         ["org.dep.c", "org.dep.b", "org.dep.a"])

    def test_unknown_dependency_refused(self):
        with self.assertRaises(coll.CollectionError) as ctx:
            self.load([{"bundle": "a.morph", "depends_on": ["org.dep.nope"]},
                       {"bundle": "b.morph"}])
        self.assertIn("not in this collection", str(ctx.exception))

    def test_self_dependency_refused(self):
        with self.assertRaises(coll.CollectionError) as ctx:
            self.load([{"bundle": "a.morph", "depends_on": ["org.dep.a"]}])
        self.assertIn("depends on itself", str(ctx.exception))

    def test_cycle_refused(self):
        with self.assertRaises(coll.CollectionError) as ctx:
            self.load([
                {"bundle": "a.morph", "depends_on": ["org.dep.b"]},
                {"bundle": "b.morph", "depends_on": ["org.dep.a"]},
            ])
        self.assertIn("dependency cycle", str(ctx.exception))

    def test_malformed_dependency_field(self):
        for bad in (5, [""], [None], {"x": 1}):
            with self.assertRaises(coll.CollectionError):
                self.load([{"bundle": "a.morph", "depends_on": bad}])

    def test_duplicate_bundle_ids_refused(self):
        with self.assertRaises(coll.CollectionError) as ctx:
            self.load([{"bundle": "a.morph"}, {"bundle": "a.morph", "order": 5}])
        self.assertIn("duplicate bundle id", str(ctx.exception))

    def test_dependencies_survive_roundtrip(self):
        c = self.load([{"bundle": "a.morph", "depends_on": ["org.dep.b"],
                        "conflicts_with": ["org.other.thing"]},
                       {"bundle": "b.morph"}])
        raw = {p["bundle"]: p for p in c.to_dict()["patches"]}
        self.assertEqual(raw["a.morph"]["depends_on"], ["org.dep.b"])
        self.assertEqual(raw["a.morph"]["conflicts_with"], ["org.other.thing"])
        self.assertNotIn("depends_on", raw["b.morph"])
        c.save(os.path.join(self.dir, "saved.json"))
        again = coll.load_collection(os.path.join(self.dir, "saved.json"))
        # reloaded in dependency order: b first, then a (which depends on b)
        self.assertEqual([e.bundle.id for e in again.entries],
                         ["org.dep.b", "org.dep.a"])
        self.assertEqual([e.depends_on for e in again.entries], [[], ["org.dep.b"]])


class TestConflicts(DepCase):
    def test_declared_conflict_blocks_the_set(self):
        c = self.load([
            {"bundle": "a.morph", "order": 10, "conflicts_with": ["org.dep.b"]},
            {"bundle": "b.morph", "order": 20},
        ])
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.preflight(c, self.target)
        self.assertIn("conflicts with", str(ctx.exception))

    def test_conflict_with_absent_patch_is_fine(self):
        c = self.load([{"bundle": "a.morph", "conflicts_with": ["org.elsewhere.x"]},
                       {"bundle": "b.morph"}])
        self.assertEqual(len(coll.select(c, self.target)[0]), 2)

    def test_disabled_conflicting_patch_does_not_block(self):
        c = self.load([
            {"bundle": "a.morph", "order": 10, "conflicts_with": ["org.dep.b"]},
            {"bundle": "b.morph", "order": 20, "enabled": False},
        ])
        ok, skipped = coll.select(c, self.target)
        self.assertEqual([e.bundle.id for e in ok], ["org.dep.a"])
        self.assertEqual([e.bundle.id for e in skipped], ["org.dep.b"])

    def test_dependency_on_disabled_patch_is_refused(self):
        c = self.load([
            {"bundle": "a.morph", "order": 10, "depends_on": ["org.dep.b"]},
            {"bundle": "b.morph", "order": 5, "enabled": False},
        ])
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.select(c, self.target)
        self.assertIn("which is disabled", str(ctx.exception))

    def test_apply_refuses_conflicts_too(self):
        c = self.load([
            {"bundle": "a.morph", "order": 10, "conflicts_with": ["org.dep.b"]},
            {"bundle": "b.morph", "order": 20},
        ])
        before = open(self.target, "rb").read()
        with self.assertRaises(coll.CollectionError):
            coll.apply_collection(c, self.target)
        self.assertEqual(open(self.target, "rb").read(), before)


if __name__ == "__main__":
    unittest.main()
