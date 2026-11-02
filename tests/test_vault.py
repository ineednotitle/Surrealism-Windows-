"""Multi-file vault collections: grouping, all-or-nothing apply, rollback."""

import json
import os
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import collection as coll
from surreal import diffgen, patcher
from surreal.patchfile import Bundle
from surreal.util import sha256_file

TEXT = 0x60000020
RDATA = 0x40000040


def edit(data: bytes, offset: int, blob: bytes) -> bytes:
    out = bytearray(data)
    out[offset:offset + len(blob)] = blob
    return bytes(out)


def second_app():
    return build_pe([(".text", b"\x90" * 0x100, TEXT),
                     (".rdata", b"helper-string\0" * 8, RDATA)])


class VaultCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.dir = self.path("patches")
        os.makedirs(self.dir, exist_ok=True)
        self.root = self.path("app")
        os.makedirs(self.root, exist_ok=True)
        self.main_bytes = sample_app()
        self.helper_bytes = second_app()
        os.makedirs(os.path.join(self.root, "sub"))
        self.main = write(os.path.join(self.root, "main.exe"), self.main_bytes)
        self.helper = write(os.path.join(self.root, "sub", "helper.dll"),
                            self.helper_bytes)
        self.entries = []

    # -- fixtures ---------------------------------------------------------- #
    def add_bundle(self, name, new_bytes, target_rel, order=100):
        old = os.path.join(self.root, *target_rel.split("/"))
        new = write(self.path(name + "_mod.bin"), new_bytes)
        bundle, _ = diffgen.build_bundle(old, new, "org.vault." + name, name)
        path = os.path.join(self.dir, name + ".morph")
        bundle.save(path)
        self.entries.append({"bundle": name + ".morph", "order": order,
                             "target": target_rel})
        return path

    def main_entries(self, order=10):
        self.add_bundle("main-jump", edit(self.main_bytes, 0x251, b"\x7e"),
                        "main.exe", order=order)
        self.add_bundle("main-nag", edit(self.main_bytes, 0x449, b"\0" * 36),
                        "main.exe", order=order + 10)

    def load(self, patches=None, name="Vault"):
        manifest = os.path.join(self.dir, "surreal-collection.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"format": "surreal.collection", "format_version": 1,
                       "name": name, "patches": patches or self.entries}, fh)
        return coll.load_collection(self.dir)


class TestLoading(VaultCase):
    def test_detects_vault_and_groups_files(self):
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=5)
        c = self.load()
        self.assertTrue(c.is_vault)
        # groups follow global order (order=5 for the helper comes first)
        self.assertEqual(c.files(), ["sub/helper.dll", "main.exe"])
        groups = dict(c.by_file())
        self.assertEqual(len(groups["main.exe"]), 2)
        self.assertEqual(len(groups["sub/helper.dll"]), 1)

    def test_single_target_collection_is_not_a_vault(self):
        self.main_entries()
        c = self.load([{k: v for k, v in self.entries[0].items() if k != "target"}])
        self.assertFalse(c.is_vault)

    def test_mixed_entries_refused(self):
        self.main_entries()
        self.entries[0] = {k: v for k, v in self.entries[0].items() if k != "target"}
        with self.assertRaises(coll.CollectionError) as ctx:
            self.load()
        self.assertIn("mixed collection", str(ctx.exception))

    def test_absolute_and_traversal_targets_refused(self):
        self.main_entries()
        for bad in ("/etc/passwd", "C:/Windows/System32/notepad.exe",
                    "../../escape.exe", "sub/../../x.exe"):
            self.entries[1]["target"] = bad
            with self.assertRaises(coll.CollectionError):
                self.load()

    def test_roundtrip_keeps_targets(self):
        self.main_entries()
        c = self.load()
        self.assertEqual([e["target"] for e in c.to_dict()["patches"]],
                         ["main.exe", "main.exe"])
        # saving and reloading the manifest keeps vault mode intact
        c.save(os.path.join(self.dir, "saved.json"))
        again = coll.load_collection(os.path.join(self.dir, "saved.json"))
        self.assertTrue(again.is_vault)
        self.assertEqual(again.files(), ["main.exe"])


class TestPreflight(VaultCase):
    def test_requires_the_application_directory(self):
        self.main_entries()
        c = self.load()
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.resolve_root(c, self.main)
        self.assertIn("must be that directory", str(ctx.exception))

    def test_missing_target_file(self):
        self.main_entries()
        new = write(self.path("phantom.bin"),
                    edit(self.helper_bytes, 0x201, b"PHANTOM\0"))
        bundle, _ = diffgen.build_bundle(self.helper, new, "org.vault.phantom",
                                        "phantom")
        bundle.save(os.path.join(self.dir, "phantom.morph"))
        self.entries.append({"bundle": "phantom.morph", "target": "nope.exe",
                             "order": 1})
        c = self.load()
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.resolve_root(c, self.root)
        self.assertIn("not found", str(ctx.exception))

    def test_preflight_touches_nothing(self):
        self.main_entries()
        c = self.load()
        before = (sha256_file(self.main), sha256_file(self.helper))
        report = coll.preflight_vault(c, self.root)
        self.assertEqual(len(report["files"]), 1)
        self.assertEqual(report["files"][0]["file"], "main.exe")
        self.assertEqual(len(report["files"][0]["patches"]), 2)
        self.assertEqual((sha256_file(self.main), sha256_file(self.helper)), before)

    def test_layout_changing_member_refused(self):
        self.main_entries()
        grown = write(self.path("grown.bin"), self.helper_bytes + b"EXTRA")
        bundle, _ = diffgen.build_bundle(self.helper, grown, "org.vault.grow", "grow")
        bundle.save(os.path.join(self.dir, "grow.morph"))
        self.entries.append({"bundle": "grow.morph", "target": "sub/helper.dll"})
        c = self.load()
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.preflight_vault(c, self.root)
        self.assertIn("size or layout", str(ctx.exception))


class TestApply(VaultCase):
    def test_applies_across_files_and_reverts_per_file(self):
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=50)
        c = self.load()
        before_main, before_helper = sha256_file(self.main), sha256_file(self.helper)
        result = coll.apply_vault(c, self.root)
        self.assertEqual(len(result["files"]), 2)
        self.assertEqual(result["files"][0]["file"], "main.exe")
        self.assertNotEqual(sha256_file(self.main), before_main)
        self.assertNotEqual(sha256_file(self.helper), before_helper)

        # each file has its own journal entry, so revert works per file
        patcher.revert(self.main)
        self.assertEqual(sha256_file(self.main), before_main)
        self.assertNotEqual(sha256_file(self.helper), before_helper)
        patcher.revert(self.helper)
        self.assertEqual(sha256_file(self.helper), before_helper)

    def test_same_directory_journal_is_per_file(self):
        # both binaries live in one directory, so they share one journal file;
        # revert must still pick each file's own entry
        self.main_entries()
        helper_root = os.path.join(self.root, "helper.exe")
        write(helper_root, self.helper_bytes)
        bundle, _ = diffgen.build_bundle(
            helper_root, write(self.path("h_mod.bin"),
                              edit(self.helper_bytes, 0x201, b"HELPER\0\0")),
            "org.vault.helper2", "helper2")
        bundle.save(os.path.join(self.dir, "helper2.morph"))
        self.entries.append({"bundle": "helper2.morph", "target": "helper.exe"})
        c = self.load()
        before = (sha256_file(self.main), sha256_file(helper_root))
        coll.apply_vault(c, self.root)
        from surreal.journal import Journal

        for path in (self.main, helper_root):
            entry = Journal(path).last()
            self.assertEqual(entry["action"], "apply-vault")
            self.assertEqual(os.path.abspath(entry["target"]), os.path.abspath(path))
        patcher.revert(self.main)
        self.assertEqual(sha256_file(self.main), before[0])
        self.assertNotEqual(sha256_file(helper_root), before[1])
        patcher.revert(helper_root)
        self.assertEqual(sha256_file(helper_root), before[1])

    def test_one_journal_entry_per_file(self):
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=50)
        c = self.load()
        coll.apply_vault(c, self.root)
        from surreal.journal import Journal

        for path in (self.main, self.helper):
            entry = Journal(path).last()
            self.assertEqual(entry["action"], "apply-vault")
            self.assertEqual(entry["collection"], "Vault")
            self.assertEqual(len(entry["vault_files"]), 2)

    def test_rollback_restores_every_file(self):
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=50)
        c = self.load()
        # corrupt the *second* file's second patch so the vault fails after the
        # first file has already been written
        broken = c.entries[-1].bundle
        broken.hunks[0].replace = bytearray(broken.hunks[0].replace)
        broken.hunks[0].expect = bytearray(broken.hunks[0].expect or
                                          b"\0" * len(broken.hunks[0].replace))
        broken.hunks[0].expect[0] = (broken.hunks[0].expect[0] + 1) % 256
        before_main, before_helper = sha256_file(self.main), sha256_file(self.helper)
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.apply_vault(c, self.root)
        self.assertIn("restored from backup", str(ctx.exception))
        self.assertEqual(sha256_file(self.main), before_main)
        self.assertEqual(sha256_file(self.helper), before_helper)

    def test_skips_files_with_no_matching_patch(self):
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=50)
        data = bytearray(self.helper_bytes)
        data[0x201] = 0x00
        write(self.helper, bytes(data))     # helper no longer matches its bundle
        c = self.load()
        result = coll.apply_vault(c, self.root)
        self.assertEqual([f["file"] for f in result["files"]], ["main.exe"])
        self.assertEqual(result["skipped"][0]["file"], "sub/helper.dll")

    def test_backups_are_verified_copies(self):
        self.main_entries()
        c = self.load()
        before = sha256_file(self.main)
        result = coll.apply_vault(c, self.root)
        backup = result["files"][0]["backup"]
        self.assertTrue(os.path.isfile(backup))
        self.assertEqual(sha256_file(backup), before)


class TestDependencyGraph(VaultCase):
    """Declared dependencies must hold *across* the vault's files, not just one."""

    def test_graph_reports_cross_file_edge(self):
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=5)
        entries = [dict(e) for e in self.entries]
        entries[0]["depends_on"] = ["org.vault.helper"]
        graph = coll.dependency_graph(self.load(entries))
        self.assertEqual([(e["from"], e["to"]) for e in graph["edges"]],
                         [("org.vault.main-jump", "org.vault.helper")])
        self.assertEqual(len(graph["cross_file_edges"]), 1)
        self.assertEqual(graph["cross_file_edges"][0]["to_file"], "sub/helper.dll")
        self.assertEqual(graph["issues"], [])

    def test_cycle_across_files_is_rejected(self):
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=5)
        entries = [dict(e) for e in self.entries]
        entries[0]["depends_on"] = ["org.vault.helper"]
        entries[2]["depends_on"] = ["org.vault.main-jump"]
        with self.assertRaises(coll.CollectionError) as ctx:
            self.load(entries)          # the loader refuses to order a cycle
        self.assertIn("dependency cycle", str(ctx.exception))
        # and the graph view finds the same cycle on its own
        self.assertEqual(coll._find_cycle({"a": ["b"], "b": ["a"]}, ["a", "b"]),
                         ["a", "b", "a"])

    def test_missing_dependency_is_caught_while_loading(self):
        self.main_entries()
        entries = [dict(e) for e in self.entries]
        entries[0]["depends_on"] = ["org.vault.nope"]
        with self.assertRaises(coll.CollectionError) as ctx:
            self.load(entries)
        self.assertIn("org.vault.nope", str(ctx.exception))
        self.assertIn("not in this collection", str(ctx.exception))

    def test_disabled_dependency_fails_preflight(self):
        # main-jump needs the helper patch, but the helper patch is switched off
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=99)
        c = self.load()
        c.entries[0].depends_on = ["org.vault.helper"]
        for entry in c.entries:
            if entry.target == "sub/helper.dll":
                entry.enabled = False
        graph = coll.dependency_graph(c)
        self.assertEqual([i["kind"] for i in graph["issues"]],
                         ["disabled-dependency"])
        before = sha256_file(self.main)
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.preflight_vault(c, self.root)
        self.assertIn("org.vault.helper", str(ctx.exception))
        self.assertIn("disabled", str(ctx.exception))
        self.assertEqual(sha256_file(self.main), before)

    def test_conflict_within_a_file_is_rejected_in_vault_mode(self):
        self.main_entries()
        entries = [dict(self.entries[0]), dict(self.entries[1])]
        entries[0]["conflicts_with"] = ["org.vault.main-nag"]
        c = self.load(entries)
        with self.assertRaises(coll.CollectionError) as ctx:
            coll.preflight_vault(c, self.root)
        self.assertIn("conflicts with", str(ctx.exception))

    def test_forward_cross_file_dependency_warns_but_runs(self):
        # load_collection topologically sorts, so this can only happen when a
        # Collection is built by hand: main.exe depends on a patch for the helper,
        # yet main.exe is patched first. It still works (different files) but the
        # user is told the order is odd.
        self.main_entries()
        self.add_bundle("helper", edit(self.helper_bytes, 0x201, b"HELPER\0\0"),
                        "sub/helper.dll", order=99)
        c = self.load()
        c.entries[0].depends_on = ["org.vault.helper"]
        # force main.exe first in manifest order without touching the loader
        c.entries.sort(key=lambda e: 0 if e.target == "main.exe" else 1)
        self.assertEqual([rel for rel, _entries in c.by_file()],
                         ["main.exe", "sub/helper.dll"])
        report = coll.preflight_vault(c, self.root)
        self.assertEqual([f["file"] for f in report["files"]],
                         ["main.exe", "sub/helper.dll"])
        self.assertTrue(any("patched after" in w for w in report["warnings"]))
        validate = coll.validate_graph(c, {e.bundle.id for e in c.entries})
        self.assertEqual(validate["issues"], [])
        result = coll.apply_vault(c, self.root)
        self.assertEqual([f["file"] for f in result["files"]],
                         ["main.exe", "sub/helper.dll"])

    def test_graph_is_serialisable(self):
        self.main_entries()
        c = self.load()
        json.dumps(coll.dependency_graph(c))


if __name__ == "__main__":
    unittest.main()
