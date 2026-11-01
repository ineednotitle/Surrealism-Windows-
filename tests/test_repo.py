"""Local patch repositories: indexing, integrity, listing and apply."""

import json
import os
import unittest

from helpers import TempDirCase, build_pe, sample_app, write

from surreal import diffgen, patcher, repo
from surreal.patchfile import Bundle
from surreal.testkit import make_pe_pair
from surreal.util import sha256_file

TEXT = 0x60000020
RDATA = 0x40000040


class RepoCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.repo_dir = self.path("repo")
        os.makedirs(self.repo_dir, exist_ok=True)
        self.target = write(self.path("app.exe"), sample_app())

    def add_bundle(self, name, new_bytes, bundle_id=None):
        new = write(self.path(name + "_mod.exe"), new_bytes)
        bundle, _ = diffgen.build_bundle(self.target, new,
                                         bundle_id or ("org.repo." + name), name)
        path = os.path.join(self.repo_dir, name + ".morph")
        bundle.save(path)
        return path

    def broken_bundle(self, name):
        path = os.path.join(self.repo_dir, name + ".morph")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"format":"surreal.morph","format_version":1,"id":"x",'
                     '"target":{"filename":"a.exe"},"hunks":[]}')
        return path

    def index(self, name="Test repo"):
        raw = repo.build_index(self.repo_dir, name=name,
                               base_dir=self.repo_dir)
        path = os.path.join(self.repo_dir, "surreal-repo.json")
        repo.write_index(raw, path)
        return path


class TestIndexing(RepoCase):
    def test_indexes_bundles_with_hashes(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        self.add_bundle("b", sample_app().replace(b"Trial expired.", b"Xrial expired."))
        index = repo.load_index(self.index())
        self.assertEqual(len(index["bundles"]), 2)
        for entry in index["bundles"]:
            self.assertTrue(entry["id"].startswith("org.repo."))
            self.assertEqual(entry["bundle_sha256"],
                             sha256_file(os.path.join(self.repo_dir, entry["file"])))
            self.assertEqual(entry["target"]["size"], len(sample_app()))
            self.assertIn("patch", entry["ops"])

    def test_skips_unreadable_bundles_but_reports_them(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        self.broken_bundle("zbroken")
        raw = repo.build_index(self.repo_dir, base_dir=self.repo_dir)
        self.assertEqual(len(raw["bundles"]), 1)
        self.assertTrue(any("zbroken" in s for s in raw.get("skipped") or []))

    def test_duplicate_ids_are_skipped(self):
        data = sample_app()
        self.add_bundle("a", data.replace(b"Version 1.0.0", b"Version 9.9.9"),
                        bundle_id="org.repo.same")
        self.add_bundle("b", data.replace(b"Trial expired.", b"Xrial expired."),
                        bundle_id="org.repo.same")
        raw = repo.build_index(self.repo_dir, base_dir=self.repo_dir)
        self.assertEqual(len(raw["bundles"]), 1)
        self.assertTrue(any("duplicate bundle id" in s
                            for s in raw.get("skipped") or []))

    def test_empty_directory_is_an_error(self):
        with self.assertRaises(repo.RepoError):
            repo.build_index(self.repo_dir, base_dir=self.repo_dir)

    def test_index_is_portable_relative(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        path = self.index()
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        self.assertNotIn("base", raw)
        for entry in raw["bundles"]:
            self.assertFalse(os.path.isabs(entry["file"]))
            self.assertNotIn("..", entry["file"])

    def test_index_above_the_bundle_tree_uses_base(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        outside = self.path("out")
        os.makedirs(outside)
        with self.assertRaises(repo.RepoError):
            repo.build_index(self.repo_dir, base_dir=outside)
        parent = self.path("")
        raw = repo.build_index(self.repo_dir, base_dir=parent)
        self.assertEqual(raw["base"], "repo")
        path = os.path.join(parent, "surreal-repo.json")
        repo.write_index(raw, path)
        index = repo.load_index(path)
        entry = index["bundles"][0]
        self.assertTrue(os.path.isfile(repo.bundle_path(index, entry)))


class TestLoading(RepoCase):
    def setUp(self):
        super().setUp()
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        self.path_index = self.index()

    def test_rejects_absolute_and_traversal_paths(self):
        with open(self.path_index, encoding="utf-8") as fh:
            raw = json.load(fh)
        for bad in ("/etc/passwd", "../../evil.morph", "C:/x.morph"):
            raw["bundles"][0]["file"] = bad
            with open(self.path_index, "w", encoding="utf-8") as fh:
                json.dump(raw, fh)
            with self.assertRaises(repo.RepoError):
                repo.load_index(self.path_index)

    def test_rejects_unknown_keys(self):
        with open(self.path_index, encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["surprise"] = 1
        with open(self.path_index, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        with self.assertRaises(repo.RepoError):
            repo.load_index(self.path_index)
        self.assertTrue(repo.load_index(self.path_index, strict=False))

    def test_rejects_wrong_format_and_empty(self):
        for payload in ({"format": "nope", "bundles": [{}]},
                        {"format": "surreal.repo", "format_version": 1,
                         "bundles": []}):
            with open(self.path_index, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            with self.assertRaises(repo.RepoError):
                repo.load_index(self.path_index)

    def test_missing_index(self):
        with self.assertRaises(repo.RepoError):
            repo.find_index(self.path("nowhere"))

    def test_get_unknown_id(self):
        index = repo.load_index(self.path_index)
        with self.assertRaises(repo.RepoError) as ctx:
            repo.get(index, "org.repo.nope")
        self.assertIn("not in this repo", str(ctx.exception))


class TestIntegrity(RepoCase):
    def test_detects_a_tampered_bundle_file(self):
        path = self.add_bundle("a", sample_app().replace(b"Version 1.0.0",
                                                         b"Version 9.9.9"))
        index = repo.load_index(self.index())
        entry = index["bundles"][0]
        bundle = Bundle.load(path)
        bundle.description = "tampered"
        bundle.save(path)
        with self.assertRaises(repo.RepoError) as ctx:
            repo.load_bundle(index, entry)
        self.assertIn("does not match the repo index", str(ctx.exception))

    def test_detects_a_missing_bundle_file(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        index = repo.load_index(self.index())
        os.remove(os.path.join(self.repo_dir, "a.morph"))
        with self.assertRaises(repo.RepoError) as ctx:
            repo.load_bundle(index, index["bundles"][0])
        self.assertIn("missing", str(ctx.exception))

    def test_detects_an_id_swap(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        index = repo.load_index(self.index())
        entry = dict(index["bundles"][0])
        entry["id"] = "org.repo.something-else"
        with self.assertRaises(repo.RepoError):
            repo.load_bundle(index, entry)


class TestMatching(RepoCase):
    def test_matching_by_hash_and_size(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        self.add_bundle("b", sample_app().replace(b"Trial expired.", b"Xrial expired."))
        index = repo.load_index(self.index())
        self.assertEqual(len(repo.matching(index, self.target)), 2)
        other = write(self.path("other.exe"),
                      build_pe([(".text", b"\x90" * 0x100, TEXT)]))
        self.assertEqual(repo.matching(index, other), [])

    def test_summary_counts_signatures_and_layout_ops(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        grown = self.path("grown.exe")
        write(grown, sample_app() + b"OVERLAY")
        bundle, _ = diffgen.build_bundle(self.target, grown, "org.repo.grow", "grow")
        bundle.save(os.path.join(self.repo_dir, "grow.morph"))
        index = repo.load_index(self.index())
        summary = repo.summarize(index, "")
        self.assertEqual(summary["bundles"], 2)
        self.assertEqual(summary["layout_changing"], 1)
        self.assertEqual(summary["signed"], 0)
        self.assertEqual(summary["trusted"], 0)


class TestApplyThroughRepo(RepoCase):
    def test_roundtrip_apply_and_revert(self):
        fixed = sample_app().replace(b"Version 1.0.0", b"Version 9.9.9")
        self.add_bundle("a", fixed)
        index = repo.load_index(self.index())
        entry = index["bundles"][0]
        bundle, path = repo.load_bundle(index, entry)
        self.assertEqual(path, os.path.join(self.repo_dir, "a.morph"))
        before = sha256_file(self.target)
        result = patcher.apply_bundle(bundle, self.target)
        self.assertNotEqual(result["sha256_after"], before)
        self.assertEqual(os.path.getsize(self.target), len(sample_app()))
        patcher.revert(self.target)
        self.assertEqual(sha256_file(self.target), before)

    def test_stale_index_blocks_apply(self):
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 9.9.9"))
        index = repo.load_index(self.index())
        # the repo moved on: bundle regenerated, index not refreshed
        self.add_bundle("a", sample_app().replace(b"Version 1.0.0", b"Version 8.8.8"))
        with self.assertRaises(repo.RepoError):
            repo.load_bundle(index, index["bundles"][0])


if __name__ == "__main__":
    unittest.main()
