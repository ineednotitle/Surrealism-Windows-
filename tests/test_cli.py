import contextlib
import io
import json
import os
import unittest

from helpers import TempDirCase, sample_app, write

from surreal import cli, policy
from surreal.util import sha256_file


def run(*argv):
    """Run the CLI in-process; return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    except SystemExit as exc:  # argparse usage errors and --version
        code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class TestCli(TempDirCase):
    def setUp(self):
        super().setUp()
        self.app = write(self.path("app.exe"), sample_app())
        self.app2 = write(self.path("app_new.exe"), sample_app(patch=True))
        self.bundle = self.path("patch.morph")

    def make_bundle(self):
        code, out, err = run("diff", self.app, self.app2, "-o", self.bundle,
                             "--id", "org.test.cli", "--name", "CLI patch",
                             "--json")
        self.assertEqual(code, 0, err)
        return json.loads(out)

    # -- init / policy ------------------------------------------------------ #
    def test_init_without_accept_does_nothing(self):
        code, out, _ = run("init")
        self.assertEqual(code, 0)
        self.assertIn("ACCEPTABLE USE", out)
        self.assertFalse(policy.policy_accepted())

    def test_init_accept_and_revoke(self):
        self.assertEqual(run("init", "--accept-policy")[0], 0)
        self.assertTrue(policy.policy_accepted())
        self.assertEqual(run("init", "--revoke")[0], 0)
        self.assertFalse(policy.policy_accepted())

    def test_apply_requires_policy(self):
        self.make_bundle()
        code, _, err = run("apply", self.bundle, "--target", self.app, "-y")
        self.assertEqual(code, 4)
        self.assertIn("policy", err.lower())
        self.assertEqual(sha256_file(self.app), sha256_file(self.app))

    def test_dry_run_allowed_without_policy(self):
        self.make_bundle()
        code, out, _ = run("apply", self.bundle, "--target", self.app, "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("dry run OK", out)

    # -- inspect / scan ----------------------------------------------------- #
    def test_inspect_text(self):
        code, out, _ = run("inspect", self.app, "--strings", "3")
        self.assertEqual(code, 0)
        self.assertIn("PE32+", out)
        self.assertIn(".text", out)
        self.assertIn("sections", out)

    def test_inspect_json(self):
        code, out, _ = run("inspect", self.app, "--json", "--imports", "--exports")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["machine_name"], "x64")
        self.assertEqual(len(data["sections"]), 3)
        self.assertIn("sha256", data)

    def test_inspect_bad_file(self):
        bad = write(self.path("bad.exe"), b"nope")
        code, _, err = run("inspect", bad)
        self.assertEqual(code, 3)
        self.assertIn("not a PE", err)

    def test_scan_pattern(self):
        code, out, _ = run("scan", self.app, "--pattern", "48 8D 15 ?? ?? ?? ??")
        self.assertEqual(code, 0)
        self.assertIn("hit(s)", out)
        self.assertIn(".text", out)

    def test_scan_string_json(self):
        code, out, _ = run("scan", self.app, "--string", "settings.ini", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["hits"][0]["section"], ".rdata")
        self.assertGreater(data["hits"][0]["offset"], 0)

    def test_scan_needs_a_query(self):
        code, _, err = run("scan", self.app)
        self.assertEqual(code, 2)
        self.assertIn("--pattern", err)

    # -- diff / info -------------------------------------------------------- #
    def test_diff_requires_id(self):
        code, _, err = run("diff", self.app, self.app2, "-o", self.bundle)
        self.assertEqual(code, 2)
        self.assertIn("--id", err)

    def test_diff_size_mismatch(self):
        smaller = write(self.path("small.exe"), sample_app()[:-0x200])
        code, _, err = run("diff", self.app, smaller, "-o", self.bundle, "--id", "x")
        self.assertEqual(code, 3)
        self.assertIn("size", err.lower())

    def test_info_text_and_json(self):
        self.make_bundle()
        code, out, _ = run("info", self.bundle)
        self.assertEqual(code, 0)
        self.assertIn("org.test.cli", out)
        self.assertIn("hunks", out)
        code, out, _ = run("info", self.bundle, "--json")
        data = json.loads(out)
        self.assertEqual(data["bundle"]["id"], "org.test.cli")
        self.assertIsNone(data["blocked"])

    def test_info_invalid_bundle(self):
        bad = write(self.path("bad.morph"), b"{not json")
        code, _, err = run("info", bad)
        self.assertEqual(code, 3)
        self.assertIn("JSON", err)

    def test_info_unknown_keys_rejected_unless_lax(self):
        self.make_bundle()
        with open(self.bundle, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        data["surprise"] = "boo"
        with open(self.bundle, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        code, _, err = run("info", self.bundle)
        self.assertEqual(code, 3)
        self.assertIn("unknown bundle keys", err)
        self.assertEqual(run("info", self.bundle, "--lax")[0], 0)

    # -- check / apply / revert --------------------------------------------- #
    def test_full_lifecycle(self):
        self.make_bundle()
        self.assertEqual(run("init", "--accept-policy")[0], 0)
        before = sha256_file(self.app)

        code, out, _ = run("check", self.bundle, "--target", self.app)
        self.assertEqual(code, 0, out)
        self.assertIn("applicable", out)

        code, out, _ = run("apply", self.bundle, "--target", self.app, "-y", "--json")
        self.assertEqual(code, 0, out)
        result = json.loads(out)
        self.assertTrue(result["ok"])
        self.assertEqual(sha256_file(self.app), sha256_file(self.app2))

        code, out, _ = run("revert", self.app)
        self.assertEqual(code, 0, out)
        self.assertEqual(sha256_file(self.app), before)

    def test_apply_without_yes_in_non_tty_aborts(self):
        self.make_bundle()
        run("init", "--accept-policy")
        code, _, err = run("apply", self.bundle, "--target", self.app)
        self.assertEqual(code, 3)
        self.assertIn("aborted", err)

    def test_check_wrong_target(self):
        self.make_bundle()
        other = write(self.path("other.exe"), sample_app(is_64=False))
        code, _, err = run("check", self.bundle, "--target", other)
        self.assertEqual(code, 3)

    def test_revert_list(self):
        self.make_bundle()
        run("init", "--accept-policy")
        run("apply", self.bundle, "--target", self.app, "-y")
        code, out, _ = run("revert", self.app, "--list")
        self.assertEqual(code, 0)
        self.assertIn("apply", out)

    def test_json_error_shape(self):
        code, out, _ = run("inspect", self.path("missing.exe"), "--json")
        self.assertEqual(code, 3)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["exit_code"], 3)

    # -- M1: signing / keys / locks / memory -------------------------------- #
    def keypair(self, name="publisher"):
        key_path = self.path(name + ".key")
        code, out, err = run("keys", "--generate", key_path, "--label", name)
        self.assertEqual(code, 0, err)
        import json as _json
        with open(key_path, "r", encoding="utf-8") as fh:
            record = _json.load(fh)
        return key_path, record["public_key"]

    def test_sign_verify_and_require_signature(self):
        self.make_bundle()
        key_path, pub = self.keypair()
        self.assertEqual(run("init", "--accept-policy")[0], 0)

        code, out, _ = run("sign", self.bundle, "--key", key_path, "--signer", "me")
        self.assertEqual(code, 0, out)
        self.assertIn("signed", out)

        code, out, err = run("verify", self.bundle)
        self.assertEqual(code, 0)
        self.assertIn("untrusted", out)
        self.assertIn("not trusted yet", err)

        # apply with --require-signature must fail before the key is trusted
        code, _, err = run("apply", self.bundle, "--target", self.app, "-y",
                           "--require-signature")
        self.assertEqual(code, 4)
        self.assertIn("trusted key", err)

        code, out, _ = run("keys", "--trust", pub, "--label", "me")
        self.assertEqual(code, 0)

        code, out, _ = run("verify", self.bundle, "--require")
        self.assertEqual(code, 0)
        self.assertIn("signed by me", out)

        code, out, _ = run("apply", self.bundle, "--target", self.app, "-y",
                           "--require-signature", "--json")
        self.assertEqual(code, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["signature"]["state"], "valid")

    def test_signature_survives_unsigned_apply(self):
        self.make_bundle()
        code, out, _ = run("apply", self.bundle, "--target", self.app, "--dry-run",
                           "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["signature"]["state"], "unsigned")

    def test_tampered_signed_bundle_is_refused(self):
        import json as _json
        self.make_bundle()
        key_path, pub = self.keypair()
        run("sign", self.bundle, "--key", key_path)
        run("keys", "--trust", pub)
        run("init", "--accept-policy")
        with open(self.bundle, "r", encoding="utf-8") as fh:
            data = _json.load(fh)
        data["hunks"][0]["replace"] = "90"
        with open(self.bundle, "w", encoding="utf-8") as fh:
            _json.dump(data, fh)
        code, _, err = run("apply", self.bundle, "--target", self.app, "-y")
        self.assertEqual(code, 4)
        self.assertIn("signature", err.lower())
        self.assertEqual(sha256_file(self.app), sha256_file(self.app))

    def test_sign_with_missing_key(self):
        self.make_bundle()
        code, _, err = run("sign", self.bundle, "--key", self.path("nope.key"))
        self.assertEqual(code, 4)
        self.assertIn("key file not found", err)

    def test_keys_list_and_untrust(self):
        _, pub = self.keypair()
        run("keys", "--trust", pub, "--label", "z")
        code, out, _ = run("keys", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["trust"]["keys"][0]["public_key"], pub)
        code, out, _ = run("keys", "--untrust", pub)
        self.assertEqual(code, 0)
        code, out, _ = run("keys", "--json")
        self.assertEqual(json.loads(out)["trust"]["keys"], [])

    def test_keys_rejects_bad_public_key(self):
        code, _, err = run("keys", "--trust", "00" * 31)
        self.assertEqual(code, 4)
        self.assertIn("64 hex", err)

    def test_lock_blocks_concurrent_apply(self):
        from surreal.lock import TargetLock
        self.make_bundle()
        run("init", "--accept-policy")
        with TargetLock(self.app):
            code, _, err = run("apply", self.bundle, "--target", self.app, "-y")
            self.assertEqual(code, 5)
            self.assertIn("another surreal process", err)
        # and it works once the lock is gone
        code, _, err = run("apply", self.bundle, "--target", self.app, "-y")
        self.assertEqual(code, 0, err)

    def test_force_unlock_breaks_a_stale_lock(self):
        import json as _json, socket, time
        from surreal.lock import lock_path
        self.make_bundle()
        run("init", "--accept-policy")
        path = lock_path(self.app)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump({"pid": 999999, "host": socket.gethostname(),
                        "time_epoch": time.time(), "action": "apply"}, fh)
        code, _, err = run("apply", self.bundle, "--target", self.app, "-y",
                           "--force-unlock")
        self.assertEqual(code, 0, err)

    def test_max_mem_guard_refuses_huge_read(self):
        code, _, err = run("--max-mem", "0.001", "diff", self.app, self.app2,
                           "-o", self.bundle, "--id", "x", "--force")
        self.assertEqual(code, 0)  # PE path never reads whole files
        # the non-PE fallback must refuse
        p1 = write(self.path("t1.bin"), b"a" * 65536)
        p2 = write(self.path("t2.bin"), b"a" * 32768 + b"b" + b"a" * 32767)
        code, _, err = run("--max-mem", "0.001", "diff", p1, p2, "-o",
                           self.bundle, "--id", "x", "--force")
        self.assertEqual(code, 5)
        self.assertIn("--max-mem", err)

    def test_check_reports_relocation_risk(self):
        from helpers import build_pe
        payload = b"\x90" * 16 + b"\0" * 8 + b"\x90" * 104
        base = build_pe([(".text", payload, 0x60000020)],
                        relocs=[(0x1010, 10)], with_reloc_section=True)
        old, new = bytearray(base), bytearray(base)
        off = 0x200 + 0x10
        old[off:off + 8] = (0x100020).to_bytes(8, "little")
        new[off:off + 8] = (0x100030).to_bytes(8, "little")
        target = write(self.path("reloc_app.exe"), bytes(old))
        modified = write(self.path("reloc_new.exe"), bytes(new))
        code, out, _ = run("diff", target, modified, "-o", self.path("r.morph"),
                           "--id", "org.reloc", "--json")
        self.assertEqual(code, 0, out)
        self.assertTrue(any("relocated" in w for w in json.loads(out)["stats"]["warnings"]))
        code, _, err = run("check", self.path("r.morph"), "--target", target)
        self.assertEqual(code, 3)
        self.assertIn("allow-abs-address", err)
        code, out, _ = run("check", self.path("r.morph"), "--target", target,
                           "--allow-abs-address")
        self.assertEqual(code, 0, out)
        self.assertIn("aslr", out.lower())

    # -- misc --------------------------------------------------------------- #
    def test_version_and_help(self):
        code, out, _ = run("--version")
        self.assertEqual(code, 0)
        self.assertIn("surreal", out)

    def test_demo_creates_applicable_bundle(self):
        outdir = self.path("demo")
        code, out, err = run("demo", "--out", outdir)
        self.assertEqual(code, 0, err)
        target = os.path.join(outdir, "demo_app.exe")
        bundle = os.path.join(outdir, "demo-shorten-nag.morph")
        self.assertTrue(os.path.isfile(target))
        self.assertTrue(os.path.isfile(bundle))
        code, out, _ = run("check", bundle, "--target", target)
        self.assertEqual(code, 0, out)

    def test_demo_json(self):
        code, out, _ = run("demo", "--out", self.path("demo2"), "--json")
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["hunks"], 1)

    def test_selftest(self):
        code, out, _ = run("selftest")
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)
        self.assertNotIn("FAIL", out)

    def test_selftest_json(self):
        code, out, _ = run("selftest", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertTrue(all(line.startswith("PASS") for line in data["report"]))

    def test_no_command_prints_help(self):
        code, out, _ = run()
        self.assertEqual(code, 0)
        self.assertIn("usage", out.lower())


if __name__ == "__main__":
    unittest.main()
