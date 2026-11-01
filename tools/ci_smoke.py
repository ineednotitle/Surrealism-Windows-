#!/usr/bin/env python3
"""Run every end-to-end smoke scenario in one process, on generated fixtures.

    python tools/ci_smoke.py

Each scenario drives the real CLI (``surreal.cli.main``) the way a user would:
demo → inspect → diff → check → sign → verify → apply → revert, then the overlay,
header-surgery, vault and repo paths. Everything happens in a temp directory, so
nothing outside it is touched and no third-party binary is involved.

Prints ``PASS``/``FAIL`` lines (ASCII only, so a cp437 console is fine) and exits
non-zero if any scenario failed — which is exactly what CI needs to see.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from surreal import cli  # noqa: E402
from surreal.util import sha256_file  # noqa: E402

results = []


def run(*argv, expect=0):
    """Run the CLI in-process and require an exit code."""
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([str(a) for a in argv])
    except SystemExit as exc:  # argparse
        code = int(exc.code or 0)
    if expect is not None and code != expect:
        raise AssertionError("`surreal %s` exited %d (expected %d)\n%s%s"
                             % (" ".join(str(a) for a in argv), code, expect,
                                out.getvalue()[-1500:], err.getvalue()[-1500:]))
    return code, out.getvalue(), err.getvalue()


def scenario(name):
    def wrap(fn):
        try:
            detail = fn() or ""
            results.append((name, True, detail))
            print("PASS  %-38s %s" % (name, detail))
        except Exception as exc:  # noqa: BLE001 - the point is to report, not throw
            results.append((name, False, str(exc)))
            print("FAIL  %-38s %s: %s" % (name, type(exc).__name__, exc))
            for line in traceback.format_exc().strip().splitlines()[-8:]:
                print("      " + line)
        return fn
    return wrap


def main() -> int:
    work = tempfile.mkdtemp(prefix="surreal-smoke-")
    demo = os.path.join(work, "demo")
    patches = os.path.join(work, "patches")
    appdir = os.path.join(work, "app")
    os.makedirs(patches, exist_ok=True)
    os.makedirs(appdir, exist_ok=True)
    os.environ.setdefault("XDG_CONFIG_HOME", os.path.join(work, "config"))
    os.environ.setdefault("APPDATA", os.environ["XDG_CONFIG_HOME"])

    state = {}

    @scenario("init + demo")
    def _demo():
        run("init", "--accept-policy")
        code, out, err = run("demo", "--out", demo, "--json")
        info = json.loads(out)
        state["app"] = os.path.join(demo, "demo_app.exe")
        state["bundle"] = os.path.join(demo, "demo-shorten-nag.morph")
        if not os.path.isfile(state["app"]):
            raise AssertionError("demo did not write demo_app.exe: %s" % err)
        return "%d hunk(s) in the demo bundle" % info["hunks"]

    @scenario("inspect --json")
    def _inspect():
        _, out, _ = run("inspect", state["app"], "--json")
        data = json.loads(out)
        if data.get("machine_name") is None:
            raise AssertionError("inspect --json lost machine_name")
        return "%s, %d section(s)" % (data["machine_name"],
                                      len(data["sections"]))

    @scenario("diff + check + info")
    def _diff():
        with open(state["app"], "rb") as fh:
            data = bytearray(fh.read())
        # flip one byte inside the first section's raw data
        data[0x240] ^= 0xFF
        edited = os.path.join(work, "edited.exe")
        with open(edited, "wb") as fh:
            fh.write(bytes(data))
        bundle = os.path.join(patches, "one.morph")
        _, out, _ = run("diff", state["app"], edited, "-o", bundle,
                        "--id", "org.smoke.one", "--json")
        if len(json.loads(out)["bundle"]["hunks"]) != 1:
            raise AssertionError("expected a single hunk")
        run("check", bundle, "--target", state["app"])
        _, info, _ = run("info", bundle, "--json")
        if json.loads(info)["bundle"]["id"] != "org.smoke.one":
            raise AssertionError("info lost the bundle id")
        state["one"] = bundle
        return "1-hunk bundle generated, checked and described"

    @scenario("sign + verify")
    def _sign():
        key = os.path.join(work, "ci.key")
        run("keys", "--generate", key, "--label", "ci")
        signed = os.path.join(patches, "signed.morph")
        shutil.copyfile(state["bundle"], signed)
        run("sign", signed, "--key", key, "--signer", "ci")
        with open(key, encoding="utf-8") as fh:
            public = json.load(fh)["public_key"]
        _, out, _ = run("verify", signed, "--require", "--trusted-key", public,
                        "--json")
        if json.loads(out)["state"] != "valid":
            raise AssertionError("signature did not verify")
        state["signed"] = signed
        return "ed25519 bundle signing works"

    @scenario("check + apply + revert")
    def _apply():
        before = sha256_file(state["app"])
        run("check", state["signed"], "--target", state["app"],
            "--require-signature", "--trusted-key",
            json.loads(open(os.path.join(work, "ci.key"), encoding="utf-8").read())
            ["public_key"])
        run("apply", state["signed"], "--target", state["app"], "-y")
        if sha256_file(state["app"]) == before:
            raise AssertionError("apply did not change the file")
        run("revert", state["app"])
        if sha256_file(state["app"]) != before:
            raise AssertionError("revert did not restore the original")
        return "signed apply then revert restored the build"

    @scenario("overlay size change")
    def _overlay():
        grown = os.path.join(patches, "grown.exe")
        with open(state["app"], "rb") as fh:
            base = fh.read()
        with open(grown, "wb") as fh:
            fh.write(base + b"\r\n[ci] overlay\r\n")
        bundle = os.path.join(patches, "overlay.morph")
        run("diff", state["app"], grown, "-o", bundle, "--id", "org.smoke.overlay")
        run("apply", bundle, "--target", state["app"], "-y")
        size = os.path.getsize(state["app"])
        run("revert", state["app"])
        return "grew to %d bytes, then reverted" % size

    @scenario("header surgery (extend-section)")
    def _surgery():
        from surreal import surgery
        from surreal.pe import PE

        grown = os.path.join(work, "grown_section.exe")
        shutil.copyfile(state["app"], grown)
        pe = PE.open(grown)
        try:
            plan = surgery.plan_extend_section(pe, pe.sections[-1].name,
                                               b"[ci] grown in place")
        finally:
            pe.close()
        with open(grown, "r+b") as fh:
            for offset, blob in plan.writes:
                fh.seek(offset)
                fh.write(blob)
            fh.seek(0, os.SEEK_END)
            fh.write(plan.payload)
        with PE.open(grown) as after:
            checksum, skip = after.compute_checksum(), after._checksum_offset
        with open(grown, "r+b") as fh:
            fh.seek(skip)
            fh.write(checksum.to_bytes(4, "little"))

        bundle = os.path.join(patches, "surgery.morph")
        _, out, _ = run("diff", state["app"], grown, "-o", bundle,
                        "--id", "org.smoke.surgery", "--json")
        hunks = json.loads(out)["bundle"]["hunks"]
        if len(hunks) != 1:
            raise AssertionError("expected one surgery hunk, got %d" % len(hunks))
        if hunks[0].get("op") != "extend-section":
            raise AssertionError("expected op extend-section, got %r"
                                 % hunks[0].get("op"))
        before = sha256_file(state["app"])
        run("apply", bundle, "--target", state["app"], "-y")
        if sha256_file(state["app"]) != sha256_file(grown):
            raise AssertionError("surgery did not reproduce the reference build")
        run("revert", state["app"])
        if sha256_file(state["app"]) != before:
            raise AssertionError("surgery revert did not restore the build")
        return "extend-section reproduced the reference build byte-for-byte"

    @scenario("collection (single target)")
    def _collection():
        shutil.copyfile(state["bundle"], os.path.join(patches, "main.morph"))
        with open(os.path.join(patches, "surreal-collection.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"format": "surreal.collection", "format_version": 1,
                       "name": "ci set",
                       "patches": [{"bundle": "main.morph", "order": 10}]}, fh)
        run("collection", "check", patches, "--target", state["app"])
        run("collection", "apply", patches, "--target", state["app"], "-y")
        run("revert", state["app"])
        return "one patch applied as a transaction and reverted"

    @scenario("vault (multi-file)")
    def _vault():
        vaultdir = os.path.join(work, "vault")
        os.makedirs(vaultdir, exist_ok=True)
        main_exe = os.path.join(appdir, "main.exe")
        shutil.copyfile(state["app"], main_exe)

        from surreal.testkit import build_pe
        helper = build_pe([(".text", b"\x90" * 0x100, 0x60000020),
                           (".rdata", b"helper-strings\0" * 8, 0x40000040)])
        helper_path = os.path.join(appdir, "helper.dll")
        with open(helper_path, "wb") as fh:
            fh.write(helper)

        # bundle for main.exe: reuse the demo patch, retargeted by hand
        shutil.copyfile(state["signed"], os.path.join(vaultdir, "main.morph"))
        # bundle for helper.dll: blank one string
        fixed = bytearray(helper)
        at = bytes(fixed).find(b"helper-strings")
        fixed[at:at + 14] = b"VAULT-STRINGS!"
        fixed_path = os.path.join(work, "helper_fixed.dll")
        with open(fixed_path, "wb") as fh:
            fh.write(bytes(fixed))
        run("diff", helper_path, fixed_path, "-o",
            os.path.join(vaultdir, "helper.morph"), "--id", "org.ci.vault-helper")
        with open(os.path.join(vaultdir, "surreal-collection.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"format": "surreal.collection", "format_version": 1,
                       "name": "ci vault",
                       "patches": [
                           {"bundle": "main.morph", "target": "main.exe",
                            "order": 10},
                           {"bundle": "helper.morph", "target": "helper.dll",
                            "order": 20}]}, fh)
        run("collection", "list", vaultdir)
        run("collection", "check", vaultdir, "--target", appdir)
        run("collection", "apply", vaultdir, "--target", appdir, "-y")
        run("revert", main_exe)
        run("revert", helper_path)
        return "2 files patched in one transaction, both reverted"

    @scenario("local repo")
    def _repo():
        index = os.path.join(patches, "surreal-repo.json")
        run("repo", "index", patches, "-o", index, "--name", "ci repo",
            "--created", "2026-11-01T00:00:00Z")
        run("repo", "list", index, "--target", state["app"])
        run("repo", "apply", index, "--id", "org.surreal.demo.shorten-nag",
            "--target", state["app"], "-y")
        run("revert", state["app"])
        return "indexed, resolved by id, applied and reverted"

    @scenario("tui (piped answers)")
    def _tui():
        import builtins

        answers = iter(["1", "n", "q"])
        real_input = builtins.input
        builtins.input = lambda *a: next(answers)
        try:
            code, _out, _err = run("tui", "--target", state["app"], "--dir",
                                   patches)
        finally:
            builtins.input = real_input
        if code != 0:
            raise AssertionError("tui exited %d" % code)
        return "menu handled piped answers"

    passed = sum(1 for _n, ok, _d in results if ok)
    print("\n%d/%d scenario(s) passed" % (passed, len(results)))
    shutil.rmtree(work, ignore_errors=True)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
