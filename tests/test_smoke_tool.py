"""The user-facing smoke test (tools/smoke_real_binary.py) on a fixture PE."""

import contextlib
import importlib.util
import io
import os
import unittest

from helpers import TempDirCase, write
from test_surgery import two_section_pe

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "smoke_real_binary.py")


def load_tool():
    spec = importlib.util.spec_from_file_location("smoke_real_binary", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestSmokeTool(TempDirCase):
    def run_tool(self, path):
        module = load_tool()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = module.main(["smoke", path])
        return code, out.getvalue()

    def test_passes_on_a_fixture_and_leaves_the_file_untouched(self):
        target = write(self.path("app.exe"), two_section_pe())
        before = open(target, "rb").read()
        code, output = self.run_tool(target)
        self.assertEqual(code, 0, output)
        self.assertIn("step(s) passed", output)
        self.assertNotIn(" FAIL ", output)
        self.assertEqual(open(target, "rb").read(), before)

    def test_reports_failures_without_raising(self):
        broken = write(self.path("broken.exe"), b"MZ" + b"\0" * 200)
        code, output = self.run_tool(broken)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", output)

    def test_usage_and_missing_file(self):
        module = load_tool()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(["smoke"]), 2)
            self.assertEqual(module.main(["smoke", self.path("nope.exe")]), 2)


if __name__ == "__main__":
    unittest.main()
