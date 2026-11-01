"""The end-to-end smoke script that CI runs must pass on this machine too."""

import contextlib
import importlib.util
import io
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "ci_smoke.py")


class TestCiSmoke(unittest.TestCase):
    def test_all_scenarios_pass(self):
        spec = importlib.util.spec_from_file_location("ci_smoke", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = module.main()
        output = out.getvalue()
        self.assertEqual(code, 0, output)
        self.assertIn("scenario(s) passed", output)
        self.assertNotIn("FAIL", output)


if __name__ == "__main__":
    unittest.main()
