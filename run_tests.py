#!/usr/bin/env python3
"""Run the whole test suite: ``python run_tests.py``.

``unittest discover`` needs the tests directory on ``sys.path`` (the tests
import ``helpers`` directly), which this runner arranges.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.join(ROOT, "tests")


def main() -> int:
    sys.path.insert(0, ROOT)
    sys.path.insert(0, TESTS)
    suite = unittest.defaultTestLoader.discover(TESTS, pattern="test_*.py",
                                                top_level_dir=TESTS)
    runner = unittest.TextTestRunner(verbosity=2 if "-v" in sys.argv else 1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
