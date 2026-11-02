#!/usr/bin/env python3
"""Convenience shim so the tool runs as `py surreal.py …` on Windows too.

Everything real lives in the ``surreal`` package; `python -m surreal` is the
canonical invocation.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from surreal.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
