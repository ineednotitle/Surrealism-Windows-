"""Shared test helpers."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from surreal.testkit import build_pe, sample_app  # noqa: E402

__all__ = ["TempDirCase", "build_pe", "sample_app", "write"]


def write(path: str, data: bytes) -> str:
    with open(path, "wb") as fh:
        fh.write(data)
    return path


class TempDirCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        # isolate the policy/config dir from the developer's real one
        self._old_cfg = os.environ.get("XDG_CONFIG_HOME")
        self._old_appdata = os.environ.get("APPDATA")
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.tmp, "config")
        os.environ["APPDATA"] = os.path.join(self.tmp, "config")

    def tearDown(self) -> None:
        self._tmp.cleanup()
        for key, old in (("XDG_CONFIG_HOME", self._old_cfg), ("APPDATA", self._old_appdata)):
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old

    def path(self, name: str) -> str:
        return os.path.join(self.tmp, name)
