"""Lock file semantics: mutual exclusion, staleness, crash recovery."""

import json
import os
import socket
import time
import unittest

from helpers import TempDirCase, sample_app, write

from surreal.lock import LockError, TargetLock, lock_path


class TestLock(TempDirCase):
    def setUp(self):
        super().setUp()
        self.target = write(self.path("app.exe"), sample_app())

    def test_acquire_and_release(self):
        with TargetLock(self.target) as lock:
            self.assertTrue(lock.acquired)
            self.assertTrue(os.path.isfile(lock_path(self.target)))
            with open(lock_path(self.target), encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["pid"], os.getpid())
            self.assertEqual(data["action"], "apply")
        self.assertFalse(os.path.exists(lock_path(self.target)))

    def test_second_holder_is_refused(self):
        outer = TargetLock(self.target).acquire()
        try:
            with self.assertRaises(LockError) as ctx:
                TargetLock(self.target).acquire()
            self.assertIn("another surreal process", str(ctx.exception))
        finally:
            outer.release()

    def test_force_breaks_a_live_lock(self):
        outer = TargetLock(self.target).acquire()
        try:
            forced = TargetLock(self.target, force=True).acquire()
            forced.release()
        finally:
            outer.acquired = False

    def test_stale_pid_is_reclaimed(self):
        os.makedirs(os.path.dirname(lock_path(self.target)), exist_ok=True)
        with open(lock_path(self.target), "w", encoding="utf-8") as fh:
            json.dump({"pid": 999999, "host": os.environ.get("COMPUTERNAME")
                       or socket.gethostname(), "time_epoch": time.time(),
                       "action": "apply"}, fh)
        lock = TargetLock(self.target).acquire()
        lock.release()

    def test_old_lock_is_reclaimed(self):
        os.makedirs(os.path.dirname(lock_path(self.target)), exist_ok=True)
        with open(lock_path(self.target), "w", encoding="utf-8") as fh:
            json.dump({"pid": os.getpid(),
                       "host": os.environ.get("COMPUTERNAME") or socket.gethostname(),
                       "time_epoch": time.time() - 3600, "action": "apply"}, fh)
        lock = TargetLock(self.target).acquire()
        lock.release()

    def test_foreign_host_lock_is_reclaimed(self):
        os.makedirs(os.path.dirname(lock_path(self.target)), exist_ok=True)
        with open(lock_path(self.target), "w", encoding="utf-8") as fh:
            json.dump({"pid": os.getpid(), "host": "some-other-machine",
                       "time_epoch": time.time(), "action": "apply"}, fh)
        lock = TargetLock(self.target).acquire()
        lock.release()

    def test_corrupt_lock_file_is_reclaimed(self):
        os.makedirs(os.path.dirname(lock_path(self.target)), exist_ok=True)
        with open(lock_path(self.target), "w", encoding="utf-8") as fh:
            fh.write("not json")
        lock = TargetLock(self.target).acquire()
        lock.release()

    def test_release_does_not_steal_others_lock(self):
        os.makedirs(os.path.dirname(lock_path(self.target)), exist_ok=True)
        with open(lock_path(self.target), "w", encoding="utf-8") as fh:
            json.dump({"pid": os.getpid() + 4242, "host": "h",
                       "time_epoch": time.time()}, fh)
        lock = TargetLock(self.target)
        lock.acquired = True
        lock.release()
        self.assertTrue(os.path.exists(lock_path(self.target)))


if __name__ == "__main__":
    unittest.main()
