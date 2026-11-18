from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from dma2box.core import CoreError, CoreManager, CoreStatus, find_core

URI = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws#test"


def _wait_for(predicate, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


class CoreStatusTests(unittest.TestCase):
    """Неудачный запуск должен сообщать «error», а не «stopped»."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from dma2box.state import Store

        self.store = Store(Path(self.tmp.name) / "state.json")
        self.statuses: list[CoreStatus] = []

    def _manager(self) -> CoreManager:
        return CoreManager(self.store, self.statuses.append)

    def test_non_executable_core_reports_error(self) -> None:
        fake = Path(self.tmp.name) / "sing-box"
        fake.write_text("#!/bin/sh\nexit 1\n")
        fake.chmod(0o600)
        self.store.set_setting("core_path", str(fake))
        manager = self._manager()
        profile = self.store.add_profile("Test", URI)

        manager.start(profile, tun=False)
        self.assertTrue(_wait_for(lambda: manager.status.state == "error"))
        self.assertIn("не исполняемый", manager.status.error or "")
        states = [status.state for status in self.statuses]
        self.assertIn("starting", states)
        self.assertNotIn("stopped", states)

    def test_missing_core_reports_error(self) -> None:
        self.store.set_setting("core_path", str(Path(self.tmp.name) / "no-such-core"))
        manager = self._manager()
        profile = self.store.add_profile("Test", URI)

        with mock.patch("dma2box.paths.CORE_PATH", Path(self.tmp.name) / "none-1"), \
                mock.patch("dma2box.core.shutil.which", return_value=None):
            manager.start(profile, tun=False)
            self.assertTrue(_wait_for(lambda: manager.status.state == "error"))
        self.assertIn("не найден", manager.status.error or "")

    def test_downloaded_core_is_used_when_nothing_else(self) -> None:
        downloaded = Path(self.tmp.name) / "downloaded-sing-box"
        downloaded.write_text("#!/bin/sh\n")
        downloaded.chmod(0o755)
        self.store.set_setting("core_path", "")
        with mock.patch("dma2box.paths.CORE_PATH", downloaded), \
                mock.patch("dma2box.core.shutil.which", return_value=None):
            self.assertEqual(find_core(self.store), downloaded)

    def test_stop_after_failed_start_reports_stopped(self) -> None:
        fake = Path(self.tmp.name) / "sing-box"
        fake.write_text("x")
        fake.chmod(0o600)
        self.store.set_setting("core_path", str(fake))
        manager = self._manager()
        profile = self.store.add_profile("Test", URI)

        manager.start(profile, tun=False)
        self.assertTrue(_wait_for(lambda: manager.status.state == "error"))
        manager.stop()
        self.assertTrue(_wait_for(lambda: manager.status.state == "stopped"))

    def test_shutdown_reports_stopped(self) -> None:
        manager = self._manager()
        manager.shutdown()
        self.assertEqual(manager.status.state, "stopped")

    def test_validate_uses_singbox_check(self) -> None:
        core = Path("/usr/bin/sing-box")
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("dma2box.core.subprocess.run", return_value=completed) as run:
            CoreManager._validate(core)
        args = run.call_args.args[0]
        self.assertEqual(args[0], str(core))
        self.assertEqual(args[1], "check")

        completed.returncode = 1
        completed.stderr = "bad config"
        with mock.patch("dma2box.core.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(CoreError, "bad config"):
                CoreManager._validate(core)


if __name__ == "__main__":
    unittest.main()
