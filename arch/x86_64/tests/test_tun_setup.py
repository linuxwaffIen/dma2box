"""Тесты авто-подготовки TUN (dma2box/tun_setup.py).

Все тяжёлые операции (pkexec, скачивание) подменяются моками: проверяется
матрица readiness, сборка команды установки и оркестрация ensure_ready.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dma2box import tun_setup
from dma2box.state import Store

CORE_BYTES = b"#!/bin/sh\n# fake sing-box\n" * 8
PRIV_BYTES = b"# fake privileged.py\n"


class TunSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="tun-setup-"))
        self.addCleanup(self._cleanup)
        self.store = Store(self.tmp / "state.json")

        # Пользовательское ядро, «настроенное» вручную (как в UI).
        self.user_core = self.tmp / "my-sing-box"
        self.user_core.write_bytes(CORE_BYTES)
        os.chmod(self.user_core, 0o700)
        self.store.set_setting("core_path", str(self.user_core))

        # Системные компоненты по умолчанию отсутствуют.
        self.system_helper = self.tmp / "dma2box-helper"
        self.system_core = self.tmp / "system-sing-box"

        self.priv = self.tmp / "privileged.py"
        self.priv.write_bytes(PRIV_BYTES)
        self.setup_script = self.tmp / "priv_setup.py"
        self.setup_script.write_bytes(b"# fake priv_setup\n")

        # Детерминизм окружения: pkexec есть, sing-box — нет.
        # Имя-aware mock: глобальная замена shutil.which не должна
        # подсунуть find_core фантомное ядро (как pkexec).
        patch_which = mock.patch(
            "dma2box.tun_setup.shutil.which",
            side_effect=lambda name: "/usr/bin/pkexec" if name == "pkexec" else None,
        )
        patch_which.start()
        self.addCleanup(patch_which.stop)
        patch_device = mock.patch(
            "dma2box.tun_setup._tun_device_available", return_value=True
        )
        patch_device.start()
        self.addCleanup(patch_device.stop)
        # find_core ищет dmacore в bin/<arch>; в тестовой песочнице там пусто.
        patch_arch_dir = mock.patch(
            "dma2box.core.paths.core_arch_dir", return_value=self.tmp
        )
        patch_arch_dir.start()
        self.addCleanup(patch_arch_dir.stop)
        patch_user_core_path = mock.patch(
            "dma2box.paths.CORE_PATH", self.tmp / "no-default-core"
        )
        patch_user_core_path.start()
        self.addCleanup(patch_user_core_path.stop)

    def _cleanup(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _patch_system(self) -> dict:
        """Все системные компоненты на месте и синхронизированы."""
        self.system_helper.write_bytes(b"helper\n")
        self.system_core.write_bytes(CORE_BYTES)
        os.chmod(self.system_core, 0o700)
        return {
            "helper": mock.patch.object(tun_setup, "SYSTEM_HELPER", self.system_helper),
            "core": mock.patch.object(tun_setup, "SYSTEM_CORE", self.system_core),
        }

    # ------------------------------------------------------------- readiness
    def test_all_ready(self) -> None:
        patches = self._patch_system()
        with patches["helper"], patches["core"]:
            checks = tun_setup.readiness(self.store)
            self.assertTrue(all(check.ok for check in checks))
            # needs_setup тоже внутри патч-контекста: снаружи tun_setup грустит
            # на реальные /usr/libexec пути этой машины.
            self.assertFalse(tun_setup.needs_setup(self.store))
        self.assertEqual(tun_setup.problems(checks), "")

    def test_missing_system_component(self) -> None:
        patches = self._patch_system()
        with patches["helper"], patches["core"]:
            self.system_helper.unlink()
            checks = tun_setup.readiness(self.store)
        failed = {check.key for check in checks if not check.ok}
        self.assertIn("system", failed)
        self.assertTrue(all(check.fix for check in checks if not check.ok))

    def test_stale_system_core(self) -> None:
        patches = self._patch_system()
        with patches["helper"], patches["core"]:
            self.system_core.write_bytes(b"#!/bin/sh\n# older sing-box\n" * 8)
            os.chmod(self.system_core, 0o700)
            checks = tun_setup.readiness(self.store)
        failed = {check.key for check in checks if not check.ok}
        self.assertEqual(failed, {"core-sync"})

    def test_manual_gaps_not_autofixed(self) -> None:
        patches = self._patch_system()
        with patches["helper"], patches["core"], mock.patch(
            "dma2box.tun_setup.shutil.which", return_value=None
        ):
            checks = tun_setup.readiness(self.store)
        polkit = next(check for check in checks if check.key == "polkit")
        self.assertFalse(polkit.ok)
        self.assertFalse(polkit.fix)

    def test_same_file_memo_keeps_answer(self) -> None:
        first = tun_setup._same_file(self.user_core, self.system_core)
        self.assertFalse(first)  # содержимое пока разное
        self.system_core.write_bytes(CORE_BYTES)
        os.chmod(self.system_core, 0o700)
        again = tun_setup._same_file(self.user_core, self.system_core)
        self.assertTrue(again)

    # ---------------------------------------------------------- setup_command
    def test_setup_command_with_pkexec(self) -> None:
        with mock.patch("dma2box.paths.PRIV_SETUP_SCRIPT", self.setup_script):
            command = tun_setup.setup_command(self.user_core, self.priv, "/usr/bin/python3")
        self.assertEqual(command[0], "/usr/bin/pkexec")
        self.assertEqual(command[1:3], ["/usr/bin/python3", str(self.setup_script)])
        self.assertIn("--core", command)
        self.assertIn(str(self.user_core), command)

    def test_setup_command_root_run(self) -> None:
        with (
            mock.patch("dma2box.paths.PRIV_SETUP_SCRIPT", self.setup_script),
            mock.patch("os.geteuid", return_value=0),
        ):
            command = tun_setup.setup_command(self.user_core, self.priv, "/usr/bin/python3")
        self.assertEqual(command[0], "/usr/bin/python3")

    def test_setup_command_requires_script(self) -> None:
        with (
            mock.patch("dma2box.paths.PRIV_SETUP_SCRIPT", self.tmp / "missing.py"),
            self.assertRaises(tun_setup.TunSetupError),
        ):
            tun_setup.setup_command(self.user_core, self.priv, "/usr/bin/python3")

    # ------------------------------------------------------------ ensure_ready
    def test_ensure_ready_noop_when_ready(self) -> None:
        """Всё на месте: скачивание и установка не вызываются."""
        patches = self._patch_system()
        with (
            patches["helper"],
            patches["core"],
            mock.patch.object(tun_setup.installer, "install_core") as download,
            mock.patch.object(tun_setup, "run_setup") as runner,
        ):
            remaining = tun_setup.ensure_ready(self.store, ask_password=None)
        runner.assert_not_called()
        download.assert_not_called()
        self.assertEqual(remaining, [])

    def test_ensure_ready_installs_system(self) -> None:
        patches = self._patch_system()

        def fake_run_setup(command, **_kwargs) -> tuple[int, str]:
            # Мок имитирует # реальный priv_setup: создаёт компоненты,
            # чтобы финальный readiness увидел их на месте.
            self.system_helper.write_bytes(b"helper\n")
            self.system_core.write_bytes(self.user_core.read_bytes())
            os.chmod(self.system_core, 0o700)
            return 0, "ок"

        with (
            patches["helper"],
            patches["core"],
            mock.patch.object(tun_setup, "run_setup", side_effect=fake_run_setup) as runner,
            mock.patch.object(tun_setup.installer, "install_core") as download,
            mock.patch("dma2box.paths.PRIV_SETUP_SCRIPT", self.setup_script),
            mock.patch("dma2box.paths.PRIV_SCRIPT", self.priv),
        ):
            self.system_helper.unlink()  # компонент не установлен
            remaining = tun_setup.ensure_ready(self.store, ask_password=None)
        download.assert_not_called()
        runner.assert_called_once()
        command = runner.call_args[0][0]
        self.assertEqual(command[0], "/usr/bin/pkexec")
        self.assertIn(str(self.user_core), command)
        self.assertEqual(remaining, [])

    def test_ensure_ready_reports_install_failure(self) -> None:
        patches = self._patch_system()
        with (
            patches["helper"],
            patches["core"],
            mock.patch.object(tun_setup, "run_setup", return_value=(1, "boom")) as runner,
            mock.patch("dma2box.paths.PRIV_SETUP_SCRIPT", self.setup_script),
            mock.patch("dma2box.paths.PRIV_SCRIPT", self.priv),
            self.assertRaises(tun_setup.TunSetupError) as ctx,
        ):
            self.system_helper.unlink()
            tun_setup.ensure_ready(self.store, ask_password=None)
        runner.assert_called_once()
        self.assertIn("boom", str(ctx.exception))

    def test_ensure_ready_downloads_core_first(self) -> None:
        patches = self._patch_system()
        # Пользовательское ядро отсутствует — нужен и download, и install.
        self.store.set_setting("core_path", str(self.tmp / "no-core"))
        fresh_core = self.tmp / "downloaded-sing-box"

        def fake_download(*_args, **_kwargs) -> Path:
            fresh_core.write_bytes(CORE_BYTES)
            os.chmod(fresh_core, 0o700)
            self.store.set_setting("core_path", str(fresh_core))
            return fresh_core

        with (
            patches["helper"],
            patches["core"],
            mock.patch.object(
                tun_setup.installer, "install_core", side_effect=fake_download
            ) as download,
            mock.patch("dma2box.paths.PRIV_SETUP_SCRIPT", self.setup_script),
            mock.patch("dma2box.paths.PRIV_SCRIPT", self.priv),
        ):
            tun_setup.ensure_ready(self.store, ask_password=None)
            checks = tun_setup.readiness(self.store)
            all_ok = all(check.ok for check in checks)
        download.assert_called_once()
        self.assertTrue(all_ok)
        self.assertIn("system", {check.key for check in checks})

    def test_ensure_ready_skips_manual_gaps(self) -> None:
        patches = self._patch_system()
        self.system_helper.unlink()
        with (
            patches["helper"],
            patches["core"],
            mock.patch("dma2box.tun_setup.shutil.which", return_value=None),
        ):
            remaining = tun_setup.ensure_ready(self.store, ask_password=None)
        # polkit отсутствует — ручной пункт, ничего не запускаем.
        self.assertTrue(any(not check.ok and not check.fix for check in remaining))
        self.assertIn("polkit", {check.key for check in remaining if not check.ok})


if __name__ == "__main__":
    unittest.main()
