"""Тесты root-установщика компонентов TUN (dma2box/priv_setup.py).

Все проверки выполняются над каталогами во временной папке — от root
зависит только main(); функции установки принимают пути параметрами.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from dma2box import priv_setup


class PrivSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="priv-setup-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.libexec = self.tmp / "libexec" / "dma2box"
        self.policy = self.tmp / "polkit" / "org.dma2box.run-core.policy"
        self.core = self.tmp / "sing-box-user"
        self.core.write_bytes(b"#!/bin/sh\n# fake sing-box v1\n" * 16)
        os.chmod(self.core, 0o700)
        self.priv = self.tmp / "privileged.py"
        self.priv.write_bytes(b"# fake privileged helper\n")

    def _install(self) -> dict:
        return priv_setup.install_components(
            self.core,
            self.priv,
            libexec_dir=self.libexec,
            policy_path=self.policy,
            python_bin="/usr/bin/python3",
        )

    def test_install_creates_all_components(self) -> None:
        summary = self._install()
        installed_core = self.libexec / priv_setup.CORE_NAME
        self.assertTrue(installed_core.is_file())
        self.assertEqual(installed_core.read_bytes(), self.core.read_bytes())
        self.assertEqual(
            stat.S_IMODE(installed_core.stat().st_mode) & 0o111, 0o111
        )
        helper = self.libexec / priv_setup.HELPER_NAME
        self.assertTrue(helper.is_file())
        helper_text = helper.read_text(encoding="utf-8")
        self.assertIn("#!/bin/sh", helper_text)
        self.assertIn("/usr/bin/python3", helper_text)
        self.assertIn(str(self.libexec / priv_setup.PRIV_NAME), helper_text)
        self.assertIn("org.dma2box.run-core", self.policy.read_text(encoding="utf-8"))
        self.assertEqual(
            summary["core_sha256"], priv_setup.sha256_file(installed_core)
        )

    def test_install_is_idempotent_and_replaces(self) -> None:
        self._install()
        self.core.write_bytes(b"#!/bin/sh\n# fake sing-box v2\n" * 16)
        os.chmod(self.core, 0o700)
        second = self._install()
        installed_core = self.libexec / priv_setup.CORE_NAME
        self.assertEqual(installed_core.read_bytes(), self.core.read_bytes())
        self.assertEqual(second["core_sha256"], priv_setup.sha256_file(self.core))
        # Временных файлов после атомарной замены не остаётся.
        leftovers = [p.name for p in self.libexec.iterdir() if p.name.endswith(".new")]
        self.assertEqual(leftovers, [])

    def test_install_rejects_directory_as_core(self) -> None:
        directory = self.tmp / "dir-core"
        directory.mkdir()
        with self.assertRaises(ValueError):
            priv_setup.install_components(
                directory, self.priv, libexec_dir=self.libexec, policy_path=self.policy
            )

    def test_install_rejects_symlink_core(self) -> None:
        link = self.tmp / "core-link"
        link.symlink_to(self.core)
        with self.assertRaises(ValueError):
            priv_setup.install_components(
                link, self.priv, libexec_dir=self.libexec, policy_path=self.policy
            )

    def test_install_rejects_non_executable_core(self) -> None:
        non_exec = self.tmp / "sing-box-data"
        non_exec.write_bytes(b"not executable\n")
        os.chmod(non_exec, 0o644)
        with self.assertRaises(ValueError):
            priv_setup.install_components(
                non_exec, self.priv, libexec_dir=self.libexec, policy_path=self.policy
            )

    def test_remove_deletes_only_installed_files(self) -> None:
        self._install()
        # Чужой файл в libexec остаётся на месте.
        bystander = self.libexec / "keep-me"
        bystander.write_bytes(b"x")
        removed = priv_setup.remove_components(
            libexec_dir=self.libexec, policy_path=self.policy
        )
        self.assertFalse((self.libexec / priv_setup.CORE_NAME).exists())
        self.assertFalse((self.libexec / priv_setup.PRIV_NAME).exists())
        self.assertFalse((self.libexec / priv_setup.HELPER_NAME).exists())
        self.assertFalse(self.policy.exists())
        self.assertTrue(bystander.is_file())
        self.assertEqual(len(removed), 4)
        # Повторное удаление не падает.
        priv_setup.remove_components(
            libexec_dir=self.libexec, policy_path=self.policy
        )

    def test_main_refuses_non_root(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("под root проверка прав тривиально проходит")
        result = priv_setup.main(
            ["install", "--core", str(self.core), "--priv", str(self.priv)]
        )
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
