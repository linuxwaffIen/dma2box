"""Миграция данных со старых имён vless-gtk и dma2ray на dma2box."""
from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.cleanup)
        self.base = Path(self.tmp.name)
        self.env = {
            "XDG_CONFIG_HOME": str(self.base / "config"),
            "XDG_DATA_HOME": str(self.base / "data"),
            "XDG_STATE_HOME": str(self.base / "state"),
            "XDG_CACHE_HOME": str(self.base / "cache"),
            "XDG_RUNTIME_DIR": str(self.base / "run"),
        }
        for var, value in self.env.items():
            os.environ[var] = value
        # Каталоги вычисляются при импорте — перечитываем модуль под тестовым XDG.
        from dma2box import paths

        self.paths = importlib.reload(paths)

    def cleanup(self) -> None:
        for var in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                    "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"):
            os.environ.pop(var, None)
        # Возвращаем модуль к каталогам реального окружения для остальных тестов.
        from dma2box import paths

        importlib.reload(paths)
        self.tmp.cleanup()

    def test_legacy_dirs_are_renamed(self) -> None:
        old_config = Path(self.env["XDG_CONFIG_HOME"]) / "vless-gtk"
        old_config.mkdir(parents=True)
        (old_config / "state.json").write_text('{"profiles": []}', "utf-8")

        self.paths.ensure_dirs()

        self.assertTrue((Path(self.env["XDG_CONFIG_HOME"]) / "dma2box" / "state.json").is_file())
        self.assertFalse(old_config.exists())

    def test_dma2ray_dirs_are_renamed(self) -> None:
        for env_var, sub in (
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_CACHE_HOME", "cache"),
        ):
            old = Path(self.env[env_var]) / "dma2ray"
            old.mkdir(parents=True)
            (old / "marker").write_text(sub, "utf-8")

        self.paths.ensure_dirs()

        for env_var, sub in (
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_CACHE_HOME", "cache"),
        ):
            new = Path(self.env[env_var]) / "dma2box"
            self.assertTrue((new / "marker").is_file(), f"{new}/marker")
            self.assertEqual((new / "marker").read_text("utf-8"), sub)
            self.assertFalse((Path(self.env[env_var]) / "dma2ray").exists())

    def test_existing_new_dirs_are_not_touched(self) -> None:
        old_config = Path(self.env["XDG_CONFIG_HOME"]) / "vless-gtk"
        old_config.mkdir(parents=True)
        (old_config / "state.json").write_text('{"old": true}', "utf-8")
        new_config = Path(self.env["XDG_CONFIG_HOME"]) / "dma2box"
        new_config.mkdir(parents=True)
        (new_config / "state.json").write_text('{"new": true}', "utf-8")

        self.paths.ensure_dirs()

        self.assertEqual((new_config / "state.json").read_text("utf-8"), '{"new": true}')
        self.assertTrue(old_config.exists())

    def test_autostart_is_migrated_with_new_exec(self) -> None:
        autostart_dir = Path(self.env["XDG_CONFIG_HOME"]) / "autostart"
        autostart_dir.mkdir(parents=True)
        (autostart_dir / "vless-gtk.desktop").write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=VLESS GTK\n"
            "Exec=/old/vless-gtk --minimized\n"
            "X-GNOME-Autostart-enabled=true\n",
            "utf-8",
        )

        self.paths.ensure_dirs()

        new_file = autostart_dir / "dma2box.desktop"
        self.assertTrue(new_file.is_file())
        self.assertFalse((autostart_dir / "vless-gtk.desktop").exists())
        text = new_file.read_text("utf-8")
        self.assertIn("Name=Dma2box", text)
        self.assertNotIn("/old/vless-gtk", text)

    def test_dma2ray_autostart_is_migrated(self) -> None:
        autostart_dir = Path(self.env["XDG_CONFIG_HOME"]) / "autostart"
        autostart_dir.mkdir(parents=True)
        (autostart_dir / "dma2ray.desktop").write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Dma2ray\n"
            "Exec=/old/dma2ray --minimized\n"
            "X-GNOME-Autostart-enabled=true\n",
            "utf-8",
        )

        self.paths.ensure_dirs()

        new_file = autostart_dir / "dma2box.desktop"
        self.assertTrue(new_file.is_file())
        self.assertIn("Name=Dma2box", new_file.read_text("utf-8"))
        self.assertNotIn("/old/dma2ray", new_file.read_text("utf-8"))

    def test_no_legacy_dirs_is_noop(self) -> None:
        self.paths.ensure_dirs()  # не должен падать
        self.assertTrue((Path(self.env["XDG_CONFIG_HOME"]) / "dma2box").is_dir())


if __name__ == "__main__":
    unittest.main()
