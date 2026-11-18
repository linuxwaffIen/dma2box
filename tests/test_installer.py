from __future__ import annotations

import unittest
from unittest import mock

from dma2box import installer


class AssetTests(unittest.TestCase):
    def test_known_architectures(self) -> None:
        cases = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "aarch64": "arm64",
            "arm64": "arm64",
            "armv7l": "armv7",
            "armv6l": "armv6",
            "i686": "386",
            "riscv64": "riscv64",
        }
        for machine, target in cases.items():
            with self.subTest(machine=machine):
                with mock.patch.object(installer.platform, "machine", return_value=machine):
                    self.assertEqual(
                        installer.asset_name(),
                        f"sing-box-{{version}}-linux-{target}-musl.tar.gz",
                    )

    def test_asset_name_with_version(self) -> None:
        self.assertEqual(
            installer.asset_name("aarch64", "1.14.4"),
            "sing-box-1.14.4-linux-arm64-musl.tar.gz",
        )

    def test_unknown_architecture(self) -> None:
        with mock.patch.object(installer.platform, "machine", return_value="mips"):
            with self.assertRaises(RuntimeError):
                installer.asset_name()


if __name__ == "__main__":
    unittest.main()
