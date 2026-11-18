from __future__ import annotations

import contextlib
import io
import unittest

from dma2box import privileged
from dma2box.config import build_config
from dma2box.vless import parse_vless

UUID = "11111111-2222-3333-4444-555555555555"


class PrivilegedConfigTests(unittest.TestCase):
    def test_generated_config_is_accepted_by_helper(self) -> None:
        config = build_config(
            parse_vless(f"vless://{UUID}@example.com:443?security=tls&type=tcp"),
            tun=True,
            enable_ipv6=True,
        )
        self.assertTrue(set(config).issubset(privileged.ALLOWED_ROOT_KEYS))
        self.assertNotIn("output", config["log"])
        self.assertTrue(config["inbounds"][0]["auto_route"])
        self.assertTrue(config["inbounds"][0]["auto_redirect"])

    def test_manual_routing_is_gone(self) -> None:
        # Маршруты, fwmark и таблицы теперь полностью внутри sing-box.
        self.assertFalse(hasattr(privileged, "_ip_run"))
        self.assertFalse(hasattr(privileged, "ROUTE_TABLE"))
        self.assertFalse(hasattr(privileged.Runner, "_configure_routing"))
        self.assertFalse(hasattr(privileged.Runner, "_remove_routing"))

    def test_helper_accepts_core_argument(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as ctx:
                privileged.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--core", output.getvalue())
        self.assertNotIn("--xray", output.getvalue())


if __name__ == "__main__":
    unittest.main()
