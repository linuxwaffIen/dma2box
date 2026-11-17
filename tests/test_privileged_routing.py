from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dma2ray import privileged
from dma2ray.config import build_config
from dma2ray.vless import parse_vless


UUID = "11111111-2222-3333-4444-555555555555"


class PrivilegedRoutingTests(unittest.TestCase):
    def test_policy_rules_cover_ipv4_ipv6_and_cleanup(self) -> None:
        config = build_config(
            parse_vless(
                f"vless://{UUID}@example.com:443?encryption=none&security=tls&type=tcp"
            ),
            tun=True,
            enable_ipv6=True,
        )
        calls: list[tuple[str, ...]] = []

        def fake_ip(family: str, *args: str, check: bool = True):
            calls.append((family, *args))
            if args[:2] == ("rule", "list"):
                return type("Result", (), {"stdout": "0: from all lookup local\n32766: from all lookup main\n"})()
            if args[:2] == ("route", "show"):
                return type("Result", (), {"stdout": ""})()
            return type("Result", (), {"stdout": ""})()

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            runner = privileged.Runner(Path("/usr/libexec/dma2ray/xray"), path,
                                       Path(directory) / "xray.log", 1000, 1000)
            with (
                patch.object(privileged, "_ip_run", side_effect=fake_ip),
                patch.object(privileged.Runner, "_save_routing_state"),
            ):
                runner._configure_routing(path)
                self.assertTrue(any(call[:3] == ("-4", "route", "add") for call in calls))
                self.assertTrue(any(call[:3] == ("-6", "route", "add") for call in calls))
                self.assertTrue(any("fwmark" in call for call in calls))
                self.assertTrue(any("suppress_prefixlength" in call for call in calls))
                self.assertTrue(any(call[-2:] == ("lookup", privileged.ROUTE_TABLE) for call in calls))
                added = list(runner.routing_cleanup)
                runner._remove_routing()
                self.assertEqual(runner.routing_cleanup, [])
                self.assertTrue(all((command[0], *command[1:]) in calls for command in added))

    def test_policy_routing_refuses_wrong_tun_name_or_unmarked_proxy(self) -> None:
        config = build_config(
            parse_vless(
                f"vless://{UUID}@example.com:443?encryption=none&security=tls&type=tcp"
            ),
            tun=True,
            enable_ipv6=False,
        )
        config["inbounds"][0]["settings"]["name"] = "other0"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            runner = privileged.Runner(Path("/usr/libexec/dma2ray/xray"), path,
                                       Path(directory) / "xray.log", 1000, 1000)
            with self.assertRaisesRegex(OSError, "Имя TUN"):
                runner._configure_routing(path)


if __name__ == "__main__":
    unittest.main()
