from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        with (
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as ctx,
        ):
            privileged.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--core", output.getvalue())
        self.assertNotIn("--xray", output.getvalue())


class _FakeResult:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class PrivilegedRouterTests(unittest.TestCase):
    """Роутер: атомарный undo, sweep и ipv6-forwarding под моками."""

    def test_pkexec_uid_conflict(self) -> None:
        self.assertFalse(privileged._pkexec_uid_conflict("1000", {"PKEXEC_UID": "1000"}))
        self.assertTrue(privileged._pkexec_uid_conflict("1000", {"PKEXEC_UID": "1001"}))
        self.assertFalse(privileged._pkexec_uid_conflict("1000", {}))

    def test_tun_interface_from_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps({"inbounds": [{"type": "tun", "interface_name": "tun9"}]}),
                encoding="utf-8",
            )
            self.assertEqual(privileged._tun_interface_from_config(path), "tun9")
            path.write_text(
                json.dumps({"inbounds": [{"type": "tun", "interface_name": "../evil"}]}),
                encoding="utf-8",
            )
            self.assertEqual(privileged._tun_interface_from_config(path), "")
            path.write_text(
                json.dumps({"inbounds": [{"type": "socks"}]}), encoding="utf-8"
            )
            self.assertEqual(privileged._tun_interface_from_config(path), "")
            path.write_text("{broken", encoding="utf-8")
            self.assertEqual(privileged._tun_interface_from_config(path), "")

    def test_router_sweep_removes_only_tagged_rules(self) -> None:
        calls: list[list[str]] = []
        listing = (
            "-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE "
            "-m comment --comment dma2box-router\n"
            "-A POSTROUTING -s 172.16.0.0/24 -o eth0 -j MASQUERADE "
            "-m comment --comment unrelated-rule\n"
            "-P POSTROUTING ACCEPT\n"
        )

        def run(argv: list[str]) -> _FakeResult:
            calls.append(list(argv))
            if "-S" in argv:
                return _FakeResult(stdout=listing)
            return _FakeResult()

        with (
            mock.patch.object(privileged, "_run_command", side_effect=run),
            mock.patch(
                "shutil.which", side_effect=lambda name: "/usr/sbin/iptables" if name == "iptables" else None
            ),
        ):
            privileged._router_sweep()
        deletes = [c for c in calls if "-D" in c]
        self.assertEqual(len(deletes), 1)
        self.assertIn("10.0.0.0/24", " ".join(deletes[0]))
        self.assertFalse(any("172.16.0.0/24" in " ".join(c) for c in deletes))
        self.assertFalse(any(c and c[0] == "nft" for c in calls))

    def _router_mocks(self, fail_second_add: bool):
        calls: list[list[str]] = []
        state = {"adds": 0}

        def run(argv: list[str]) -> _FakeResult:
            calls.append(list(argv))
            if argv[0] == "sysctl" and "-n" in argv:
                return _FakeResult(stdout="0")
            if len(argv) > 1 and argv[1] == "-t" and "-C" in argv:
                return _FakeResult(returncode=1)  # правила ещё нет
            if len(argv) > 1 and argv[1] == "-t" and "-A" in argv:
                state["adds"] += 1
                if fail_second_add and state["adds"] == 2:
                    return _FakeResult(returncode=1, stderr="iptables: boom")
                return _FakeResult()
            return _FakeResult()

        return run, calls

    def test_router_apply_registers_undo_progressively(self) -> None:
        run, _calls = self._router_mocks(fail_second_add=False)
        seen: list[list[str]] = []
        with (
            mock.patch.object(privileged, "_run_command", side_effect=run),
            mock.patch(
                "shutil.which", side_effect=lambda name: "/usr/sbin/iptables" if name == "iptables" else None
            ),
            mock.patch.object(privileged, "_ipv6_supported", return_value=True),
        ):
            result = privileged._router_apply(
                "eth0", ["10.10.0.0/24", "192.168.50.0/24"], on_undo=seen.append
            )
        self.assertEqual(result, seen)
        self.assertEqual(len(result), 4)
        self.assertIn("net.ipv4.ip_forward=0", " ".join(result[0]))
        self.assertIn("net.ipv6.conf.all.forwarding=0", " ".join(result[1]))
        delete_rules = [" ".join(c) for c in result[2:]]
        self.assertTrue(any("10.10.0.0/24" in c and "-D" in c for c in delete_rules))
        self.assertTrue(any("192.168.50.0/24" in c and "-D" in c for c in delete_rules))

    def test_router_apply_atomic_on_failure(self) -> None:
        run, _calls = self._router_mocks(fail_second_add=True)
        seen: list[list[str]] = []
        with (
            mock.patch.object(privileged, "_run_command", side_effect=run),
            mock.patch(
                "shutil.which", side_effect=lambda name: "/usr/sbin/iptables" if name == "iptables" else None
            ),
            mock.patch.object(privileged, "_ipv6_supported", return_value=True),
            self.assertRaises(RuntimeError) as ctx,
        ):
            privileged._router_apply(
                "eth0", ["10.10.0.0/24", "192.168.50.0/24"], on_undo=seen.append
            )
        self.assertIn("iptables", str(ctx.exception))
        # Атомарность: к моменту сбоя undo уже знает про оба sysctl и первый NAT.
        self.assertEqual(len(seen), 3)
        self.assertTrue(any("-D" in " ".join(c) and "10.10.0.0/24" in " ".join(c) for c in seen))

    def test_router_apply_without_ipv6(self) -> None:
        run, _calls = self._router_mocks(fail_second_add=False)
        with (
            mock.patch.object(privileged, "_run_command", side_effect=run),
            mock.patch(
                "shutil.which", side_effect=lambda name: "/usr/sbin/iptables" if name == "iptables" else None
            ),
            mock.patch.object(privileged, "_ipv6_supported", return_value=False),
        ):
            result = privileged._router_apply("eth0", ["10.10.0.0/24"])
        self.assertEqual(len(result), 2)
        self.assertNotIn("ipv6", " ".join(" ".join(c) for c in result))


if __name__ == "__main__":
    unittest.main()
