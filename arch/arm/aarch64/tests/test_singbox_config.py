from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from dma2box.config import build_config
from dma2box.vless import parse_vless

UUID = "11111111-2222-3333-4444-555555555555"


def _find_singbox() -> str | None:
    from dma2box import paths

    override = os.environ.get("SINGBOX_BINARY")
    if override and Path(override).is_file():
        return override
    if paths.CORE_PATH.is_file():
        return str(paths.CORE_PATH)
    return shutil.which("sing-box")


class SingboxConfigValidationTests(unittest.TestCase):
    """Проверка сгенерированных конфигов настоящим бинарником sing-box."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.singbox = _find_singbox()
        if not cls.singbox:
            raise unittest.SkipTest("sing-box binary not found")

    def _validate(self, profile: object, *, tun: bool) -> None:
        config = build_config(
            profile,
            tun=tun,
            socks_port=10808,
            http_port=10809,
            log_level="warning",
            address_override="127.0.0.1",
            enable_ipv6=True,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(config, handle, ensure_ascii=False)
            path = handle.name
        try:
            result = subprocess.run(
                [self.singbox, "check", "-c", path],
                capture_output=True,
                text=True,
                timeout=25,
            )
        finally:
            Path(path).unlink(missing_ok=True)
        detail = (result.stdout + "\n" + result.stderr).strip()
        self.assertEqual(result.returncode, 0, detail)

    def test_common_transports_in_socks_mode(self) -> None:
        links = [
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=none&type=tcp#tcp",
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=tls&type=ws&path=%2Fws#ws",
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=tls&type=grpc&serviceName=svc#grpc",
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=tls&type=httpupgrade&path=%2Fup#up",
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=tls&type=http&path=%2Fh2#http2",
        ]
        for link in links:
            with self.subTest(link=link):
                self._validate(parse_vless(link), tun=False)

    def test_reality_and_tun_mode(self) -> None:
        profile = parse_vless(
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=reality"
            "&type=tcp&flow=xtls-rprx-vision&sni=example.com"
            "&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#reality"
        )
        self._validate(profile, tun=False)
        self._validate(profile, tun=True)

    def test_plain_and_ipv6_in_tun_mode(self) -> None:
        links = [
            f"vless://{UUID}@127.0.0.1:443?encryption=none&security=none&type=tcp#plain",
            f"vless://{UUID}@[::1]:443?encryption=none&security=none&type=tcp#ipv6",
        ]
        for link in links:
            with self.subTest(link=link):
                self._validate(parse_vless(link), tun=True)

    def test_other_protocols(self) -> None:
        import base64

        from dma2box.vless import parse_shadowsocks, parse_trojan, parse_vmess
        from dma2box.hysteria import parse_hysteria2

        vmess_json = {
            "add": "example.com", "port": 443, "id": UUID,
            "net": "ws", "path": "/v", "tls": "tls",
        }
        vmess_uri = "vmess://" + base64.b64encode(
            json.dumps(vmess_json).encode()
        ).decode()
        profiles = [
            parse_trojan("trojan://passw0rd@example.com:443?sni=example.com"),
            parse_shadowsocks("ss://aes-128-gcm:passw0rd@example.com:8388"),
            parse_vmess(vmess_uri),
            parse_hysteria2("hysteria2://host.com:443?p=passw0rd&sni=host.com"),
        ]
        for profile in profiles:
            with self.subTest(protocol=profile.protocol):
                self._validate(profile, tun=True)


if __name__ == "__main__":
    unittest.main()
