from __future__ import annotations

import unittest

from dma2box.vless import VlessError, parse_vless

UUID = "11111111-2222-3333-4444-555555555555"


class ParseVlessTests(unittest.TestCase):
    def test_ws_tls_profile(self) -> None:
        uri = (
            f"vless://{UUID}@example.com:443?encryption=none&security=tls"
            "&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws"
            "&alpn=h2%2Chttp%2F1.1&fp=chrome#My%20Server"
        )
        profile = parse_vless(uri)
        self.assertEqual(profile.uuid, UUID)
        self.assertEqual(profile.address, "example.com")
        self.assertEqual(profile.port, 443)
        self.assertEqual(profile.name, "My Server")
        self.assertEqual(profile.security, "tls")
        self.assertEqual(profile.network, "ws")
        self.assertEqual(profile.sni, "cdn.example.com")
        self.assertEqual(profile.host_header, "cdn.example.com")
        self.assertEqual(profile.path, "/ws")
        self.assertEqual(profile.alpn, ["h2", "http/1.1"])
        self.assertEqual(profile._singbox_transport(), {
            "type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"},
        })
        tls = profile._singbox_tls()
        assert tls is not None
        self.assertEqual(tls["server_name"], "cdn.example.com")
        self.assertEqual(tls["alpn"], ["h2", "http/1.1"])
        self.assertEqual(tls["utls"]["fingerprint"], "chrome")

    def test_reality_profile(self) -> None:
        uri = (
            f"vless://{UUID}@example.com:443?security=reality&sni=www.microsoft.com"
            "&fp=chrome&pbk=public-key&sid=0123&spx=%2F&type=tcp"
            "&flow=xtls-rprx-vision#Reality"
        )
        profile = parse_vless(uri)
        self.assertEqual(profile.security, "reality")
        self.assertEqual(profile.public_key, "public-key")
        self.assertEqual(profile.short_id, "0123")
        self.assertEqual(profile.flow, "xtls-rprx-vision")
        tls = profile._singbox_tls()
        assert tls is not None
        self.assertEqual(tls["reality"]["public_key"], "public-key")
        self.assertEqual(tls["reality"]["short_id"], "0123")
        outbound = profile.to_singbox_outbound()
        self.assertEqual(outbound["flow"], "xtls-rprx-vision")

    def test_transport_variants(self) -> None:
        grpc = parse_vless(f"vless://{UUID}@example.com:443?type=grpc&serviceName=svc")
        self.assertEqual(grpc._singbox_transport(), {
            "type": "grpc", "service_name": "svc",
        })

        upgrade = parse_vless(
            f"vless://{UUID}@example.com:443?type=httpupgrade"
            "&host=example.com&path=%2Fup"
        )
        self.assertEqual(upgrade._singbox_transport(), {
            "type": "httpupgrade", "path": "/up", "host": "example.com",
        })

        # Парсеры принимают эти транспорты, но outbound должен отказать.
        for transport in ("xhttp", "splithttp", "kcp", "mkcp"):
            with self.subTest(transport=transport):
                profile = parse_vless(
                    f"vless://{UUID}@example.com:443?type={transport}&path=%2Fx"
                )
                with self.assertRaises(VlessError) as ctx:
                    profile.to_singbox_outbound()
                self.assertIn("sing-box", str(ctx.exception))

        tcp_http = parse_vless(
            f"vless://{UUID}@example.com:443?type=tcp"
            "&headerType=http&host=a.example.com&path=%2Fh"
        )
        with self.assertRaises(VlessError) as ctx:
            tcp_http.to_singbox_outbound()
        self.assertIn("sing-box", str(ctx.exception))

    def test_http2_transport_is_supported(self) -> None:
        for transport in ("http", "h2", "http2"):
            with self.subTest(transport=transport):
                profile = parse_vless(
                    f"vless://{UUID}@example.com:443?type={transport}"
                    "&security=tls&path=%2Fh2&host=example.com"
                )
                self.assertEqual(profile.network, "http")
                self.assertEqual(profile._singbox_transport(), {
                    "type": "http", "path": "/h2", "host": ["example.com"],
                })

    def test_raw_is_plain_tcp(self) -> None:
        profile = parse_vless(f"vless://{UUID}@example.com:443?type=raw")
        self.assertEqual(profile.network, "raw")
        self.assertIsNone(profile._singbox_transport())

    def test_ipv6_address(self) -> None:
        profile = parse_vless(f"vless://{UUID}@[2001:db8::1]:8443?type=tcp")
        self.assertEqual(profile.address, "2001:db8::1")
        self.assertEqual(profile.endpoint, "[2001:db8::1]:8443")
        self.assertEqual(profile.to_singbox_outbound()["server"], "2001:db8::1")

    def test_address_override(self) -> None:
        outbound = parse_vless(
            f"vless://{UUID}@example.com:443?type=tcp"
        ).to_singbox_outbound("203.0.113.7")
        self.assertEqual(outbound["server"], "203.0.113.7")

    def test_name_fallback(self) -> None:
        profile = parse_vless(f"vless://{UUID}@example.com:443")
        self.assertEqual(profile.name, "example.com:443")
        self.assertEqual(profile.port, 443)

    def test_default_port(self) -> None:
        profile = parse_vless(f"vless://{UUID}@example.com")
        self.assertEqual(profile.port, 443)

    def test_invalid_links(self) -> None:
        invalid = [
            "",
            "http://example.com",
            f"vless://@example.com:443",
            f"vless://{UUID}@:443",
            f"vless://{UUID}@example.com:0",
            f"vless://{UUID}@example.com:70000",
            f"vless://{UUID}@example.com:notaport",
            f"vless://{UUID}@[2001:db8::1:443",
            f"vless://{UUID}@example.com:443?type=wireguard",
            f"vless://{UUID}@example.com:443?security=reality&type=tcp",
        ]
        for uri in invalid:
            with self.subTest(uri=uri):
                with self.assertRaises(VlessError):
                    parse_vless(uri)

    def test_removed_transport(self) -> None:
        with self.assertRaises(VlessError) as ctx:
            parse_vless(f"vless://{UUID}@example.com:443?type=quic")
        self.assertIn("sing-box", str(ctx.exception))

    def test_splithttp_alias(self) -> None:
        profile = parse_vless(f"vless://{UUID}@example.com:443?type=splithttp")
        self.assertEqual(profile.network, "xhttp")

    def test_mkcp_alias(self) -> None:
        profile = parse_vless(f"vless://{UUID}@example.com:443?type=mkcp&seed=abc")
        self.assertEqual(profile.network, "kcp")


if __name__ == "__main__":
    unittest.main()
