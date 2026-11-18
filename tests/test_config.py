from __future__ import annotations

import base64
import unittest

from dma2box.config import (
    PRIVATE_NETWORKS,
    TUN_GATEWAY,
    TUN_GATEWAY_V6,
    TUN_NAME,
    build_config,
)
from dma2box.hysteria import HysteriaError, parse_hysteria2 as parse_hy
from dma2box.vless import (
    VlessError,
    parse_amnezia,
    parse_hysteria2,
    parse_shadowsocks,
    parse_trojan,
    parse_vless,
    parse_wireguard,
)

UUID = "11111111-2222-3333-4444-555555555555"


def make_profile(transport: str = "ws") -> object:
    return parse_vless(
        f"vless://{UUID}@127.0.0.1:443?encryption=none&security=tls"
        f"&sni=example.com&type={transport}&path=%2Fws&host=example.com"
    )


class BuildConfigTests(unittest.TestCase):
    def test_socks_mode(self) -> None:
        config = build_config(make_profile(), tun=False, socks_port=11080, http_port=11081)
        self.assertNotIn("dns", config)
        tags = [inbound["tag"] for inbound in config["inbounds"]]
        self.assertEqual(tags, ["socks-in", "http-in"])
        socks, http = config["inbounds"]
        self.assertEqual((socks["type"], socks["listen_port"]), ("socks", 11080))
        self.assertEqual((http["type"], http["listen_port"]), ("http", 11081))
        self.assertEqual(socks["listen"], "127.0.0.1")
        self.assertEqual(
            [outbound["tag"] for outbound in config["outbounds"]],
            ["proxy", "direct", "block"],
        )
        self.assertEqual(
            [outbound["type"] for outbound in config["outbounds"]],
            ["vless", "direct", "block"],
        )
        self.assertEqual(config["route"]["final"], "proxy")

    def test_tun_mode(self) -> None:
        config = build_config(
            make_profile(), tun=True, socks_port=11080, http_port=11081, enable_ipv6=True
        )
        self.assertEqual(
            [inbound["tag"] for inbound in config["inbounds"]],
            ["tun-in", "socks-in", "http-in"],
        )
        tun = config["inbounds"][0]
        self.assertEqual(tun["type"], "tun")
        self.assertEqual(tun["interface_name"], TUN_NAME)
        self.assertEqual(tun["address"], [TUN_GATEWAY, TUN_GATEWAY_V6])
        self.assertTrue(tun["auto_route"])
        self.assertTrue(tun["strict_route"])
        self.assertTrue(tun["auto_redirect"])
        self.assertEqual(tun["dns_mode"], "hijack")

        self.assertIn("dns", config)
        self.assertTrue(all(s["type"] == "https" for s in config["dns"]["servers"]))
        self.assertTrue(all(s["detour"] == "proxy" for s in config["dns"]["servers"]))
        self.assertEqual(config["dns"]["final"], "doh-0")
        self.assertEqual(config["route"]["default_domain_resolver"], "doh-0")
        self.assertTrue(config["route"]["auto_detect_interface"])
        self.assertEqual(
            config["route"]["rules"][0],
            {"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"},
        )

    def test_tun_mode_ipv4_only(self) -> None:
        config = build_config(
            make_profile(), tun=True, socks_port=11080, http_port=11081, enable_ipv6=False
        )
        tun = config["inbounds"][0]
        self.assertEqual(tun["address"], [TUN_GATEWAY])
        self.assertEqual(config["dns"]["strategy"], "ipv4_only")
        private = [rule for rule in config["route"]["rules"] if rule.get("ip_cidr")]
        self.assertEqual(len(private), 1)
        self.assertEqual(private[0]["ip_cidr"], PRIVATE_NETWORKS)
        self.assertEqual(private[0]["outbound"], "direct")

    def test_ports_must_differ(self) -> None:
        with self.assertRaises(ValueError):
            build_config(make_profile(), tun=False, socks_port=1080, http_port=1080)

    def test_port_range(self) -> None:
        with self.assertRaises(ValueError):
            build_config(make_profile(), tun=False, socks_port=0, http_port=1080)
        with self.assertRaises(ValueError):
            build_config(make_profile(), tun=False, socks_port=1080, http_port=70000)

    def test_log_level_is_copied(self) -> None:
        self.assertEqual(
            build_config(make_profile(), tun=False, log_level="warning")["log"]["level"],
            "warn",
        )
        self.assertEqual(
            build_config(make_profile(), tun=False, log_level="debug")["log"]["level"],
            "debug",
        )

    def test_vless_outbound_details(self) -> None:
        config = build_config(make_profile(), tun=False)
        proxy = config["outbounds"][0]
        self.assertEqual(proxy["type"], "vless")
        self.assertEqual(proxy["uuid"], UUID)
        self.assertEqual(proxy["server"], "127.0.0.1")
        self.assertEqual(proxy["server_port"], 443)
        self.assertEqual(proxy["transport"], {"type": "ws", "path": "/ws", "headers": {"Host": "example.com"}})
        self.assertEqual(proxy["tls"]["server_name"], "example.com")
        self.assertEqual(proxy["server"], "127.0.0.1")

    def test_reality_outbound(self) -> None:
        profile = parse_vless(
            f"vless://{UUID}@example.com:443?security=reality&sni=www.microsoft.com"
            "&fp=chrome&pbk=public-key&sid=0123&type=tcp&flow=xtls-rprx-vision"
        )
        proxy = build_config(profile, tun=False)["outbounds"][0]
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")
        self.assertEqual(proxy["tls"]["reality"]["public_key"], "public-key")
        self.assertEqual(proxy["tls"]["reality"]["short_id"], "0123")
        self.assertEqual(proxy["tls"]["utls"]["fingerprint"], "chrome")

    def test_address_override(self) -> None:
        proxy = build_config(make_profile(), tun=False, address_override="203.0.113.7")["outbounds"][0]
        self.assertEqual(proxy["server"], "203.0.113.7")
        self.assertEqual(proxy["tls"]["server_name"], "example.com")

    def test_trojan_outbound_is_generated(self) -> None:
        profile = parse_trojan("trojan://passw0rd@example.com:443?sni=example.com&type=ws&path=/t")
        proxy = build_config(profile, tun=False)["outbounds"][0]
        self.assertEqual(proxy["type"], "trojan")
        self.assertEqual(proxy["password"], "passw0rd")
        self.assertEqual(proxy["server"], "example.com")
        self.assertEqual(proxy["server_port"], 443)
        self.assertEqual(proxy["tls"]["server_name"], "example.com")
        self.assertEqual(proxy["transport"], {"type": "ws", "path": "/t"})

    def test_shadowsocks_outbound_is_generated(self) -> None:
        profile = parse_shadowsocks("ss://aes-128-gcm:passw0rd@example.com:443")
        proxy = build_config(profile, tun=False)["outbounds"][0]
        self.assertEqual(proxy["type"], "shadowsocks")
        self.assertEqual(proxy["method"], "aes-128-gcm")
        self.assertEqual(proxy["password"], "passw0rd")
        self.assertEqual(proxy["server"], "example.com")
        self.assertEqual(proxy["server_port"], 443)

    def test_shadowsocks_2022_plain_userinfo(self) -> None:
        profile = parse_shadowsocks(
            "ss://2022-blake3-aes-256-gcm%3AaGVsbG8lMjB3b3JsZA%3D%3D"
            "@example.com:8388#SS2022"
        )
        self.assertEqual(profile.security, "2022-blake3-aes-256-gcm")
        self.assertEqual(profile.uuid, "aGVsbG8lMjB3b3JsZA==")
        self.assertEqual(profile.name, "SS2022")

    def test_shadowsocks_sip002_base64_userinfo(self) -> None:
        userinfo = base64.urlsafe_b64encode(
            b"chacha20-ietf-poly1305:secret:pass"
        ).decode().rstrip("=")
        profile = parse_shadowsocks(f"ss://{userinfo}@example.com:443#node")
        self.assertEqual(profile.security, "chacha20-ietf-poly1305")
        self.assertEqual(profile.uuid, "secret:pass")
        self.assertEqual(profile.name, "node")

    def test_shadowsocks_legacy_base64_uri(self) -> None:
        payload = base64.b64encode(
            b"aes-256-gcm:passw0rd@example.com:443#legacy"
        ).decode()
        profile = parse_shadowsocks(f"ss://{payload}")
        self.assertEqual(profile.security, "aes-256-gcm")
        self.assertEqual(profile.uuid, "passw0rd")
        self.assertEqual(profile.address, "example.com")
        self.assertEqual(profile.port, 443)
        self.assertEqual(profile.name, "legacy")

    def test_shadowsocks_plugin_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_shadowsocks(
                "ss://aes-128-gcm:passw0rd@example.com:443"
                "?plugin=obfs-local%3Bobfs%3Dhttp"
            )

    def test_hysteria2_outbound_is_generated(self) -> None:
        for profile in (
            parse_hysteria2("hysteria2://host.com:443?p=passw0rd"),
            parse_hy("hysteria2://host.com:443?p=passw0rd&sni=host.com"),
        ):
            with self.subTest(profile=profile):
                proxy = build_config(profile, tun=False)["outbounds"][0]
                self.assertEqual(proxy["type"], "hysteria2")
                self.assertEqual(proxy["password"], "passw0rd")
                self.assertEqual(proxy["server"], "host.com")
                self.assertEqual(proxy["server_port"], 443)
                self.assertTrue(proxy["tls"]["enabled"])

    def test_unsupported_protocols_and_transports_are_rejected(self) -> None:
        cases = [
            f"vless://{UUID}@example.com:443?type=xhttp#x",
            f"vless://{UUID}@example.com:443?type=split-http#s",
            f"vless://{UUID}@example.com:443?type=kcp#k",
            f"vless://{UUID}@example.com:443?type=mkcp#m",
            f"vless://{UUID}@example.com:443?type=tcp&headerType=http#h",
        ]
        for uri in cases:
            with self.subTest(uri=uri):
                with self.assertRaises(VlessError) as ctx:
                    build_config(parse_vless(uri), tun=False)
                self.assertIn("sing-box", str(ctx.exception))
        for profile in (parse_amnezia("amnezia://password@example.com:443"),
                        parse_wireguard("wireguard://pubkey@example.com:51820")):
            with self.subTest(protocol=profile.protocol):
                with self.assertRaises(VlessError) as ctx:
                    build_config(profile, tun=False)
                self.assertIn("sing-box", str(ctx.exception))
        with self.assertRaises(HysteriaError):
            build_config(
                parse_hy("hy2://host.com:443?p=pass&pinsha256=AAAA"), tun=False
            )


if __name__ == "__main__":
    unittest.main()
