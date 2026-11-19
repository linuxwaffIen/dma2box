import json
import unittest
from types import SimpleNamespace

from dma2box import xray


def _profile() -> SimpleNamespace:
    return SimpleNamespace(
        network="xhttp",
        address="cdn.shorts-boost.online",
        port=443,
        uuid="d94bec13-40d3-4a3c-b6a3-3b93e921f3ac",
        sni="cdn.shorts-boost.online",
        host_header="cdn.shorts-boost.online",
        path="/hitori-xhttp",
        mode="packet-up",
        fingerprint="chrome",
        alpn=["h2", "http/1.1"],
        flow="",
        extra={"extra": json.dumps({"xmux": {"maxConnections": 4}, "uplinkDataKey": "X-Data"})},
    )


class XrayBackendTests(unittest.TestCase):
    def test_needs_xray(self) -> None:
        self.assertTrue(xray.needs_xray(_profile()))
        plain = _profile()
        plain.network = "ws"
        self.assertFalse(xray.needs_xray(plain))

    def test_config_has_socks_and_no_xmux(self) -> None:
        cfg = xray.build_config(_profile(), 18500)
        self.assertEqual(cfg["inbounds"][0]["protocol"], "socks")
        self.assertEqual(cfg["inbounds"][0]["port"], 18500)
        outbound = cfg["outbounds"][0]
        self.assertEqual(outbound["protocol"], "vless")
        stream = outbound["streamSettings"]
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["xhttpSettings"]["mode"], "packet-up")
        self.assertNotIn("xmux", stream["xhttpSettings"]["extra"])
        self.assertEqual(stream["xhttpSettings"]["extra"]["uplinkDataKey"], "X-Data")


if __name__ == "__main__":
    unittest.main()
