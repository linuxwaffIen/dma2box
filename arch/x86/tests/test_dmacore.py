import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dma2box.dmacore import Backend, available_backends, choose, features, plan_run


class DmacoreTests(unittest.TestCase):
    def test_features_include_our_strengths(self) -> None:
        values = features()
        for feature in ("tun", "routing", "geoip", "health", "failover"):
            self.assertIn(feature, values)

    def test_xhttp_prefers_xray(self) -> None:
        backends = {
            "xray": Backend("xray", Path("/bin/xray"), "run"),
            "singbox": Backend("singbox", Path("/bin/sing-box"), "run"),
        }
        with patch("dma2box.dmacore.available_backends", return_value=backends):
            self.assertEqual(choose(SimpleNamespace(network="xhttp")), "xray")
            self.assertEqual(choose(None), "singbox")

    def test_plan_run_uses_backend_mode(self) -> None:
        backends = {
            "hiddify": Backend("hiddify", Path("/bin/hiddify-core"), "srun"),
        }
        with patch("dma2box.dmacore.available_backends", return_value=backends):
            self.assertEqual(
                plan_run(Path("/tmp/config.json"), "hiddify"),
                ["/bin/hiddify-core", "srun", "-c", "/tmp/config.json"],
            )

    def test_missing_backend_version_is_empty(self) -> None:
        self.assertEqual(Backend("x", Path("/nonexistent/xray"), "run").version(), "")

    def test_available_backends_returns_backend_objects(self) -> None:
        for item in available_backends().values():
            self.assertIsInstance(item, Backend)


if __name__ == "__main__":
    unittest.main()
