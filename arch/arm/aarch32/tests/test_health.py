import unittest

from dma2box.health import HealthResult, check, parse_ip_body


class HealthTests(unittest.TestCase):
    def test_parse_ip_body(self) -> None:
        self.assertEqual(parse_ip_body("64.181.219.110\n"), "64.181.219.110")
        self.assertEqual(parse_ip_body("\n2001:4860:4860::8888\n"), "2001:4860:4860::8888")
        self.assertEqual(parse_ip_body("<html>error</html>"), "")

    def test_dead_proxy_is_not_healthy(self) -> None:
        result = check(1, real_ip="77.222.99.46", timeout=0.5)
        self.assertFalse(result.ok)
        self.assertTrue(result.error)
        self.assertIsInstance(result, HealthResult)


if __name__ == "__main__":
    unittest.main()
