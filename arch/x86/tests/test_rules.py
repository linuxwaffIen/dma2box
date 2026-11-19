import unittest

from dma2box.config import build_config, parse_rule_sets, parse_rules
from dma2box.hysteria import parse_any

HY2 = "hysteria2://secret@example.com:443?sni=example.com#test"


class RoutingRulesTests(unittest.TestCase):
    def test_parse_rules(self) -> None:
        rules, errors = parse_rules([
            "# comment",
            "domain:example.com:direct",
            "suffix:.ru:proxy",
            "ip:1.2.3.0/24:block",
            "rule:geoip-cn:direct",
            "broken",
        ])
        self.assertEqual(errors, ["Правило «broken»: ожидается тип:значение:outbound"])
        self.assertEqual(len(rules), 4)
        self.assertEqual(rules[0], {"domain": ["example.com"], "outbound": "direct"})
        self.assertEqual(rules[2], {"ip_cidr": ["1.2.3.0/24"], "outbound": "block"})

    def test_remote_rule_sets(self) -> None:
        sets = parse_rule_sets([
            "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
            "not-a-url",
        ])
        self.assertEqual(len(sets), 1)
        self.assertEqual(sets[0]["tag"], "geoip-cn")
        self.assertEqual(sets[0]["type"], "remote")

    def test_config_contains_rules(self) -> None:
        profile = parse_any(HY2)
        cfg = build_config(
            profile,
            route_rules=["domain:example.com:direct"],
            geo_rule_sets=["https://example.com/geoip-cn.srs"],
        )
        self.assertIn({"domain": ["example.com"], "outbound": "direct"}, cfg["route"]["rules"])
        self.assertEqual(cfg["route"]["rule_set"][0]["tag"], "geoip-cn")


if __name__ == "__main__":
    unittest.main()
