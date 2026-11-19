from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any

TUN_NAME = "tun0"
TUN_GATEWAY = "172.19.0.1/30"
TUN_GATEWAY_V6 = "fdfe:dcba:9876::1/126"
TUN_MTU = 1500
DNS_TAG = "doh-0"

PRIVATE_NETWORKS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

# DoH-серверы sing-box использует для перехваченного DNS и для имён в правилах.
# Запросы идут через proxy outbound — как и весь остальной трафик.
PUBLIC_DNS = (
    ("1.1.1.1", 443),
    ("8.8.8.8", 443),
)


def is_ipv6_supported() -> bool:
    try:
        flag = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if flag.is_file() and flag.read_text().strip() == "1":
            return False
    except OSError:
        pass
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.close()
        return True
    except OSError:
        return False


def _log_level(level: str) -> str:
    return "warn" if level == "warning" else str(level)


# Пользовательские правила маршрутизации (как в Hiddify):
#   domain:example.com:direct   — домену и его поддоменам напрямую
#   suffix:.ru:proxy            — суффикс домена через туннель
#   ip:1.2.3.0/24:block         — подсеть блокируется
#   rule:geoip-cn:direct        — geo rule-set (geoip/geosite)
def parse_rules(lines: list[str] | tuple[str, ...] | None) -> tuple[list[dict], list[str]]:
    rules: list[dict] = []
    errors: list[str] = []
    for raw in lines or []:
        line = str(raw).strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            errors.append(f"Правило «{line}»: ожидается тип:значение:outbound")
            continue
        kind, value, outbound = parts[0].lower(), ":".join(parts[1:-1]), parts[-1].lower()
        if outbound not in ("direct", "proxy", "block"):
            errors.append(f"Правило «{line}»: неизвестный outbound {outbound}")
            continue
        if kind == "domain":
            rules.append({"domain": [value], "outbound": outbound})
        elif kind == "suffix":
            rules.append({"domain_suffix": [value], "outbound": outbound})
        elif kind == "ip":
            rules.append({"ip_cidr": [value], "outbound": outbound})
        elif kind == "rule":
            rules.append({"rule_set": [value], "outbound": outbound})
        else:
            errors.append(f"Правило «{line}»: неизвестный тип {kind}")
    return rules, errors


def parse_rule_sets(urls: list[str] | tuple[str, ...] | None) -> list[dict]:
    """Превращает URL .srs в remote rule-set'ы sing-box."""
    result: list[dict] = []
    for raw in urls or []:
        url = str(raw).strip()
        if not url or not url.endswith(".srs"):
            continue
        tag = url.rsplit("/", 1)[-1][: -len(".srs")]
        result.append({
            "tag": tag,
            "type": "remote",
            "format": "binary",
            "url": url,
            "update_interval": "24h",
        })
    return result


def build_config(
    profile: object,
    *,
    tun: bool = False,
    socks_port: int = 10808,
    http_port: int = 10809,
    log_level: str = "warning",
    address_override: str | None = None,
    enable_ipv6: bool | None = None,
    route_rules: list[str] | tuple[str, ...] | None = None,
    geo_rule_sets: list[str] | tuple[str, ...] | None = None,
    socks_detour: tuple[str, int] | None = None,
) -> dict[str, Any]:
    """Build a sing-box config for a parsed profile.

    Unsupported protocols/transports are rejected here, so the UI gets a clear
    message instead of a core that fails to start.
    """
    if not 1 <= socks_port <= 65535 or not 1 <= http_port <= 65535:
        raise ValueError("Порты должны быть в диапазоне 1..65535")
    if socks_port == http_port:
        raise ValueError("SOCKS и HTTP порты должны различаться")

    if socks_detour is not None:
        # xhttp: внешний движок (Xray) поднимает локальный SOCKS, а sing-box
        # остаётся фронтендом — TUN, DNS и правила работают как обычно.
        proxy: dict[str, Any] = {
            "tag": "proxy",
            "type": "socks",
            "server": socks_detour[0],
            "server_port": int(socks_detour[1]),
            "version": "5",
        }
    else:
        proxy = profile.to_singbox_outbound(address_override)
    inbounds: list[dict[str, Any]] = [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": int(socks_port),
        },
        {
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "listen_port": int(http_port),
        },
    ]

    user_rules, _ = parse_rules(route_rules)
    rule_sets = parse_rule_sets(geo_rule_sets)
    route: dict[str, Any] = {
        "rules": [
            # Локальные сети всегда идут мимо туннеля.
            {"ip_cidr": list(PRIVATE_NETWORKS), "outbound": "direct"},
            *user_rules,
        ],
        "final": "proxy",
    }
    if rule_sets:
        route["rule_set"] = rule_sets
    config: dict[str, Any] = {
        "log": {"level": _log_level(log_level), "timestamp": True},
        "inbounds": inbounds,
        "outbounds": [
            proxy,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": route,
    }

    if tun:
        has_v6 = is_ipv6_supported() if enable_ipv6 is None else enable_ipv6
        addresses = [TUN_GATEWAY] + ([TUN_GATEWAY_V6] if has_v6 else [])
        inbounds.insert(
            0,
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": TUN_NAME,
                "address": addresses,
                "mtu": TUN_MTU,
                # sing-box сам создаёт интерфейс, маршруты и redirect-правила —
                # ручной возни с ip rule/таблицами в privileged helper'е нет.
                "auto_route": True,
                "strict_route": True,
                "auto_redirect": True,
                "dns_mode": "hijack",
            },
        )
        config["dns"] = {
            "servers": [
                {
                    "type": "https",
                    "tag": f"doh-{index}",
                    "server": host,
                    "server_port": port,
                    "detour": "proxy",
                }
                for index, (host, port) in enumerate(PUBLIC_DNS)
            ],
            "final": DNS_TAG,
            "strategy": "prefer_ipv4" if has_v6 else "ipv4_only",
        }
        route["default_domain_resolver"] = DNS_TAG
        route["auto_detect_interface"] = True
        route["rules"].insert(
            0,
            {"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"},
        )

    return config


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
