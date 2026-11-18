from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit


class HysteriaError(ValueError):
    pass


@dataclass(frozen=True)
class HysteriaProfile:
    auth: str
    address: str
    port: int
    name: str
    sni: str = ""
    insecure: bool = False
    pin_sha256: str = ""
    obfs: str = ""
    obfs_password: str = ""
    protocol: str = "hysteria2"

    @property
    def endpoint(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{host}:{self.port}"

    def detail(self) -> str:
        return f"{self.endpoint} · QUIC · HYSTERIA2"

    def to_singbox_outbound(self, address_override: str | None = None) -> dict:
        if self.pin_sha256:
            raise HysteriaError(
                "sing-box не поддерживает проверку сертификата по pinSHA256. "
                "Уберите параметр pinsha256 из ссылки."
            )
        outbound: dict = {
            "tag": "proxy",
            "type": "hysteria2",
            "server": address_override or self.address,
            "server_port": int(self.port),
            "password": self.auth,
            "tls": {
                "enabled": True,
                "server_name": self.sni or self.address,
            },
        }
        if self.insecure:
            outbound["tls"]["insecure"] = True
        if self.obfs:
            outbound["obfs"] = {"type": self.obfs, "password": self.obfs_password}
        return outbound


def parse_hysteria2(uri: str) -> HysteriaProfile:
    uri = uri.strip()
    if not (uri.lower().startswith("hysteria2://") or uri.lower().startswith("hy2://")):
        raise HysteriaError("Ссылка должна начинаться с hysteria2:// или hy2://")
    try:
        parts = urlsplit(uri)
        host = (parts.hostname or "").strip("[]")
        port = parts.port or 443
    except ValueError as exc:
        # сюда попадает и port hopping вида host:20000-30000
        raise HysteriaError(f"Некорректный адрес или порт: {exc}") from exc
    if not host:
        raise HysteriaError("В ссылке отсутствует адрес сервера")
    if not 1 <= port <= 65535:
        raise HysteriaError("Порт должен быть в диапазоне 1..65535")
    q = {k.lower(): v for k, v in parse_qsl(parts.query, keep_blank_values=True)}
    auth = unquote(parts.username or "")
    if parts.password is not None:
        auth += ":" + unquote(parts.password)
    # Большинство ссылок передают пароль в query: hysteria2://host:443?p=...
    if not auth:
        auth = q.get("p") or q.get("password") or ""
    if not auth:
        raise HysteriaError("В ссылке отсутствует пароль")
    obfs = q.get("obfs", "")
    if obfs and obfs != "salamander":
        raise HysteriaError(f"Неподдерживаемая обфускация: {obfs}")
    return HysteriaProfile(
        auth=auth,
        address=host,
        port=port,
        name=unquote(parts.fragment).strip() or f"{host}:{port}",
        sni=q.get("sni", ""),
        insecure=q.get("insecure", "").lower() in ("1", "true", "yes", "on"),
        pin_sha256=q.get("pinsha256", ""),
        obfs=obfs,
        obfs_password=q.get("obfs-password", ""),
    )


def parse_any(uri: str):
    """Единая точка входа для всех поддерживаемых ссылок."""
    from .vless import (
        parse_trojan,
        parse_shadowsocks,
        parse_vmess,
        parse_wireguard,
        parse_amnezia,
        parse_vless,
    )

    lowered = uri.strip().lower()
    if lowered.startswith(("hysteria2://", "hy2://")):
        return parse_hysteria2(uri)
    if lowered.startswith("trojan://"):
        return parse_trojan(uri)
    if lowered.startswith("ss://"):
        return parse_shadowsocks(uri)
    if lowered.startswith("vmess://"):
        return parse_vmess(uri)
    if lowered.startswith("wireguard://"):
        return parse_wireguard(uri)
    if lowered.startswith("amnezia://"):
        return parse_amnezia(uri)
    return parse_vless(uri)
