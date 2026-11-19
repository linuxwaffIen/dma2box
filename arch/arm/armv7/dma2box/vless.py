from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field, replace
from urllib.parse import parse_qsl, unquote, urlsplit


class VlessError(ValueError):
    pass


# Транспорты, которые понимает sing-box. xhttp и kcp парсер принимает, но при
# сборке конфига ссылка отклоняется с понятной ошибкой (см. _singbox_transport).
SUPPORTED_NETWORKS = {
    "tcp",
    "raw",
    "ws",
    "grpc",
    "httpupgrade",
    "http",
    "xhttp",
    "kcp",
}
NETWORK_ALIASES = {
    "split-http": "xhttp",
    "splithttp": "xhttp",
    "mkcp": "kcp",
    "h2": "http",
    "http2": "http",
}
# Транспорты, которых нет в sing-box: такие ссылки отклоняются при подключении.
UNSUPPORTED_TRANSPORTS = {
    "xhttp": (
        "Транспорт xhttp/splithttp не поддерживается sing-box. "
        "Попросите у провайдера ссылку с type=ws или type=grpc."
    ),
    "kcp": (
        "Транспорт mKCP не поддерживается sing-box. "
        "Попросите у провайдера ссылку с type=ws или type=grpc."
    ),
}
REMOVED_NETWORKS = {
    "quic": (
        "Транспорт QUIC не поддерживается sing-box. "
        "Попросите у провайдера ссылку с type=tcp или type=ws."
    ),
}
SUPPORTED_SECURITY = {"none", "tls", "reality", "xtls"}


@dataclass(frozen=True)
class VlessProfile:
    uuid: str
    address: str
    port: int
    name: str
    security: str = "none"
    network: str = "tcp"
    flow: str = ""
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    fingerprint: str = ""
    allow_insecure: bool = False
    public_key: str = ""
    short_id: str = ""
    spider_x: str = "/"
    host_header: str = ""
    path: str = "/"
    service_name: str = ""
    header_type: str = "none"
    mode: str = ""
    seed: str = ""
    quic_security: str = "none"
    quic_key: str = ""
    extra: dict[str, str] = field(default_factory=dict)
    protocol: str = "vless"

    @property
    def endpoint(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{host}:{self.port}"

    @property
    def transport_label(self) -> str:
        label = self.network.upper()
        if self.network in ("tcp", "raw") and self.header_type == "http":
            label = "TCP/HTTP"
        if self.network == "xhttp" and self.mode:
            label += f"/{self.mode}"
        return label

    @property
    def security_label(self) -> str:
        if self.security == "reality":
            return "REALITY"
        if self.security in ("tls", "xtls"):
            return "TLS"
        return "NONE"

    def detail(self) -> str:
        return f"{self.endpoint} · {self.transport_label} · {self.security_label}"

    def _singbox_tls(self) -> dict | None:
        security = "tls" if self.security == "xtls" else self.security
        if security == "tls":
            tls: dict = {"enabled": True, "server_name": self.sni or self.address}
            if self.allow_insecure:
                tls["insecure"] = True
            if self.alpn:
                tls["alpn"] = list(self.alpn)
            if self.fingerprint:
                tls["utls"] = {"enabled": True, "fingerprint": self.fingerprint}
            return tls
        if security == "reality":
            return {
                "enabled": True,
                "server_name": self.sni or self.address,
                "utls": {
                    "enabled": True,
                    "fingerprint": self.fingerprint or "chrome",
                },
                "reality": {
                    "enabled": True,
                    "public_key": self.public_key,
                    "short_id": self.short_id,
                },
            }
        return None

    def _singbox_transport(self) -> dict | None:
        if self.network in UNSUPPORTED_TRANSPORTS:
            raise VlessError(UNSUPPORTED_TRANSPORTS[self.network])
        if self.network in ("tcp", "raw"):
            if self.header_type == "http":
                raise VlessError(
                    "Обфускация TCP с headerType=http не поддерживается sing-box. "
                    "Попросите у провайдера ссылку с type=ws или type=grpc."
                )
            return None
        if self.network == "ws":
            transport: dict = {"type": "ws", "path": self.path or "/"}
            if self.host_header:
                transport["headers"] = {"Host": self.host_header}
            return transport
        if self.network == "grpc":
            return {"type": "grpc", "service_name": self.service_name}
        if self.network == "httpupgrade":
            transport = {"type": "httpupgrade", "path": self.path or "/"}
            if self.host_header:
                transport["host"] = self.host_header
            return transport
        if self.network == "http":
            transport = {"type": "http", "path": self.path or "/"}
            if self.host_header:
                transport["host"] = _split_hosts(self.host_header)
            return transport
        raise VlessError(f"Неподдерживаемый транспорт: {self.network}")

    def to_singbox_outbound(self, address_override: str | None = None) -> dict:
        if self.protocol == "amnezia":
            raise VlessError(
                "Протокол Amnezia не поддерживается sing-box. "
                "Попросите у провайдера ссылку vless:// или trojan://."
            )
        if self.protocol == "wireguard":
            raise VlessError(
                "WireGuard не поддерживается: sing-boxу нужны приватный ключ и "
                "адреса, которых нет в ссылке wireguard://."
            )
        address = address_override or self.address
        outbound: dict = {
            "tag": "proxy",
            "server": address,
            "server_port": int(self.port),
        }

        if self.protocol == "shadowsocks":
            outbound["type"] = "shadowsocks"
            outbound["method"] = self.security or "aes-128-gcm"
            outbound["password"] = self.uuid
            return outbound

        if self.protocol in ("hysteria", "hysteria2"):
            outbound["type"] = "hysteria2"
            outbound["password"] = self.uuid
            tls: dict = {"enabled": True, "server_name": self.sni or self.address}
            if self.allow_insecure:
                tls["insecure"] = True
            if self.alpn:
                tls["alpn"] = list(self.alpn)
            outbound["tls"] = tls
            obfs = self.extra.get("obfs", "")
            if obfs:
                outbound["obfs"] = {
                    "type": obfs,
                    "password": self.extra.get("obfs-password", ""),
                }
            return outbound

        transport = self._singbox_transport()
        tls = self._singbox_tls()
        if tls:
            outbound["tls"] = tls
        if transport:
            outbound["transport"] = transport

        if self.protocol == "trojan":
            outbound["type"] = "trojan"
            outbound["password"] = self.uuid
        elif self.protocol == "vmess":
            outbound["type"] = "vmess"
            outbound["uuid"] = self.uuid
            outbound["security"] = self.extra.get("scy") or "auto"
            try:
                outbound["alter_id"] = int(self.extra.get("aid") or 0)
            except ValueError:
                outbound["alter_id"] = 0
        else:
            outbound["type"] = "vless"
            outbound["uuid"] = self.uuid
            if self.flow:
                outbound["flow"] = self.flow
        return outbound


def parse_trojan(uri: str) -> VlessProfile:
    uri = uri.strip()
    if not uri.lower().startswith("trojan://"):
        raise VlessError("Ссылка должна начинаться с trojan://")
    rest = uri[len("trojan://"):]
    auth, _, hostport = rest.partition("@")
    password = unquote(auth)
    if not password:
        raise VlessError("В ссылке отсутствует пароль Trojan")
    hostpart, _, query = hostport.partition("?")
    host, _, port_str = hostpart.rpartition(":")
    if not host:
        raise VlessError("В ссылке отсутствует адрес сервера")
    try:
        port = int(port_str or "443")
    except ValueError as exc:
        raise VlessError(f"Некорректный порт: {exc}") from exc
    q = {key.lower(): value for key, value in parse_qsl(query, keep_blank_values=True)}
    network = _normalize_network(_first(q, "type", "network", default="tcp"))
    security = _first(q, "security", default="tls").lower()
    if security not in SUPPORTED_SECURITY:
        raise VlessError(f"Неподдерживаемый тип безопасности: {security}")
    return replace(
        VlessProfile(
            uuid=password,
            address=host,
            port=port,
            name=f"trojan://{host}:{port}",
            security=security,
            network=network,
            sni=_first(q, "sni", "servername"),
            alpn=[item for item in _first(q, "alpn").replace(" ", ",").split(",") if item],
            fingerprint=_first(q, "fp", "fingerprint"),
            allow_insecure=_as_bool(_first(q, "allowinsecure", "insecure")),
            host_header=_first(q, "host"),
            path=_first(q, "path", default="/") or "/",
            service_name=_first(q, "servicename", "service"),
            header_type=_first(q, "headertype", "header", default="none").lower() or "none",
            extra=q,
        ),
        protocol="trojan",
    )


def _b64decode_pad(text: str) -> bytes:
    """base64 с url-safe алфавитом и без выравнивания (как в SIP002)."""
    fixed = text.replace("-", "+").replace("_", "/")
    fixed += "=" * (-len(fixed) % 4)
    return base64.b64decode(fixed, validate=False)


def _ss_userinfo(raw: str) -> tuple[str, str]:
    """Разбор userinfo ss:// ссылки: method:password (plain, percent или base64)."""
    userinfo = unquote(raw)
    if ":" not in userinfo:
        # Некоторые провайдеры отдают userinfo в base64
        try:
            decoded = _b64decode_pad(raw).decode("utf-8")
        except Exception:
            decoded = ""
        if ":" in decoded:
            userinfo = decoded
    method, _, password = userinfo.partition(":")
    return method, password


def parse_shadowsocks(uri: str) -> VlessProfile:
    uri = uri.strip()
    if not uri.lower().startswith("ss://"):
        raise VlessError("Ссылка должна начинаться с ss://")
    payload = uri[len("ss://"):]

    if "@" not in payload:
        # Легаси-формат: весь payload в base64 (method:password@host:port#tag)
        body, _, frag = payload.partition("#")
        try:
            decoded = _b64decode_pad(body).decode("utf-8")
        except Exception as exc:
            raise VlessError("Не удалось декодировать ss:// ссылку") from exc
        if frag and "#" not in decoded:
            decoded = decoded + "#" + frag
        payload = decoded

    body_all, _, frag = payload.partition("#")
    name = unquote(frag).strip()

    userinfo, _, hostpart = body_all.rpartition("@")
    hostbody, _, query = hostpart.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))

    if params.get("plugin"):
        plugin = unquote(params["plugin"]).split(";", 1)[0]
        raise VlessError(f"SIP003-плагины не поддерживаются: {plugin}")

    host, _, port_str = hostbody.rpartition(":")
    if not host:
        raise VlessError("В ссылке отсутствует адрес сервера")
    try:
        port = int(port_str or "443")
    except ValueError as exc:
        raise VlessError(f"Некорректный порт: {exc}") from exc
    if not 1 <= port <= 65535:
        raise VlessError("Порт должен быть в диапазоне 1..65535")

    method, password = _ss_userinfo(userinfo)
    if not password:
        raise VlessError("В ссылке отсутствует пароль")
    return replace(
        VlessProfile(
            uuid=password,
            address=host,
            port=port,
            name=name or f"ss://{host}:{port}",
            security=method or "aes-128-gcm",
        ),
        protocol="shadowsocks",
    )


def parse_vmess(uri: str) -> VlessProfile:
    uri = uri.strip()
    if not uri.lower().startswith("vmess://"):
        raise VlessError("Ссылка должна начинаться с vmess://")
    payload = uri[len("vmess://"):]
    padded = payload + "=" * (-len(payload) % 4)
    try:
        raw = base64.b64decode(padded, altchars="-_", validate=False)
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise VlessError(f"Некорректная vmess:// ссылка: {exc}") from exc
    if not isinstance(data, dict):
        raise VlessError("Некорректная vmess:// ссылка: ожидается JSON-объект")
    uuid = str(data.get("id") or data.get("uuid") or "")
    address = str(data.get("add") or data.get("address") or "")
    try:
        port = int(data.get("port") or 443)
    except (TypeError, ValueError) as exc:
        raise VlessError("Некорректный порт в vmess:// ссылке") from exc
    network = _normalize_network(str(data.get("net") or "tcp"))
    tls_flag = str(data.get("tls") or "").lower()
    security = (
        "reality" if tls_flag == "reality"
        else "tls" if tls_flag in ("tls", "xtls") else "none"
    )
    path = str(data.get("path") or "/") or "/"
    return replace(
        VlessProfile(
            uuid=uuid,
            address=address,
            port=port,
            name=str(data.get("ps") or f"{address}:{port}"),
            security=security,
            network=network,
            sni=str(data.get("sni") or ""),
            fingerprint=str(data.get("fp") or ""),
            allow_insecure=bool(data.get("allowInsecure", False)),
            host_header=str(data.get("host") or ""),
            path=path,
            service_name=path if network == "grpc" else "",
            header_type=str(data.get("type") or "none").lower() or "none",
            extra={
                "scy": str(data.get("scy") or data.get("security") or "auto"),
                "aid": str(data.get("aid") or data.get("alterId") or 0),
            },
        ),
        protocol="vmess",
    )


def parse_hysteria2(uri: str) -> VlessProfile:
    uri = uri.strip()
    lowered = uri.lower()
    if not (lowered.startswith("hysteria2://") or lowered.startswith("hy2://")):
        raise VlessError("Ссылка должна начинаться с hysteria2:// или hy2://")
    rest = uri.split("://", 1)[1]
    authority, _, query = rest.partition("?")
    host, _, port_str = authority.rpartition(":")
    try:
        port = int(port_str or "443")
    except ValueError as exc:
        raise VlessError(f"Некорректный порт: {exc}") from exc
    q = {key.lower(): value for key, value in parse_qsl(query, keep_blank_values=True)}
    password = q.get("p") or q.get("password") or ""
    obfs = q.get("obfs", "")
    if obfs and obfs != "salamander":
        raise VlessError(f"Неподдерживаемая обфускация: {obfs}")
    return replace(
        VlessProfile(
            uuid=password,
            address=host,
            port=port,
            name=f"hysteria2://{host}:{port}",
            security="none",
            sni=q.get("sni", ""),
            allow_insecure=_as_bool(q.get("insecure", "")),
            extra={"obfs": obfs, "obfs-password": q.get("obfs-password", "")},
        ),
        protocol="hysteria",
    )


def parse_wireguard(uri: str) -> VlessProfile:
    uri = uri.strip()
    if not uri.lower().startswith("wireguard://"):
        raise VlessError("Ссылка должна начинаться с wireguard://")
    rest = uri[len("wireguard://"):]
    auth, _, hostport = rest.partition("@")
    public_key = unquote(auth)
    if not public_key:
        raise VlessError("В ссылке отсутствует публичный ключ WireGuard")
    hostport = hostport.split("?", 1)[0]
    host, _, port_str = hostport.rpartition(":")
    if not host:
        raise VlessError("В ссылке отсутствует адрес сервера")
    try:
        port = int(port_str or "51820")
    except ValueError as exc:
        raise VlessError(f"Некорректный порт: {exc}") from exc
    return replace(
        VlessProfile(
            uuid=public_key,
            address=host,
            port=port,
            name=f"wireguard://{host}:{port}",
            security="none",
        ),
        protocol="wireguard",
    )


def parse_amnezia(uri: str) -> VlessProfile:
    uri = uri.strip()
    if not uri.lower().startswith("amnezia://"):
        raise VlessError("Ссылка должна начинаться с amnezia://")
    rest = uri[len("amnezia://"):]
    auth, _, hostport = rest.partition("@")
    password = unquote(auth)
    if not password:
        raise VlessError("В ссылке отсутствует пароль Amnezia")
    hostport = hostport.split("?", 1)[0]
    host, _, port_str = hostport.rpartition(":")
    if not host:
        raise VlessError("В ссылке отсутствует адрес сервера")
    try:
        port = int(port_str or "443")
    except ValueError as exc:
        raise VlessError(f"Некорректный порт: {exc}") from exc
    return replace(
        VlessProfile(
            uuid=password,
            address=host,
            port=port,
            name=f"amnezia://{host}:{port}",
            security="none",
        ),
        protocol="amnezia",
    )


def _split_hosts(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _first(query: dict[str, str], *names: str, default: str = "") -> str:
    for name in names:
        value = query.get(name)
        if value not in (None, ""):
            return value
    return default


def _as_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


def _normalize_network(network: str) -> str:
    value = network.strip().lower()
    value = NETWORK_ALIASES.get(value, value)
    if value in REMOVED_NETWORKS:
        raise VlessError(REMOVED_NETWORKS[value])
    if value not in SUPPORTED_NETWORKS:
        raise VlessError(f"Неподдерживаемый транспорт: {value}")
    return value


def parse_vless(uri: str) -> VlessProfile:
    uri = uri.strip()
    if not uri.lower().startswith("vless://"):
        raise VlessError("Ссылка должна начинаться с vless://")
    try:
        parts = urlsplit(uri)
        host = (parts.hostname or "").strip()
        raw_port = parts.port
    except ValueError as exc:
        raise VlessError(f"Некорректная ссылка: {exc}") from exc

    uuid = unquote(parts.username or "").strip()
    if not uuid:
        raise VlessError("В ссылке отсутствует UUID")
    if len(uuid) > 64 or any(char.isspace() for char in uuid):
        raise VlessError("Некорректный UUID")

    if not host:
        raise VlessError("В ссылке отсутствует адрес сервера")
    host = host.strip("[]")

    try:
        port = int(443 if raw_port is None else raw_port)
    except (TypeError, ValueError) as exc:
        raise VlessError("Некорректный порт") from exc
    if not 1 <= port <= 65535:
        raise VlessError("Порт должен быть в диапазоне 1..65535")

    query = {key.lower(): value for key, value in parse_qsl(parts.query, keep_blank_values=True)}

    network = _normalize_network(_first(query, "type", "network", default="tcp"))

    security = _first(query, "security", default="none").lower()
    if security not in SUPPORTED_SECURITY:
        raise VlessError(f"Неподдерживаемый тип безопасности: {security}")
    if security == "reality" and not _first(query, "pbk", "publickey"):
        raise VlessError("Для REALITY нужен публичный ключ (pbk)")

    name = unquote(parts.fragment or "").strip() or f"{host}:{port}"
    alpn = [item for item in _first(query, "alpn").replace(" ", ",").split(",") if item]
    header_type = _first(query, "headertype", "header", default="none").lower()

    return VlessProfile(
        uuid=uuid,
        address=host,
        port=port,
        name=name,
        security=security,
        network=network,
        flow=_first(query, "flow"),
        sni=_first(query, "sni", "servername"),
        alpn=alpn,
        fingerprint=_first(query, "fp", "fingerprint"),
        allow_insecure=_as_bool(_first(query, "allowinsecure", "insecure")),
        public_key=_first(query, "pbk", "publickey"),
        short_id=_first(query, "sid", "shortid"),
        spider_x=_first(query, "spx", "spiderx", default="/") or "/",
        host_header=_first(query, "host"),
        path=_first(query, "path", default="/") or "/",
        service_name=_first(query, "servicename", "service"),
        header_type=header_type or "none",
        mode=_first(query, "mode"),
        seed=_first(query, "seed"),
        quic_security=_first(query, "quicsecurity", default="none") or "none",
        quic_key=_first(query, "key"),
        extra=query,
    )
