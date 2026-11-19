"""Проверка, что трафик действительно идёт через туннель.

Hiddify делает то же самое через `hiddify-core health`: запрашивает внешний IP
через прокси и сравнивает его с реальным IP машины. Если прокси молчит или
выдаёт тот же IP (транзитный перехват), соединение считается мёртвым.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.request
from dataclasses import dataclass

IP_HOST = "api.ipify.org"
IP_PATH = "/"
_AGENT = "dma2box-health/1.0"
_IP_RE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s*$")


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    ip: str = ""
    error: str = ""
    intercepted: bool = False


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("сокет закрыт во время ответа SOCKS5")
        data += chunk
    return data


def _socks5_connect(host: str, port: int, socks_port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", int(socks_port)), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")  # SOCKS5, без аутентификации
        version, method = _recv_exact(sock, 2)
        if version != 5 or method != 0:
            raise OSError(f"SOCKS5 отказал в методе: {version}/{method}")
        host_bytes = host.encode("idna")
        sock.sendall(
            b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + int(port).to_bytes(2, "big")
        )
        reply = _recv_exact(sock, 4)
        if reply[1] != 0:
            raise OSError(f"SOCKS5 CONNECT отклонён: код {reply[1]}")
        atyp = reply[3]
        if atyp == 1:
            _recv_exact(sock, 4)
        elif atyp == 4:
            _recv_exact(sock, 16)
        elif atyp == 3:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length)
        else:
            raise OSError(f"неизвестный тип адреса SOCKS5: {atyp}")
        _recv_exact(sock, 2)  # BND.PORT
        return sock
    except Exception:
        sock.close()
        raise


def parse_ip_body(body: str) -> str:
    """Достаёт IP из ответа api.ipify.org (первая непустая строка)."""
    for line in body.splitlines():
        match = _IP_RE.match(line)
        if match:
            return match.group(1)
    return ""


def _tunnel_ip(socks_port: int, timeout: float) -> str:
    sock = _socks5_connect(IP_HOST, 443, socks_port, timeout)
    context = ssl.create_default_context()
    with context.wrap_socket(sock, server_hostname=IP_HOST) as tls:
        request = (
            f"GET {IP_PATH} HTTP/1.1\r\n"
            f"Host: {IP_HOST}\r\n"
            f"User-Agent: {_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        tls.sendall(request)
        data = b""
        while len(data) < 8192:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
    return parse_ip_body(data.decode("utf-8", errors="replace").split("\r\n\r\n", 1)[-1])


def direct_ip(timeout: float = 6.0) -> str:
    """Реальный IP машины без прокси (игнорирует proxy-переменные окружения)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"https://{IP_HOST}{IP_PATH}", timeout=timeout) as response:
            return parse_ip_body(response.read(2048).decode("utf-8", errors="replace"))
    except Exception:
        return ""


def check(socks_port: int, real_ip: str = "", timeout: float = 8.0) -> HealthResult:
    """Проверяет работоспособность исходящего SOCKS-прокси."""
    try:
        ip = _tunnel_ip(int(socks_port), timeout)
    except Exception as exc:
        return HealthResult(False, error=f"{type(exc).__name__}: {exc}")
    if not ip:
        return HealthResult(False, error="пустой ответ сервера IP")
    if real_ip and ip == real_ip:
        return HealthResult(False, ip=ip, error="выход совпадает с реальным IP", intercepted=True)
    return HealthResult(True, ip=ip)
