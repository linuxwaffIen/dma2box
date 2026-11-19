"""Xray-core как backend для xhttp-профилей.

sing-box не поддерживает xhttp, поэтому такие профили идут цепочкой:
Xray поднимает локальный SOCKS и говорит с сервером по XHTTP, а sing-box
остаётся фронтендом (TUN, DNS, правила маршрутизации).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path

from . import paths

RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
LATEST_URL = "https://github.com/XTLS/Xray-core/releases/latest"
DOWNLOAD_BASE = "https://github.com/XTLS/Xray-core/releases/download"
FALLBACK_VERSION = "26.11.9"
USER_AGENT = "dma2box/0.3"
Progress = Callable[[float, str], None]

XRAY_ASSETS = {
    "x86_64": "64",
    "amd64": "64",
    "x86": "32",
    "i386": "32",
    "i686": "32",
    "aarch64": "arm64-v8a",
    "arm64": "arm64-v8a",
    "armv7": "armv7",
    "armv7l": "armv7",
    "armhf": "armv7",
}


def needs_xray(profile: object) -> bool:
    return str(getattr(profile, "network", "")).lower() == "xhttp"


def find_xray() -> Path | None:
    for candidate in (
        paths.core_arch_dir() / "xray",
        paths.core_arch_dir() / "xray" / "xray",  # старый layout ядра
        Path("/usr/libexec/dma2box/xray"),
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("xray")
    return Path(found) if found else None


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def build_config(profile: object, socks_port: int) -> dict:
    extra_raw = profile.extra.get("extra") if getattr(profile, "extra", None) else None
    try:
        extra = json.loads(extra_raw) if isinstance(extra_raw, str) else dict(extra_raw or {})
    except (ValueError, TypeError):
        extra = {}
    # xray с xmux на таком сервере уходит в вечный ожидающий GET — убираем.
    extra.pop("xmux", None)

    tls = {
        "serverName": profile.sni or profile.address,
        "fingerprint": profile.fingerprint or "chrome",
    }
    if getattr(profile, "alpn", None):
        tls["alpn"] = list(profile.alpn)
    xhttp: dict = {
        "path": profile.path or "/",
        "host": profile.host_header or profile.address,
        "mode": profile.mode or "auto",
    }
    if extra:
        xhttp["extra"] = extra
    user: dict = {"id": profile.uuid, "encryption": "none"}
    if getattr(profile, "flow", ""):
        user["flow"] = profile.flow
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": int(socks_port),
            "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": profile.address,
                "port": int(profile.port),
                "users": [user],
            }]},
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": tls,
                "xhttpSettings": xhttp,
            },
        }],
    }


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
    )


def _latest_version() -> str:
    try:
        with urllib.request.urlopen(_request(RELEASES_API), timeout=25) as response:
            data = json.load(response)
        tag = str(data.get("tag_name") or "").lstrip("v")
        if tag:
            return tag
    except (urllib.error.URLError, ValueError, TypeError):
        pass
    try:
        with urllib.request.urlopen(_request(LATEST_URL), timeout=25) as response:
            match = re.search(r"/tag/v?([0-9][0-9A-Za-z.\-]*)", response.geturl())
        if match:
            return match.group(1)
    except urllib.error.URLError:
        pass
    return FALLBACK_VERSION


def install_xray_core(progress: Progress | None = None, arch: str | None = None) -> Path:
    """Скачивает Xray-core рядом с sing-box. Возвращает путь к бинарнику."""
    machine = (arch or paths.current_arch()).lower()
    target = XRAY_ASSETS.get(machine)
    if not target:
        raise RuntimeError(f"Нет сборки Xray-core для архитектуры {machine}")
    version = _latest_version()
    asset = f"Xray-linux-{target}.zip"
    url = f"{DOWNLOAD_BASE}/v{version}/{asset}"
    if progress:
        progress(0.05, f"Загрузка {asset}…")
    directory = paths.core_arch_dir()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "xray"
    # Старые версии клали бинарник в каталог xray/xray — не затираем каталог.
    if target.is_dir():
        target = target / "xray"
    staged = target.with_name(".xray.new")
    with tempfile.TemporaryDirectory(
        prefix="dma2box-xray-", dir=str(paths.CACHE_DIR)
    ) as tmp:
        archive = Path(tmp) / asset
        with urllib.request.urlopen(_request(url), timeout=90) as response, archive.open("wb") as out:
            shutil.copyfileobj(response, out)
        if archive.stat().st_size < 1024 * 1024:
            raise RuntimeError(f"Слишком маленький архив Xray-core: {asset}")
        with zipfile.ZipFile(archive) as bundle:
            names = set(bundle.namelist())
            if "xray" not in names:
                raise RuntimeError(f"В архиве {asset} нет бинарника xray")
            with bundle.open("xray") as source, staged.open("wb") as out:
                shutil.copyfileobj(source, out)
            for geo in ("geoip.dat", "geosite.dat"):
                if geo in names:
                    with bundle.open(geo) as source, (target.parent / geo).open("wb") as out:
                        shutil.copyfileobj(source, out)
    staged.chmod(0o755)
    os.replace(staged, target)
    if progress:
        progress(1.0, "Xray-core установлен")
    return target


def launch(binary: Path, config_path: Path, log_path: Path, port: int) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("ab", buffering=0)
    try:
        proc = subprocess.Popen(
            [str(binary), "run", "-c", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        handle.close()
        raise RuntimeError(f"Не удалось запустить Xray-core: {exc}") from exc
    finally:
        try:
            handle.close()
        except Exception:
            pass
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Xray-core завершился с кодом {proc.returncode}")
        sock = socket.socket()
        sock.settimeout(0.2)
        try:
            sock.connect(("127.0.0.1", int(port)))
            return proc
        except OSError:
            time.sleep(0.15)
        finally:
            sock.close()
    proc.terminate()
    raise RuntimeError("Xray-core не открыл локальный SOCKS за 6 секунд")


def stop(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, 15)
    except OSError:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            proc.kill()
