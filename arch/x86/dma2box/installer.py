from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from . import paths

RELEASES_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
LATEST_URL = "https://github.com/SagerNet/sing-box/releases/latest"
DOWNLOAD_BASE = "https://github.com/SagerNet/sing-box/releases/download"
USER_AGENT = "dma2box/0.3"

# Статическая musl-сборка работает и на glibc, и на musl, поэтому берём её
# для всех архитектур — без проверки локального libc.
TARGET_ARCH = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "x86": "386",
    "i386": "386",
    "i486": "386",
    "i586": "386",
    "i686": "386",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv5l": "armv5",
    "armv6l": "armv6",
    "armv7l": "armv7",
    "armv7": "armv7",
    "arm": "armv7",
    "aarch32": "armv7",
    "armhf": "armv7",
    "riscv64": "riscv64",
    "loongarch64": "loong64",
}
SUPPORTED_ARCHS = frozenset(TARGET_ARCH)

Progress = Callable[[float, str], None]


def current_arch() -> str:
    return platform.machine().lower()


def target_arch(arch: str | None = None) -> str:
    machine = (arch or current_arch()).lower()
    target = TARGET_ARCH.get(machine)
    if not target:
        raise RuntimeError(f"Нет сборки sing-box для архитектуры {machine}")
    return target


def asset_name(arch: str | None = None, version: str = "{version}") -> str:
    """Имя ассета. По умолчанию — шаблон для отображения в интерфейсе."""
    return f"sing-box-{version}-linux-{target_arch(arch)}-musl.tar.gz"


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
    )


def _download(url: str, destination: Path, progress: Progress | None) -> None:
    with urllib.request.urlopen(_request(url), timeout=60) as response:
        total = int(response.headers.get("Content-Length") or 0)
        downloaded = 0
        with destination.open("wb") as handle:
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                downloaded += len(chunk)
                if progress:
                    fraction = (downloaded / total) if total else 0.0
                    progress(min(fraction, 0.95), "Скачивание sing-box…")
        if total and downloaded != total:
            raise RuntimeError("Загрузка прервана")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _release_info() -> tuple[str, dict[str, dict] | None]:
    """Версия и данные ассетов. None вместо ассетов — если GitHub API недоступен."""
    try:
        with urllib.request.urlopen(_request(RELEASES_API), timeout=30) as response:
            data = json.load(response)
        tag = str(data.get("tag_name") or "")
        version = tag.lstrip("v")
        if not version:
            raise ValueError("В ответе GitHub нет версии релиза")
        assets = {
            str(item["name"]): item
            for item in data.get("assets", [])
            if isinstance(item, dict) and item.get("name")
        }
        return version, assets
    except (urllib.error.URLError, ValueError, TypeError, KeyError):
        # GitHub API может быть недоступен (лимит запросов). Берём версию из
        # перенаправления /releases/latest — без контрольной суммы ассета.
        try:
            with urllib.request.urlopen(_request(LATEST_URL), timeout=30) as response:
                final_url = response.geturl()
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Не удалось получить данные о релизе sing-box: {exc}") from exc
        match = re.search(r"/tag/v?([0-9][0-9A-Za-z.\-]*)", final_url)
        if not match:
            raise RuntimeError("Не удалось определить версию sing-box")
        return match.group(1), None


def install_core(
    progress: Progress | None = None, arch: str | None = None, kernel_type: str = "sing-box"
) -> Path:
    machine = arch or current_arch()
    version, assets = _release_info()
    asset = asset_name(machine, version)
    if progress:
        progress(0.02, f"Загрузка {asset}…")

    info = (assets or {}).get(asset)
    if info and info.get("browser_download_url"):
        url = str(info["browser_download_url"])
    else:
        url = f"{DOWNLOAD_BASE}/v{version}/{asset}"
    if progress and not assets:
        progress(0.03, "GitHub API недоступен — контрольная сумма не проверяется")

    target_dir = paths.core_dir(machine)
    target_path = paths.core_path(machine)
    target_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dma2box-core-", dir=str(paths.CACHE_DIR)) as tmp:
        tmpdir = Path(tmp)
        archive = tmpdir / asset
        _download(url, archive, progress)

        digest = str((info or {}).get("digest") or "")
        if digest.startswith("sha256:"):
            if progress:
                progress(0.96, "Проверка контрольной суммы…")
            expected = digest.split(":", 1)[1].strip().lower()
            actual = _sha256(archive)
            if actual != expected:
                raise RuntimeError(
                    f"Контрольная сумма не совпала: ожидалось {expected[:12]}…, "
                    f"получено {actual[:12]}…"
                )

        try:
            with tarfile.open(archive, "r:gz") as bundle:
                members = [
                    member for member in bundle.getmembers()
                    if member.isfile() and Path(member.name).name == "sing-box"
                ]
                if not members:
                    raise RuntimeError(f"В архиве {asset} нет бинарника sing-box")
                source = bundle.extractfile(members[0])
                if source is None:
                    raise RuntimeError("Не удалось прочитать бинарник из архива")
                staged = target_dir / ".sing-box.new"
                with source, staged.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
        except tarfile.TarError as exc:
            raise RuntimeError(f"Некорректный архив sing-box: {exc}") from exc

        staged.chmod(0o755)
        os.replace(staged, target_path)

    if progress:
        progress(1.0, "sing-box установлен")
    return target_path
