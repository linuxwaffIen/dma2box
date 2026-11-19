"""dmacore — единый слой поверх сетевых ядер dma2box.

База — sing-box. Плюс лучшее из других клиентов:
  * hiddify-core (hiddify-sing-box) — srun, XHTTP/H2/H3, Cronet, MASQUE;
  * Xray-core — XHTTP packet-up с данными в заголовках (обходит лимиты CDN).

Модуль не заменяет ядра бинарно: он выбирает подходящий бэкенд под профиль
и даёт один интерфейс запуска/диагностики для всех архитектур.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import paths, xray


@dataclass(frozen=True)
class Backend:
    name: str
    binary: Path
    mode: str  # run | srun — команда запуска конфига

    def version(self) -> str:
        try:
            result = subprocess.run(
                [str(self.binary), "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        lines = (result.stdout or result.stderr or "").strip().splitlines()
        return lines[0].strip() if lines else ""


def _first_existing(candidates: list[Path]) -> Path | None:
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def available_backends() -> dict[str, Backend]:
    """Находит установленные ядра без запуска внешних команд."""
    result: dict[str, Backend] = {}

    # dmacore — наш форк sing-box, предпочитаем его при наличии.
    fork = _first_existing([
        paths.core_arch_dir() / "dmacore",
        Path("/usr/libexec/dma2box/dmacore"),
    ]) or (Path(shutil.which("dmacore")) if shutil.which("dmacore") else None)
    if fork:
        result["dmacore"] = Backend("dmacore", fork, "run")

    singbox = _first_existing([
        paths.CORE_PATH,
        paths.core_arch_dir() / "sing-box",
        Path("/usr/libexec/dma2box/sing-box"),
    ]) or (Path(shutil.which("sing-box")) if shutil.which("sing-box") else None)
    if singbox:
        result["singbox"] = Backend("singbox", singbox, "run")

    hiddify_env = os.environ.get("DMA2BOX_HIDDIFY_CORE", "")
    hiddify = _first_existing([
        Path(hiddify_env) if hiddify_env else Path("/nonexistent"),
        paths.DATA_DIR / "dmacore" / "hiddify-core",
        Path("/usr/libexec/dma2box/hiddify-core"),
    ]) or (Path(shutil.which("hiddify-core")) if shutil.which("hiddify-core") else None)
    if hiddify:
        result["hiddify"] = Backend("hiddify", hiddify, "srun")

    binary = xray.find_xray()
    if binary:
        result["xray"] = Backend("xray", binary, "run")
    return result


def features() -> tuple[str, ...]:
    names = set(available_backends())
    items = ["tun", "routing", "geoip", "health", "failover"]
    if "xray" in names or "hiddify" in names:
        items.append("xhttp")
    if "hiddify" in names:
        items += ["masque", "h2-h3"]
    return tuple(items)


def choose(profile: object | None = None, prefer: str = "auto") -> str:
    """Выбирает бэкенд: xhttp -> Xray/Hiddify, иначе sing-box."""
    backends = available_backends()
    if profile is not None and xray.needs_xray(profile):
        for candidate in ("xray", "hiddify"):
            if candidate in backends:
                return candidate
    if prefer in backends and prefer != "auto":
        return prefer
    if "dmacore" in backends:
        return "dmacore"
    if "singbox" in backends:
        return "singbox"
    if backends:
        return sorted(backends)[0]
    raise RuntimeError("Не найдено ни одного доступного ядра (sing-box/hiddify/Xray)")


def plan_run(config: Path, backend: str | None = None) -> list[str]:
    """Готовит команду запуска конфига выбранным ядром."""
    backends = available_backends()
    name = backend if backend in backends else choose()
    item = backends[name]
    return [str(item.binary), item.mode, "-c", str(config)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dmacore", description="Унифицированное ядро dma2box")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="список найденных ядер")
    run = sub.add_parser("run", help="запустить конфиг лучшим ядром")
    run.add_argument("-c", "--config", required=True)
    run.add_argument("--backend", default="auto", choices=("auto", "singbox", "hiddify", "xray"))
    args = parser.parse_args(argv)

    if args.command == "list":
        info = {
            name: {"binary": str(item.binary), "mode": item.mode, "version": item.version()}
            for name, item in available_backends().items()
        }
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0
    if args.command == "run":
        command = plan_run(Path(args.config), None if args.backend == "auto" else args.backend)
        os.execv(command[0], command)  # noqa: PLW1509 — заменяем процесс ядром
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
