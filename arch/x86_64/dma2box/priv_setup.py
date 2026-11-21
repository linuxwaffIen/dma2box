#!/usr/bin/env python3
"""Установка и удаление root-компонентов TUN-режима Dma2box.

Кладёт в /usr/libexec/dma2box:
  * sing-box       — root-owned копия пользовательского бинарника ядра;
  * priv.py        — привилегированный helper (копия dma2box/privileged.py);
  * dma2box-helper — обёртка, запускающая priv.py системным python3,
и polkit-политику /usr/share/polkit-1/actions/org.dma2box.run-core.policy.

Запускается из приложения через pkexec (см. dma2box/tun_setup.py), поэтому
модуль намеренно не тянет ничего из пакета dma2box: pkexec поднимает его
как обычный скрипт, вне контекста пакета. Функции установки принимают
каталоги параметрами, чтобы юнит-тесты могли работать без root.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import shutil
import stat
import sys
from pathlib import Path

LIBEXEC_DIR = Path("/usr/libexec/dma2box")
POLICY_PATH = Path("/usr/share/polkit-1/actions/org.dma2box.run-core.policy")
HELPER_NAME = "dma2box-helper"
CORE_NAME = "sing-box"
PRIV_NAME = "priv.py"
MAX_CORE_SIZE = 256 * 1024 * 1024

HELPER_TEMPLATE = "#!/bin/sh\nexec {python} {priv} \"$@\"\n"

# Дублирует политику из install.sh (install_system_helper): приложение и
# системная установка должны ставить идентичные права.
POLICY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Dma2box</vendor>
  <action id="org.dma2box.run-core">
    <description>Запуск ядра Dma2box в режиме ВПН</description>
    <message>Для режима ВПН (TUN) нужны права администратора</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/libexec/dma2box/dma2box-helper</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">false</annotate>
  </action>
</policyconfig>
"""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_regular(path: Path, *, executable: bool = False, max_size: int = 0) -> None:
    """Проверка «снимка» файла: не симлинк, обычный, не пустой и не гигант."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError(f"Ожидается абсолютный путь: {path}")
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"Файл недоступен: {path} ({exc})") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"Символьные ссылки не разрешены: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Ожидается обычный файл: {path}")
    if info.st_size == 0:
        raise ValueError(f"Файл пуст: {path}")
    if max_size and info.st_size > max_size:
        raise ValueError(
            f"Файл подозрительно велик ({info.st_size} байт): {path}"
        )
    if executable:
        try:
            executable_ok = os.access(path, os.X_OK)
        except OSError as exc:
            raise ValueError(f"Файл недоступен: {path} ({exc})") from exc
        if not executable_ok:
            raise ValueError(f"Файл не исполняется: {path}")


def _staged_write(target: Path, mode: int, data: bytes | None, source: Path | None) -> None:
    """Копирует source или пишет data во временный файл рядом с target.

    Временный файл создаётся с нужными правами и владельцем root, затем
    атомарно переименовывается — на месте всегда остаётся либо старый,
    либо новый полный файл.
    """
    tmp = target.with_name(target.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            if source is not None:
                with Path(source).open("rb") as src:
                    shutil.copyfileobj(src, handle, 1024 * 1024)
            else:
                if data is None:
                    raise ValueError(f"В _staged_write нужен source или data: {target}")
                handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        # chown-root только под root: install_components гоняют и юнит-тесты
        # (بدون привилегий), где chown(0,0) запрещён.
        if os.geteuid() == 0:
            os.chown(tmp, 0, 0)
        os.replace(tmp, target)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def install_components(
    core: Path,
    priv: Path,
    *,
    libexec_dir: Path = LIBEXEC_DIR,
    policy_path: Path = POLICY_PATH,
    python_bin: str | None = None,
) -> dict:
    """Устанавливает/обновляет root-компоненты. Идемпотентен."""
    core, priv = Path(core), Path(priv)
    _require_regular(core, executable=True, max_size=MAX_CORE_SIZE)
    _require_regular(priv, max_size=4 * 1024 * 1024)
    python = python_bin or shutil.which("python3") or sys.executable
    libexec_dir.mkdir(parents=True, exist_ok=True)
    policy_path.parent.mkdir(parents=True, exist_ok=True)

    _staged_write(libexec_dir / CORE_NAME, 0o755, None, core)
    _staged_write(libexec_dir / PRIV_NAME, 0o755, None, priv)
    _staged_write(
        libexec_dir / HELPER_NAME,
        0o755,
        HELPER_TEMPLATE.format(python=python, priv=libexec_dir / PRIV_NAME).encode(),
        None,
    )
    _staged_write(
        policy_path,
        0o644,
        POLICY_XML.encode(),
        None,
    )
    return {
        "libexec": str(libexec_dir),
        "policy": str(policy_path),
        # Приложение сверяет эту сумму с пользовательским ядром.
        "core_sha256": sha256_file(libexec_dir / CORE_NAME),
    }


def remove_components(
    *,
    libexec_dir: Path = LIBEXEC_DIR,
    policy_path: Path = POLICY_PATH,
) -> list:
    """Удаляет только файлы, установленные install_components."""
    removed: list[str] = []
    for name in (CORE_NAME, PRIV_NAME, HELPER_NAME):
        target = Path(libexec_dir) / name
        with contextlib.suppress(FileNotFoundError):
            target.unlink()
            removed.append(str(target))
    with contextlib.suppress(FileNotFoundError):
        policy_path.unlink()
        removed.append(str(policy_path))
    with contextlib.suppress(OSError):
        # Каталог не пуст или отсутствует — остальное не трогаем.
        Path(libexec_dir).rmdir()
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="priv_setup",
        description="Установка/удаление root-компонентов TUN-режима Dma2box",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install", help="установить или обновить компоненты")
    install.add_argument("--core", required=True, help="пользовательский бинарник sing-box")
    install.add_argument("--priv", required=True, help=" dma2box/privileged.py из пакета")
    install.add_argument("--libexec-dir", default=str(LIBEXEC_DIR))
    install.add_argument("--policy", default=str(POLICY_PATH))

    remove = sub.add_parser("remove", help="удалить компоненты")
    remove.add_argument("--libexec-dir", default=str(LIBEXEC_DIR))
    remove.add_argument("--policy", default=str(POLICY_PATH))

    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("priv_setup должен запускаться от root (pkexec/sudo)", file=sys.stderr)
        return 1
    try:
        if args.command == "install":
            summary = install_components(
                Path(args.core),
                Path(args.priv),
                libexec_dir=Path(args.libexec_dir),
                policy_path=Path(args.policy),
            )
            print("Установлено:")
            print(f"  ядро:     {summary['libexec']}/{CORE_NAME}")
            print(f"  helper:    {summary['libexec']}/{HELPER_NAME}")
            print(f"  polkit:    {summary['policy']}")
            print(f"  core sha256: {summary['core_sha256']}")
        else:
            removed = remove_components(
                libexec_dir=Path(args.libexec_dir),
                policy_path=Path(args.policy),
            )
            print("Удалено:" if removed else "Нечего удалять.")
            for line in removed:
                print(f"  {line}")
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
