"""Автоматическая подготовка окружения TUN-режима «из коробки».

Что делает при включении режима ВПН/Роутер:
  1. скачивает пользовательский sing-box, если его нет (installer.install_core);
  2. через pkexec запускает priv_setup.py, который ставит в /usr/libexec/dma2box
     root-копию ядра,	priv-хелпер и polkit-политику;
  3. пароль администратора запрашивает GUI-диалогом (ask_password) и
     подаёт в pkexec по pty — так же, как это делает CoreManager.

Переиспользует из core.py проверенные детали: поиск ядра (find_core),
пути root-компонентов и pty-хелперы подсказки пароля.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from . import installer, paths
from .core import (
    SYSTEM_CORE,
    SYSTEM_HELPER,
    CoreError,
    CoreManager,
    _clean_prompt,
    _close_fd,
    _looks_like_password_prompt,
    _PtyProcess,
    _read_pty,
    find_core,
    pty,
)
from .state import Store

TUN_DEVICE = Path("/dev/net/tun")
SETUP_LOG = paths.CACHE_DIR / "priv-setup.log"

AskPassword = Callable[[str], str | None]
OnStatus = Callable[[str], None]


class TunSetupError(RuntimeError):
    """Ошибка автоматической подготовки TUN-режима."""


@dataclass(frozen=True)
class TunCheck:
    key: str
    title: str
    ok: bool
    fix: bool = False  # можно ли починить автоматически


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


_same_memo: dict[tuple[str, str], tuple[tuple[int, int, int, int], bool]] = {}


def _same_file(a: Path, b: Path) -> bool:
    """Сравнение содержимого с memo по (размер, mtime): сравнение ядер
    происходит по клику «Подключить» и не должно хешировать сотни МБ
    каждый раз."""
    try:
        sa, sb = Path(a).stat(), Path(b).stat()
    except OSError:
        return False
    if sa.st_size != sb.st_size:
        return False
    fingerprint = (sa.st_size, sb.st_size, sa.st_mtime_ns, sb.st_mtime_ns)
    key = (str(a), str(b))
    memo = _same_memo.get(key)
    if memo is not None and memo[0] == fingerprint:
        return memo[1]
    result = _sha256(a) == _sha256(b)
    _same_memo[key] = (fingerprint, result)
    return result


def _tun_device_available() -> bool:
    try:
        return TUN_DEVICE.exists() and os.access(TUN_DEVICE, os.R_OK | os.W_OK)
    except OSError:
        return False


def readiness(store: Store) -> list[TunCheck]:
    """Снимок готовности TUN; вызывается и в UI-потоке — без тяжёлых работ."""
    root_run = getattr(os, "geteuid", lambda: 0)() == 0
    core = find_core(store)
    checks = [
        TunCheck(
            "core",
            "Ядро sing-box (скачивается автоматически)",
            core is not None,
            True,
        ),
        TunCheck(
            "polkit",
            "Механизм авторизации pkexec (polkit)",
            root_run or shutil.which("pkexec") is not None,
            False,
        ),
        TunCheck(
            "tun-device",
            "Устройство /dev/net/tun",
            _tun_device_available(),
            False,
        ),
    ]
    system_ok = SYSTEM_HELPER.is_file() and SYSTEM_CORE.is_file()
    checks.append(
        TunCheck(
            "system",
            "Системный компонент TUN: root-хелпер и root-ядро",
            system_ok,
            True,
        )
    )
    if system_ok:
        # _same_file сам гасит OSError (возвращает False) — отдельный
        # try/except не нужен, значение всегда определено.
        in_sync = core is not None and _same_file(core, SYSTEM_CORE)
        checks.append(
            TunCheck(
                "core-sync",
                "Root-ядро совпадает с пользовательским",
                in_sync,
                True,
            )
        )
    else:
        # Появится вместе с системным компонентом — отдельная работа не нужна.
        checks.append(
            TunCheck("core-sync", "Root-ядро совпадает с пользовательским", True, True)
        )
    return checks


def problems(checks: list[TunCheck]) -> str:
    return "; ".join(check.title for check in checks if not check.ok)


def needs_setup(store: Store) -> bool:
    """Быстрая проверка для UI: нужна ли подготовка TUN перед запуском."""
    return any(not check.ok for check in readiness(store))


def setup_command(core: Path, priv: Path, python_bin: str) -> list[str]:
    """Команда установки root-компонентов: pkexec-обёртка над priv_setup."""
    script = paths.PRIV_SETUP_SCRIPT
    if not script.is_file():
        raise TunSetupError(f"Не найден скрипт установки: {script}")
    base = [
        python_bin,
        str(script),
        "install",
        "--core",
        str(core),
        "--priv",
        str(priv),
    ]
    if getattr(os, "geteuid", lambda: 0)() == 0:
        # Приложение уже запущено от root (sudo) — pkexec не нужен.
        return base
    pkexec = shutil.which("pkexec")
    if not pkexec:
        raise TunSetupError(
            "Не найден pkexec — установите пакет polkit и его агент\N{HORIZONTAL ELLIPSIS}"
        )
    return [pkexec, *base]


def _tail(path: Path, limit: int = 4000) -> str:
    try:
        with Path(path).open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            return handle.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _drive_tty(
    proc: _PtyProcess,
    master: int,
    ask_password: AskPassword | None,
    log_handle,
    timeout: float,
) -> tuple[int, str]:
    """Живёт рядом с pkexec-процессом: лог, подсказки пароля, дедлайн."""
    deadline = time.monotonic() + timeout
    prompt_buffer = b""
    redact = b""
    code = proc.poll()
    while code is None and time.monotonic() < deadline:
        chunk = _read_pty(master, 0.25)
        if chunk:
            masked = chunk.replace(redact, b"***") if redact else chunk
            log_handle.write(masked)
            prompt_buffer = (prompt_buffer + masked)[-4000:]
            if _looks_like_password_prompt(prompt_buffer):
                password = ask_password(_clean_prompt(prompt_buffer)) if ask_password else None
                if not password:
                    proc.terminate()
                    return 130, "Авторизация отменена"
                redact = password.encode("utf-8")
                try:
                    os.write(master, redact + b"\n")
                except OSError as exc:
                    raise TunSetupError(f"Не удалось передать пароль: {exc}") from exc
                prompt_buffer = b""
        code = proc.poll()
    if code is None:
        proc.terminate()
        return -1, "Истекло время ожидания авторизации"
    while True:
        chunk = _read_pty(master, 0.2)
        if not chunk:
            break
        log_handle.write(chunk.replace(redact, b"***") if redact else chunk)
    return code, _tail(log_handle.name)


def run_setup(
    command: list[str],
    *,
    ask_password: AskPassword | None,
    log_path: Path = SETUP_LOG,
    timeout: float = 300.0,
) -> tuple[int, str]:
    """Запускает установку root-компонентов, возвращает (код, хвост лога)."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    tty_mode = pty is not None and getattr(os, "geteuid", lambda: 0)() != 0
    if not tty_mode:
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise TunSetupError("Установка системного компонента не ответила") from exc
        except OSError as exc:
            raise TunSetupError(f"Не удалось запустить установку: {exc}") from exc
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        with contextlib.suppress(OSError), log_path.open("ab") as handle:
            handle.write(output.encode("utf-8", "replace"))
        return proc.returncode, output

    # pty-подъём через единый проверенный спаунер core.py: fork+exec
    # живёт в одном месте (CoreManager._popen_tty).
    try:
        proc_raw, master = CoreManager._popen_tty(command)
    except CoreError as exc:
        raise TunSetupError(str(exc)) from exc
    proc = cast(_PtyProcess, proc_raw)
    try:
        with log_path.open("ab", buffering=0) as log_handle:
            return _drive_tty(proc, master, ask_password, log_handle, timeout)
    finally:
        _close_fd(master)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                # Процесс мог завершиться параллельно (waitpid-гонка) —
                # _PtyProcess.kill сам глушит OSError, чистка безопасна.
                proc.kill()


def _report(callback: OnStatus | None, text: str) -> None:
    """Сообщает этап подготовки; исключения ловит слой-запуска,
    чтобы сбой "статуса" не замаскировал реальную ошибку установки."""
    if callback is None:
        return
    callback(text)


def ensure_ready(
    store: Store,
    ask_password: AskPassword | None,
    on_status: OnStatus | None = None,
) -> list[TunCheck]:
    """Доводит окружение до рабочего TUN, возвращает неустранённые пункты.

    Вызывается из фонового потока окна; тяжёлые операции (скачивание,
    установка) — здесь, а не в UI-потоке.
    """
    checks = readiness(store)
    if any(not check.ok and not check.fix for check in checks):
        # pkexec/tun-device из приложения не чинятся — только руками.
        return checks

    core = find_core(store)
    if core is None:
        _report(on_status, "Скачиваю ядро sing-box…")
        try:
            installer.install_core()
        except Exception as exc:
            raise TunSetupError(f"Не удалось скачать ядро sing-box: {exc}") from exc
        core = find_core(store)
        if core is None:
            return [check for check in readiness(store) if not check.ok]

    pending = readiness(store)
    if any(check.key in ("system", "core-sync") and not check.ok for check in pending):
        priv = paths.PRIV_SCRIPT
        if not priv.is_file():
            raise TunSetupError(f"Не найден privileged-скрипт: {priv}")
        _report(on_status, "Устанавливаю системный компонент TUN (нужен пароль)…")
        command = setup_command(core, priv, paths.python_bin())
        code, tail = run_setup(command, ask_password=ask_password)
        if code != 0:
            message = f"Установка системного компонента не удалась (код {code})"
            raise TunSetupError(f"{message}\n{tail}" if tail else message)

    return [check for check in readiness(store) if not check.ok]
