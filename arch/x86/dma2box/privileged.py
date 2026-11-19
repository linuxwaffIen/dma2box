#!/usr/bin/env python3
"""Привилегированный helper для TUN-режима sing-box.

Запускается через pkexec, держит root-процесс sing-box и пишет его лог.
sing-box сам создаёт tun0, ставит маршруты и redirect-правила (auto_route,
auto_redirect), поэтому helper не трогает ip rule, таблицы маршрутизации и
фаервол. Команды принимаются только от запустившего пользователя и только по
фиксированным путям.
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import re
import os
import pwd
import signal
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ALLOWED_ROOT_KEYS = {"log", "dns", "inbounds", "outbounds", "route"}


def _log_tail(path: Path, limit: int = 16000) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            return handle.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _pdeathsig() -> None:  # pragma: no cover - runs in the forked child
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
    except Exception:
        pass


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


class Runner:
    def __init__(self, core: Path, config: Path, log_path: Path, uid: int, gid: int) -> None:
        self.core = core
        self.config = config
        self.log_path = log_path
        self.uid = uid
        self.gid = gid
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.runtime_dir = Path("/run/dma2box") / str(uid)
        self.staged_config: Path | None = None

    def _stage_config(self) -> Path:
        """Скопировать сгенерированный JSON в закрытый root-каталог /run/dma2box."""
        parent = Path("/run/dma2box")
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise OSError("/run/dma2box должен принадлежать root и не быть доступен для записи группе")
        self.runtime_dir.mkdir(mode=0o700, exist_ok=True)
        runtime_stat = self.runtime_dir.stat()
        if runtime_stat.st_uid != 0 or runtime_stat.st_mode & 0o077:
            raise OSError("Каталог runtime-конфига должен быть закрыт и принадлежать root")
        fd = os.open(self.config, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid not in (self.uid, 0):
                raise OSError("Конфиг должен быть обычным файлом пользователя")
            chunks = []
            remaining = 2 * 1024 * 1024
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining == 0 and os.read(fd, 1):
                raise OSError("Конфиг sing-box превышает 2 MiB")
        finally:
            os.close(fd)
        raw = b"".join(chunks)
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OSError(f"Некорректный JSON конфига: {exc}") from exc
        if not isinstance(parsed, dict):
            raise OSError("Корень конфига sing-box должен быть объектом")
        if set(parsed) - ALLOWED_ROOT_KEYS:
            raise OSError("В конфиге есть неподдерживаемые root-параметры")
        # Пути к файлам обрабатывал бы root — запрещаем их в конфиге.
        if isinstance(parsed.get("log"), dict) and parsed["log"].get("output"):
            raise OSError("В конфиге запрещено поле log.output (запись файла от root)")
        fd, name = tempfile.mkstemp(prefix="config-", suffix=".json", dir=self.runtime_dir)
        staged = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        self.staged_config = staged
        return staged

    def _cleanup_config(self) -> None:
        if self.staged_config is not None:
            try:
                self.staged_config.unlink()
            except OSError:
                pass
            self.staged_config = None

    def status(self) -> dict:
        with self.lock:
            proc = self.proc
            running = bool(proc and proc.poll() is None)
            if proc is not None and not running:
                self._cleanup_config()
            return {
                "ok": True,
                "running": running,
                "pid": proc.pid if running and proc else None,
                "returncode": None if running or not proc else proc.returncode,
                "log": _log_tail(self.log_path),
            }

    def start(self) -> dict:
        with self.lock:
            self._stop_locked()
            try:
                config = self._stage_config()
            except (OSError, ValueError) as exc:
                self._cleanup_config()
                return {"ok": False, "error": f"Не удалось подготовить root-конфиг: {exc}"}
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(
                    self.log_path,
                    os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                    0o644,
                )
                os.fchmod(fd, 0o644)
                os.fchown(fd, self.uid, self.gid)
                log_info = os.fstat(fd)
                if not stat.S_ISREG(log_info.st_mode) or log_info.st_uid != self.uid or log_info.st_nlink != 1:
                    os.close(fd)
                    raise OSError("Лог должен быть обычным файлом пользователя без hard link")
                log_handle = os.fdopen(fd, "wb", buffering=0)
            except OSError as exc:
                self._cleanup_config()
                return {"ok": False, "error": f"Не удалось открыть лог: {exc}"}

            try:
                self.proc = subprocess.Popen(
                    [str(self.core), "run", "-c", str(config)],
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    preexec_fn=_pdeathsig,
                    env={
                        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "HOME": "/root",
                        "LANG": "C.UTF-8",
                    },
                )
            except OSError as exc:
                log_handle.close()
                self._cleanup_config()
                return {"ok": False, "error": f"Не удалось запустить sing-box: {exc}"}
            finally:
                try:
                    log_handle.close()
                except Exception:
                    pass

            # Даём sing-box время поднять TUN и установить маршруты.
            time.sleep(1.0)
            code = self.proc.poll()
            if code is not None:
                tail = _log_tail(self.log_path)
                self.proc = None
                self._cleanup_config()
                return {
                    "ok": False,
                    "error": f"sing-box завершился с кодом {code}",
                    "log": tail,
                }
            return {
                "ok": True,
                "running": True,
                "pid": self.proc.pid,
                "log": _log_tail(self.log_path),
            }

    def stop(self) -> dict:
        with self.lock:
            self._stop_locked()
            return {"ok": True, "running": False, "log": _log_tail(self.log_path)}

    def _stop_locked(self) -> None:
        proc = self.proc
        self.proc = None
        if not proc or proc.poll() is not None:
            self._cleanup_config()
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            try:
                proc.terminate()
            except OSError:
                pass
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                self._cleanup_config()
                return
            time.sleep(0.1)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        self._cleanup_config()


def _run_command(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=15)


def _router_detect() -> tuple[str, list[str]]:
    """Возвращает (WAN-интерфейс, LAN-подсети) для NAT роутера."""
    routes = _run_command(["ip", "-4", "route", "show", "default"])
    match = re.search(r"\bdev\s+(\S+)", routes.stdout)
    if not match:
        raise RuntimeError("не найден интерфейс с маршрутом по умолчанию")
    wan = match.group(1)
    addresses = _run_command(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    subnets: list[str] = []
    for line in addresses.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[1] == wan:
            continue
        try:
            subnet = str(ipaddress.ip_network(fields[3], strict=False))
        except ValueError:
            continue
        if subnet not in subnets:
            subnets.append(subnet)
    return wan, subnets


def _router_apply(wan: str, subnets: list[str]) -> list[list[str]]:
    """Включает ip_forward и MASQUERADE. Возвращает команды для отката."""
    undo: list[list[str]] = []
    before = _run_command(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip()
    _run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    undo.append(["sysctl", "-w", f"net.ipv4.ip_forward={before}"])

    iptables = shutil.which("iptables")
    if iptables:
        for subnet in subnets:
            rule = [
                "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", wan,
                "-j", "MASQUERADE", "-m", "comment", "--comment", "dma2box-router",
            ]
            # -C проверяет то же правило, что и -A
            check = ["-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", wan,
                     "-j", "MASQUERADE", "-m", "comment", "--comment", "dma2box-router"]
            if _run_command([iptables, *check]).returncode == 0:
                continue
            result = _run_command([iptables, *rule])
            if result.returncode != 0:
                raise RuntimeError(f"iptables: {result.stderr.strip()[:180]}")
            undo.append([iptables, "-t", "nat", "-D", "POSTROUTING", "-s", subnet,
                         "-o", wan, "-j", "MASQUERADE", "-m", "comment",
                         "--comment", "dma2box-router"])
        return undo

    nft = shutil.which("nft")
    if not nft:
        raise RuntimeError("ни iptables, ни nft не найдены — NAT недоступен")
    _run_command([nft, "delete", "table", "inet", "dma2box_router"])
    commands = [
        [nft, "add", "table", "inet", "dma2box_router"],
        [nft, "add", "chain", "inet", "dma2box_router", "postrouting",
         "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}"],
    ]
    for subnet in subnets:
        commands.append([nft, "add", "rule", "inet", "dma2box_router", "postrouting",
                         "ip", "saddr", subnet, "oifname", wan, "masquerade"])
    for command in commands:
        result = _run_command(command)
        if result.returncode != 0:
            raise RuntimeError(f"nft: {result.stderr.strip()[:180]}")
    return [[nft, "delete", "table", "inet", "dma2box_router"], *undo]


def _router_undo(commands: list[list[str]]) -> None:
    for command in reversed(commands):
        try:
            _run_command(command)
        except (OSError, subprocess.SubprocessError):
            pass


class Helper:
    def __init__(self, args: argparse.Namespace) -> None:
        self.socket_path = Path(args.socket)
        self.uid = int(args.uid)
        self.gid = int(args.gid)
        self.runner = Runner(Path(args.core), Path(args.config), Path(args.log), self.uid, self.gid)
        self.server: socket.socket | None = None
        self.stop_event = threading.Event()
        self._router_undo_commands: list[list[str]] = []
        self._validate_paths()

    def _validate_paths(self) -> None:
        helper_info = Path(__file__).stat()
        if helper_info.st_uid != 0 or helper_info.st_mode & 0o022:
            raise SystemExit("privileged.py должен принадлежать root и быть недоступен для записи группе/остальным")
        try:
            home = Path(pwd.getpwuid(self.uid).pw_dir)
        except KeyError:
            home = Path("/root")
        core = self.runner.core
        if not core.is_file() or not os.access(core, os.X_OK):
            raise SystemExit(f"sing-box не найден или не исполняемый: {core}")
        binary_info = core.stat()
        if binary_info.st_uid != 0 or binary_info.st_mode & 0o022:
            raise SystemExit("Root может запускать только root-owned sing-box, недоступный для записи группе/остальным")
        allowed_roots = [
            Path("/usr/libexec/dma2box"),
            Path("/usr/lib/dma2box"),
            Path("/usr/local/lib/dma2box"),
        ]
        if not any(_under(core, root) for root in allowed_roots):
            raise SystemExit(f"sing-box должен быть установлен в root-owned каталог приложения: {core}")
        if not _under(self.runner.config, home):
            raise SystemExit("Конфиг должен находиться в домашнем каталоге пользователя")
        if not _under(self.runner.log_path, home):
            raise SystemExit("Лог должен находиться в домашнем каталоге пользователя")

    @staticmethod
    def _network_diagnostics() -> dict:
        """Только чтение: снимок маршрутов, правил и слушателей для диагностики."""
        commands = {
            "ipv4_routes": ["ip", "-4", "route", "show", "table", "all"],
            "ipv6_routes": ["ip", "-6", "route", "show", "table", "all"],
            "ipv4_route_probe": ["ip", "-4", "route", "get", "1.1.1.1"],
            "ipv6_route_probe": ["ip", "-6", "route", "get", "2606:4700:4700::1111"],
            "rules": ["ip", "rule", "list"],
            "ipv6_rules": ["ip", "-6", "rule", "list"],
            "nftables": ["nft", "-a", "list", "ruleset"],
            "iptables_nat": ["iptables", "-t", "nat", "-S"],
            "iptables_filter": ["iptables", "-t", "filter", "-S"],
            "iptables_mangle": ["iptables", "-t", "mangle", "-S"],
            "iptables_raw": ["iptables", "-t", "raw", "-S"],
            "ip6tables_nat": ["ip6tables", "-t", "nat", "-S"],
            "ip6tables_filter": ["ip6tables", "-t", "filter", "-S"],
            "ip6tables_mangle": ["ip6tables", "-t", "mangle", "-S"],
            "ip6tables_raw": ["ip6tables", "-t", "raw", "-S"],
            "dns_listeners": ["ss", "-lnptu"],
            "dns_socket_owner": ["lsof", "-nP", "-i", ":53"],
        }
        result: dict[str, str] = {}
        for name, command in commands.items():
            executable = shutil.which(command[0], path="/usr/sbin:/usr/bin:/sbin:/bin")
            if not executable:
                result[name] = "(команда не установлена)"
                continue
            try:
                proc = subprocess.run(
                    [executable, *command[1:]],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
                )
                output = proc.stdout.strip()
                error = proc.stderr.strip()
                if proc.returncode and error:
                    output = f"{output}\n[exit {proc.returncode}] {error}".strip()
                result[name] = output[:24000] or "(пусто)"
            except (OSError, subprocess.TimeoutExpired) as exc:
                result[name] = f"(ошибка: {exc})"
        try:
            result["resolv_conf"] = Path("/etc/resolv.conf").read_text()[:4000]
        except OSError as exc:
            result["resolv_conf"] = f"(ошибка: {exc})"
        return {"ok": True, "diagnostics": result}

    def run(self) -> int:
        if self.socket_path.parent != Path("/run/dma2box") or self.socket_path.name != f"privileged-{self.uid}.sock":
            raise SystemExit("Сокет helper должен находиться в /run/dma2box")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        parent_info = self.socket_path.parent.stat()
        if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise SystemExit("/run/dma2box должен принадлежать root и не быть доступен для записи группе")
        try:
            old = self.socket_path.lstat()
        except FileNotFoundError:
            old = None
        if old is not None:
            if not stat.S_ISSOCK(old.st_mode) or old.st_uid not in (0, self.uid):
                raise SystemExit("Отказ удалять неизвестный объект по пути privileged socket")
            self.socket_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server = server
        server.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        try:
            os.chown(self.socket_path, self.uid, self.gid)
        except OSError:
            pass
        server.listen(2)
        server.settimeout(1.0)
        try:
            while not self.stop_event.is_set():
                try:
                    client, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                try:
                    self._handle_client(client)
                finally:
                    try:
                        client.close()
                    except OSError:
                        pass
                # Приложение держит одно долгоживущее соединение. Когда оно
                # закрылось, приложение ушло — не оставляем root-процесс.
                break
        finally:
            self._router_stop()
            self.runner.stop()
            try:
                server.close()
            except OSError:
                pass
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
        return 0

    def _router_start(self) -> dict:
        if self._router_undo_commands:
            return {"ok": True, "already": True}
        try:
            wan, subnets = _router_detect()
            if not subnets:
                return {"ok": False, "error": "LAN-подсети не найдены"}
            self._router_undo_commands = _router_apply(wan, subnets)
            return {"ok": True, "wan": wan, "subnets": subnets}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _router_stop(self) -> dict:
        if self._router_undo_commands:
            _router_undo(self._router_undo_commands)
            self._router_undo_commands = []
        return {"ok": True}

    def _handle_client(self, client: socket.socket) -> None:
        try:
            creds = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
        except OSError:
            return
        if uid not in (self.uid, 0):
            self._send(client, {"ok": False, "error": "Недостаточно прав"})
            return

        reader = client.makefile("rb")
        try:
            for raw in reader:
                if self.stop_event.is_set():
                    break
                try:
                    message = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    self._send(client, {"ok": False, "error": "Некорректная команда"})
                    continue
                command = message.get("cmd")
                try:
                    if command == "start":
                        response = self.runner.start()
                    elif command == "stop":
                        response = self.runner.stop()
                    elif command == "status":
                        response = self.runner.status()
                    elif command == "inspect-network":
                        response = self._network_diagnostics()
                    elif command == "router-start":
                        response = self._router_start()
                    elif command == "router-stop":
                        response = self._router_stop()
                    elif command == "shutdown":
                        self.runner.stop()
                        self._send(client, {"ok": True, "running": False})
                        self.stop_event.set()
                        return
                    else:
                        response = {"ok": False, "error": "Неизвестная команда"}
                except Exception as exc:  # helper живёт дальше после ошибок команды
                    response = {"ok": False, "error": f"Внутренняя ошибка: {exc}"}
                self._send(client, response)
        finally:
            try:
                reader.close()
            except Exception:
                pass

    @staticmethod
    def _send(client: socket.socket, payload: dict) -> None:
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            client.sendall(data)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Privileged sing-box helper for dma2box")
    parser.add_argument("--inspect-network", action="store_true")
    parser.add_argument("--socket")
    parser.add_argument("--core")
    parser.add_argument("--config")
    parser.add_argument("--log")
    parser.add_argument("--uid")
    parser.add_argument("--gid")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print("privileged helper must run as root", file=sys.stderr)
        return 1

    if args.inspect_network:
        print(json.dumps(Helper._network_diagnostics(), ensure_ascii=False))
        return 0

    missing = [name for name in ("socket", "core", "config", "log", "uid", "gid") if not getattr(args, name)]
    if missing:
        parser.error("missing required arguments: " + ", ".join("--" + name for name in missing))

    helper = Helper(args)

    def on_signal(_signum, _frame):
        helper.stop_event.set()
        helper.runner.stop()
        try:
            helper.socket_path.unlink()
        except OSError:
            pass
        os._exit(0)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    return helper.run()


if __name__ == "__main__":
    raise SystemExit(main())
