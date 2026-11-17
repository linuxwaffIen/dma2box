#!/usr/bin/env python3
"""Small privileged helper for Xray TUN mode.

Started through pkexec. It owns the root Xray process, writes its log and
reverts routes by stopping Xray gracefully. It only accepts commands from the
user who started it and only uses paths fixed at startup.
"""

from __future__ import annotations

import argparse
import ctypes
import json
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


TUN_NAME = "tun0"
ROUTE_TABLE = "42424"
XRAY_MARK = "0xd2a2/0xffffffff"
PRIVATE_PREFIXES_V4 = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "224.0.0.0/4", "255.255.255.255/32",
)
PRIVATE_PREFIXES_V6 = ("::1/128", "fc00::/7", "fe80::/10", "ff00::/8")


def _ip_binary() -> str:
    executable = shutil.which("ip", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not executable:
        raise OSError("Не найдена команда ip")
    return executable


def _ip_run(family: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    command = [_ip_binary(), family, *args]
    proc = subprocess.run(
        command, capture_output=True, text=True, timeout=8, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
    )
    if check and proc.returncode:
        raise OSError(f"{' '.join(command)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


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
    def __init__(self, xray: Path, config: Path, log_path: Path, uid: int, gid: int) -> None:
        self.xray = xray
        self.config = config
        self.log_path = log_path
        self.uid = uid
        self.gid = gid
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.runtime_dir = Path("/run/dma2ray") / str(uid)
        self.staged_config: Path | None = None
        self.routing_cleanup: list[tuple[str, ...]] = []

    def _remove_routing(self) -> None:
        commands = list(self.routing_cleanup)
        state_path = self.runtime_dir / "routing-cleanup.json"
        if not commands:
            try:
                directory_info = self.runtime_dir.lstat()
            except FileNotFoundError:
                directory_info = None
            if directory_info is not None and (
                not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != 0
                or directory_info.st_mode & 0o077
            ):
                raise OSError("Небезопасный каталог состояния policy routing")
            try:
                fd = os.open(state_path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                fd = None
            except OSError:
                fd = None
            if fd is not None:
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                        raise OSError("Небезопасный файл состояния policy routing")
                    with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as handle:
                        stored = json.load(handle)
                    if not isinstance(stored, list):
                        raise OSError("Некорректный файл состояния policy routing")
                    commands = [tuple(map(str, item)) for item in stored]
                    for command in commands:
                        if (len(command) < 4 or command[0] not in ("-4", "-6")
                                or command[1:3] not in (("route", "del"), ("rule", "del"))):
                            raise OSError("В файле состояния есть недопустимая команда")
                finally:
                    os.close(fd)
        for command in reversed(commands):
            _ip_run(command[0], *command[1:], check=False)
        self.routing_cleanup.clear()
        try:
            state_path.unlink()
        except FileNotFoundError:
            pass

    def _save_routing_state(self, commands: list[tuple[str, ...]]) -> None:
        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_info = self.runtime_dir.lstat()
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0
                or directory_info.st_mode & 0o077):
            raise OSError("Небезопасный каталог состояния policy routing")
        fd = os.open(
            self.runtime_dir / "routing-cleanup.json",
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
                json.dump(commands, handle)
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _choose_rule_priorities(family: str, count: int) -> list[int]:
        proc = _ip_run(family, "rule", "list")
        used = set()
        for line in proc.stdout.splitlines():
            head = line.strip().split(":", 1)[0]
            if head.isdigit():
                used.add(int(head))
        for start in range(1, 32766 - count):
            priorities = list(range(start, start + count))
            if not used.intersection(priorities):
                return priorities
        raise OSError(f"Не удалось найти {count} свободных приоритетов ip rule ({family})")

    def _configure_routing(self, staged_config: Path) -> None:
        """Route unmarked host traffic through TUN; let marked Xray sockets use main."""
        with staged_config.open("r", encoding="utf-8") as handle:
            config = json.load(handle)
        tun = next(
            (item for item in config.get("inbounds", []) if item.get("tag") == "tun-in"),
            None,
        )
        if not tun:
            raise OSError("В конфиге нет tun-in")
        settings = tun.get("settings", {})
        if settings.get("name") != TUN_NAME:
            raise OSError(f"Имя TUN должно быть {TUN_NAME}")
        routes = settings.get("autoSystemRoutingTable", [])
        if "0.0.0.0/0" not in routes:
            raise OSError("В TUN-конфиге отсутствует маршрут IPv4 по умолчанию")
        proxy = next(
            (item for item in config.get("outbounds", []) if item.get("tag") == "proxy"),
            None,
        )
        if not proxy or proxy.get("streamSettings", {}).get("sockopt", {}).get("mark") != int(XRAY_MARK.split("/")[0], 16):
            raise OSError("Proxy outbound должен использовать зарезервированную routing mark")
        families = [("-4", PRIVATE_PREFIXES_V4)]
        if "::/0" in routes:
            families.append(("-6", PRIVATE_PREFIXES_V6))

        # Recover exact rules saved before the previous helper was interrupted.
        self._remove_routing()

        installed: list[tuple[str, ...]] = []
        cleanup: list[tuple[str, ...]] = []
        try:
            for family, prefixes in families:
                occupied = _ip_run(family, "route", "show", "table", ROUTE_TABLE)
                if occupied.stdout.strip():
                    raise OSError(f"Таблица маршрутизации {ROUTE_TABLE} уже занята ({family})")
                cleanup.append((family, "route", "del", "default", "dev", TUN_NAME,
                                "table", ROUTE_TABLE))

                rules = [("fwmark", XRAY_MARK, "lookup", "main")]
                rules.extend(
                    ("to", prefix, "lookup", "main", "suppress_prefixlength", "0")
                    for prefix in prefixes
                )
                rules.append(("lookup", ROUTE_TABLE))
                priorities = self._choose_rule_priorities(family, len(rules))
                for priority, rule in zip(priorities, rules):
                    cleanup.append((family, "rule", "del", "priority", str(priority), *rule))
            # Persist the cleanup plan before touching the live routing tables,
            # so a helper SIGKILL can be repaired on the next start.
            self._save_routing_state(cleanup)
            for command in cleanup:
                add = list(command)
                add[2] = "add"
                _ip_run(add[0], *add[1:])
                installed.append(command)
        except Exception:
            for command in reversed(installed):
                _ip_run(command[0], *command[1:], check=False)
            try:
                (self.runtime_dir / "routing-cleanup.json").unlink()
            except FileNotFoundError:
                pass
            raise
        self.routing_cleanup.extend(installed)

    def _stage_config(self) -> Path:
        """Copy the user's generated JSON into a private root-owned runtime dir."""
        parent = Path("/run/dma2ray")
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise OSError("/run/dma2ray должен принадлежать root и не быть доступен для записи группе")
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
                raise OSError("Конфиг Xray превышает 2 MiB")
        finally:
            os.close(fd)
        raw = b"".join(chunks)
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise OSError(f"Некорректный JSON конфига: {exc}") from exc
        if not isinstance(parsed, dict):
            raise OSError("Корень конфига Xray должен быть объектом")
        if set(parsed) - {"log", "inbounds", "outbounds", "dns", "routing"}:
            raise OSError("В конфиге есть неподдерживаемые root-параметры")

        def reject_file_inputs(value) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if str(key).lower() in {
                        "access", "error", "certificates", "keyfile", "privatekeyfile",
                        "geodata", "geodatapath", "assetspath", "externalcontroller",
                    }:
                        raise OSError(f"В конфиге запрещено root-файловое поле: {key}")
                    reject_file_inputs(item)
            elif isinstance(value, list):
                for item in value:
                    reject_file_inputs(item)

        reject_file_inputs(parsed)
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

    def _backup_network_state(self) -> None:
        commands = (
            ("ip", "-4", "route", "show", "table", "all"),
            ("ip", "-6", "route", "show", "table", "all"),
        )
        route_lines = []
        for command in commands:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
            if proc.returncode:
                raise OSError(f"Не удалось сохранить маршруты ({' '.join(command)}): {proc.stderr.strip()}")
            route_lines.append(f"$ {' '.join(command)}\n{proc.stdout.rstrip()}")
        rule_commands = (("ip", "rule", "list"), ("ip", "-6", "rule", "list"))
        rule_lines = []
        for command in rule_commands:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
            if proc.returncode:
                raise OSError(f"Не удалось сохранить правила ({' '.join(command)}): {proc.stderr.strip()}")
            rule_lines.append(f"$ {' '.join(command)}\n{proc.stdout.rstrip()}")
        for name, content in (
            ("/tmp/routes.before", "\n\n".join(route_lines) + "\n"),
            ("/tmp/rules.before", "\n\n".join(rule_lines) + "\n"),
        ):
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, self.uid) or info.st_nlink != 1:
                    os.close(fd)
                    raise OSError(f"Небезопасный файл backup: {name}")
                os.ftruncate(fd, 0)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)

    def status(self) -> dict:
        with self.lock:
            proc = self.proc
            running = bool(proc and proc.poll() is None)
            if proc is not None and not running:
                # A crashed Xray must not leave host traffic pointed at a dead
                # TUN until the user reconnects or exits the application.
                self._remove_routing()
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
                self._backup_network_state()
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"ok": False, "error": f"TUN не запущен: не удалось сделать backup маршрутов: {exc}"}
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
                    [str(self.xray), "run", "-c", str(config)],
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
                return {"ok": False, "error": f"Не удалось запустить Xray: {exc}"}
            finally:
                try:
                    log_handle.close()
                except Exception:
                    pass

            # Give Xray a moment to create the TUN device and install routes.
            time.sleep(1.0)
            code = self.proc.poll()
            if code is not None:
                tail = _log_tail(self.log_path)
                self.proc = None
                self._cleanup_config()
                return {
                    "ok": False,
                    "error": f"Xray завершился с кодом {code}",
                    "log": tail,
                }
            try:
                self._configure_routing(config)
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                self._stop_locked()
                return {"ok": False, "error": f"Не удалось включить policy routing TUN: {exc}",
                        "log": _log_tail(self.log_path)}
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
            self._remove_routing()
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
                self._remove_routing()
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
        self._remove_routing()
        self._cleanup_config()


class Helper:
    def __init__(self, args: argparse.Namespace) -> None:
        self.socket_path = Path(args.socket)
        self.uid = int(args.uid)
        self.gid = int(args.gid)
        self.runner = Runner(Path(args.xray), Path(args.config), Path(args.log), self.uid, self.gid)
        self.server: socket.socket | None = None
        self.stop_event = threading.Event()
        self._validate_paths()

    def _validate_paths(self) -> None:
        helper_info = Path(__file__).stat()
        if helper_info.st_uid != 0 or helper_info.st_mode & 0o022:
            raise SystemExit("privileged.py должен принадлежать root и быть недоступен для записи группе/остальным")
        try:
            home = Path(pwd.getpwuid(self.uid).pw_dir)
        except KeyError:
            home = Path("/root")
        xray = self.runner.xray
        if not xray.is_file() or not os.access(xray, os.X_OK):
            raise SystemExit(f"Xray не найден или не исполняемый: {xray}")
        binary_info = xray.stat()
        if binary_info.st_uid != 0 or binary_info.st_mode & 0o022:
            raise SystemExit("Root может запускать только root-owned Xray, недоступный для записи группе/остальным")
        allowed_roots = [Path("/usr/libexec/dma2ray"), Path("/usr/lib/dma2ray"), Path("/usr/local/lib/dma2ray")]
        if not any(_under(xray, root) for root in allowed_roots):
            raise SystemExit(f"Xray должен быть установлен в root-owned каталог приложения: {xray}")
        if not _under(self.runner.config, home):
            raise SystemExit("Конфиг должен находиться в домашнем каталоге пользователя")
        if not _under(self.runner.log_path, home):
            raise SystemExit("Лог должен находиться в домашнем каталоге пользователя")

    @staticmethod
    def _network_diagnostics() -> dict:
        """Read-only snapshot used before changing any TUN routes or rules."""
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
        if self.socket_path.parent != Path("/run/dma2ray") or self.socket_path.name != f"privileged-{self.uid}.sock":
            raise SystemExit("Сокет helper должен находиться в /run/dma2ray")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        parent_info = self.socket_path.parent.stat()
        if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise SystemExit("/run/dma2ray должен принадлежать root и не быть доступен для записи группе")
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
                # The app keeps one long-lived connection. Once it goes away,
                # the app is gone too, so do not leave a root process behind.
                break
        finally:
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
                    elif command == "shutdown":
                        self.runner.stop()
                        self._send(client, {"ok": True, "running": False})
                        self.stop_event.set()
                        return
                    else:
                        response = {"ok": False, "error": "Неизвестная команда"}
                except Exception as exc:  # keep the helper alive on unexpected errors
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
    parser = argparse.ArgumentParser(description="Privileged Xray helper for dma2ray")
    parser.add_argument("--inspect-network", action="store_true")
    parser.add_argument("--socket")
    parser.add_argument("--xray")
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

    missing = [name for name in ("socket", "xray", "config", "log", "uid", "gid") if not getattr(args, name)]
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
