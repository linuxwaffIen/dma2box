#!/usr/bin/env python3
"""GTK3 + AppIndicator tray helper.

It runs in a separate process because libayatana-appindicator requires GTK3,
while the main application is GTK4. The two processes talk over a Unix socket.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time

import gi

gi.require_version("Gtk", "3.0")

try:
    gi.require_version("AyatanaAppIndicator3", "0.1")
    from gi.repository import AyatanaAppIndicator3 as AppIndicator
except (ValueError, ImportError):
    try:
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as AppIndicator
    except (ValueError, ImportError):
        print("AppIndicator typelib is not installed", file=sys.stderr)
        raise SystemExit(1)

from gi.repository import GLib, Gtk


class Tray:
    def __init__(self, socket_path: str, icon: str, modes: list | None = None) -> None:
        self.sock: socket.socket | None = None
        self.reader = None
        self.send_lock = threading.Lock()
        self.running = True
        self._syncing_modes = False
        self._mode_items: dict[str, Gtk.CheckMenuItem] = {}
        self._mode_labels = {str(m): str(label) for m, label in (modes or [])}

        indicator = AppIndicator.Indicator.new(
            "dma2box", icon, AppIndicator.IndicatorCategory.APPLICATION_STATUS
        )
        indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.indicator = indicator

        menu = Gtk.Menu()
        self.show_item = Gtk.MenuItem(label="Показать окно")
        self.show_item.connect("activate", lambda _item: self.send({"cmd": "show"}))
        menu.append(self.show_item)

        self.toggle_item = Gtk.MenuItem(label="Подключиться")
        self.toggle_item.connect("activate", lambda _item: self.send({"cmd": "toggle"}))
        menu.append(self.toggle_item)

        if self._mode_labels:
            self.mode_item = Gtk.MenuItem(label="Режим: —")
            submenu = Gtk.Menu()
            group: list[Gtk.RadioMenuItem] = []
            for value, label in self._mode_labels.items():
                item = Gtk.RadioMenuItem.new_with_label(group, label)
                group.append(item)
                item.connect("activate", self._on_mode_activate, value)
                self._mode_items[value] = item
                submenu.append(item)
            submenu.show_all()
            self.mode_item.set_submenu(submenu)
            menu.append(self.mode_item)

        menu.append(Gtk.SeparatorMenuItem())

        quit_item = Gtk.MenuItem(label="Выход")
        quit_item.connect("activate", self.on_quit)
        menu.append(quit_item)
        menu.show_all()
        indicator.set_menu(menu)

        try:
            indicator.set_title("Dma2box")
        except Exception:
            pass

        self._connect(socket_path)
        thread = threading.Thread(target=self._reader, name="tray-reader", daemon=True)
        thread.start()

    def _connect(self, path: str) -> None:
        deadline = time.monotonic() + 8.0
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect(path)
                sock.settimeout(None)
                self.sock = sock
                self.reader = sock.makefile("rb")
                return
            except OSError as exc:
                last_error = exc
                time.sleep(0.2)
        raise SystemExit(f"cannot connect to app: {last_error}")

    def send(self, payload: dict) -> None:
        if not self.sock:
            return
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            with self.send_lock:
                self.sock.sendall(data)
        except OSError:
            GLib.idle_add(self._quit)

    def _reader(self) -> None:
        assert self.reader is not None
        try:
            for raw in self.reader:
                try:
                    message = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                GLib.idle_add(self._apply, message)
        except OSError:
            pass
        GLib.idle_add(self._quit)

    def _on_mode_activate(self, item: Gtk.RadioMenuItem, value: str) -> None:
        if self._syncing_modes:
            return
        if not item.get_active():
            return  # radio-группа шлёт activate и на соседних пунктах
        self.send({"cmd": "mode", "mode": value})

    def _apply(self, message: dict) -> bool:
        state = str(message.get("state") or "stopped")
        profile = str(message.get("profile") or "")
        mode = str(message.get("mode") or "")
        if state == "running":
            self.toggle_item.set_label("Отключиться")
            self._set_icon("network-vpn-symbolic", "Dma2box — подключено")
        elif state == "starting":
            self.toggle_item.set_label("Подключение…")
            self._set_icon("network-vpn-symbolic", "Dma2box — подключение")
        else:
            self.toggle_item.set_label("Подключиться")
            self._set_icon("network-offline-symbolic", "Dma2box — отключено")
        if mode and self._mode_items:
            label = self._mode_labels.get(mode)
            if label:
                self.mode_item.set_label(f"Режим: {label}")
            self._syncing_modes = True
            try:
                item = self._mode_items.get(mode)
                if item is not None and not item.get_active():
                    item.set_active(True)
            finally:
                self._syncing_modes = False
        title = "Dma2box"
        if profile:
            title += f" — {profile}"
        health = str(message.get("health") or "")
        if state == "running" and health == "ok":
            title += " ✓"
        elif state == "running" and health == "bad":
            title += " !"
        try:
            self.indicator.set_title(title)
        except Exception:
            pass
        return False

    def _set_icon(self, name: str, title: str) -> None:
        try:
            self.indicator.set_icon_full(name, title)
        except Exception:
            try:
                self.indicator.set_icon(name)
            except Exception:
                pass

    def on_quit(self, *_args) -> None:
        self.send({"cmd": "quit"})
        self._quit()

    def _quit(self) -> bool:
        if not self.running:
            return False
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        Gtk.main_quit()
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--icon", default="network-vpn-symbolic")
    parser.add_argument("--label", default="Dma2box")
    parser.add_argument("--modes", default="", help="JSON-список [[mode, label], …]")
    args = parser.parse_args(argv)

    modes: list = []
    if args.modes:
        try:
            modes = json.loads(args.modes)
        except ValueError:
            modes = []

    if not Gtk.init_check([])[0]:
        print("cannot initialize GTK3", file=sys.stderr)
        return 1

    try:
        tray = Tray(args.socket, args.icon, modes)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1
    tray._apply({"state": "stopped"})
    Gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
