from __future__ import annotations

import json
import math
import os
import tempfile
import time
import uuid
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, TypedDict

from . import paths

Mode = Literal["proxy", "system", "vpn", "router"]
LogLevel = Literal["debug", "info", "warning", "error"]
PingType = Literal["tcp", "http", "icmp"]
ColorScheme = Literal["system", "light", "dark"]


class Settings(TypedDict):
    tun_enabled: bool
    mode: Mode
    socks_port: int
    http_port: int
    autostart: bool
    tray_enabled: bool
    auto_connect: bool
    selected_profile_id: str | None
    core_path: str
    accent_mode: Literal["preset", "custom", "wallpaper"]
    accent_color: str
    log_level: LogLevel
    close_to_tray: bool
    ping_timeout: float
    ping_type: PingType
    auto_ping: bool
    sort_by_latency: bool
    color_scheme: ColorScheme
    auto_update_subs: bool
    auto_update_interval: int
    auto_failover: bool
    health_interval: int
    health_timeout: int
    route_rules: list[str]
    geo_rule_sets: list[str]


DEFAULT_SETTINGS: Settings = {
    "tun_enabled": True,
    "mode": "vpn",
    "socks_port": 10808,
    "http_port": 10809,
    "autostart": False,
    "tray_enabled": True,
    "auto_connect": False,
    "selected_profile_id": None,
    "core_path": "",
    "accent_mode": "preset",
    "accent_color": "#2B5CE6",
    "log_level": "warning",
    "close_to_tray": True,
    "ping_timeout": 4.0,
    "ping_type": "tcp",
    "auto_ping": True,
    "sort_by_latency": False,
    "color_scheme": "system",
    "auto_update_subs": False,
    "auto_update_interval": 6,
    # Hiddify-подобные возможности: проверка живого туннеля и автопереключение.
    "auto_failover": True,
    "health_interval": 30,
    "health_timeout": 8,
    # Маршрутизация: пользовательские правила и опциональные geoip/geosite
    # rule-sets (по URL, sing-box качает их сам).
    "route_rules": [],
    "geo_rule_sets": [],
}

LOG_LEVELS = ("debug", "info", "warning", "error")
PING_TYPES = ("tcp", "http", "icmp")

# Режимы подключения: локальный прокси, системный прокси ОС, TUN на всю машину
# и TUN-роутер с NAT для устройств локальной сети (как router-mode в Hiddify).
MODES = ("proxy", "system", "vpn", "router")

# Подписи для ComboBox в настройках и для меню в трее.
MODE_LABELS = (
    "Прокси (SOCKS5/HTTP)",
    "Системный прокси",
    "ВПН (TUN, вся машина)",
    "Роутер (TUN + NAT, вся сеть)",
)


def new_id() -> str:
    return uuid.uuid4().hex


def _timestamp(value: object, fallback: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return fallback
    return parsed if math.isfinite(parsed) else fallback


@dataclass
class Profile:
    name: str
    uri: str
    id: str = field(default_factory=new_id)
    subscription_id: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Profile":
        uri = raw.get("uri")
        if not isinstance(uri, str) or not uri.strip():
            raise ValueError("profile URI is missing")
        name = raw.get("name")
        profile_id = raw.get("id")
        subscription_id = raw.get("subscription_id")
        now = time.time()
        return cls(
            id=profile_id if isinstance(profile_id, str) and profile_id else new_id(),
            name=name.strip() if isinstance(name, str) else "",
            uri=uri.strip(),
            subscription_id=(
                subscription_id
                if isinstance(subscription_id, str) and subscription_id
                else None
            ),
            created_at=_timestamp(raw.get("created_at"), now),
            updated_at=_timestamp(raw.get("updated_at"), now),
        )


@dataclass
class Subscription:
    name: str
    url: str
    id: str = field(default_factory=new_id)
    updated_at: float = 0.0
    last_error: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Subscription":
        url = raw.get("url")
        if not isinstance(url, str) or not url.strip():
            raise ValueError("subscription URL is missing")
        name = raw.get("name")
        sub_id = raw.get("id")
        last_error = raw.get("last_error")
        return cls(
            id=sub_id if isinstance(sub_id, str) and sub_id else new_id(),
            name=name.strip() if isinstance(name, str) and name.strip() else url.strip(),
            url=url.strip(),
            updated_at=_timestamp(raw.get("updated_at"), 0.0),
            last_error=last_error if isinstance(last_error, str) and last_error else None,
        )


class Store:
    """Persistent application state. All calls are expected on the GTK main thread."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or paths.STATE_FILE
        self.profiles: list[Profile] = []
        self.subscriptions: list[Subscription] = []
        self.settings: Settings = deepcopy(DEFAULT_SETTINGS)
        self._load()

    # ------------------------------------------------------------------ io
    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        profiles = raw.get("profiles")
        self.profiles = []
        profile_ids: set[str] = set()
        profile_uris: set[str] = set()
        if isinstance(profiles, list):
            for item in profiles:
                if not isinstance(item, dict):
                    continue
                try:
                    profile = Profile.from_dict(item)
                except (TypeError, ValueError, OverflowError):
                    continue
                if profile.id in profile_ids or profile.uri in profile_uris:
                    continue
                profile_ids.add(profile.id)
                profile_uris.add(profile.uri)
                self.profiles.append(profile)
        subscriptions = raw.get("subscriptions")
        self.subscriptions = []
        subscription_ids: set[str] = set()
        if isinstance(subscriptions, list):
            for item in subscriptions:
                if not isinstance(item, dict):
                    continue
                try:
                    subscription = Subscription.from_dict(item)
                except (TypeError, ValueError, OverflowError):
                    continue
                if subscription.id in subscription_ids:
                    continue
                subscription_ids.add(subscription.id)
                self.subscriptions.append(subscription)
        settings = raw.get("settings")
        raw_settings = settings if isinstance(settings, dict) else None
        if isinstance(settings, dict):
            for key, default in DEFAULT_SETTINGS.items():
                value = settings.get(key, default)
                if isinstance(default, bool) and not isinstance(value, bool):
                    value = default
                elif isinstance(default, int) and not isinstance(default, bool):
                    try:
                        value = int(value)
                    except (TypeError, ValueError):
                        value = default
                elif isinstance(default, float):
                    try:
                        value = float(value)
                    except (TypeError, ValueError):
                        value = default
                elif default is None and value is not None:
                    value = str(value)
                self.settings[key] = value
        self.settings["log_level"] = (
            self.settings["log_level"]
            if self.settings.get("log_level") in LOG_LEVELS
            else "warning"
        )
        # Миграция: старые состояния имели только tun_enabled (bool).
        if raw_settings is None or "mode" not in raw_settings:
            self.settings["mode"] = "vpn" if self.settings.get("tun_enabled") else "proxy"
        if self.settings.get("mode") not in MODES:
            self.settings["mode"] = "vpn" if self.settings.get("tun_enabled") else "proxy"
        # tun_enabled остаётся зеркалом mode для обратной совместимости.
        self.settings["tun_enabled"] = self.settings["mode"] in ("vpn", "router")
        self._sanitize()

    def _sanitize(self) -> None:
        self._sanitize_settings()
        ids = {profile.id for profile in self.profiles}
        selected = self.settings.get("selected_profile_id")
        if selected not in ids:
            self.settings["selected_profile_id"] = self.profiles[0].id if self.profiles else None
        sub_ids = {sub.id for sub in self.subscriptions}
        for profile in self.profiles:
            if profile.subscription_id not in sub_ids:
                profile.subscription_id = None

    def _sanitize_settings(self) -> None:
        settings = self.settings
        for key, default in DEFAULT_SETTINGS.items():
            settings.setdefault(key, deepcopy(default))

        for key, default in DEFAULT_SETTINGS.items():
            value = settings.get(key)
            if isinstance(default, bool):
                settings[key] = value if isinstance(value, bool) else default
            elif isinstance(default, int):
                if isinstance(value, bool):
                    value = default
                try:
                    settings[key] = int(value)
                except (TypeError, ValueError, OverflowError):
                    settings[key] = default
            elif isinstance(default, float):
                if isinstance(value, bool):
                    value = default
                try:
                    number = float(value)
                    settings[key] = number if math.isfinite(number) else default
                except (TypeError, ValueError, OverflowError):
                    settings[key] = default
            elif default is None:
                settings[key] = value if isinstance(value, str) else None
            elif isinstance(default, str):
                settings[key] = value if isinstance(value, str) else default
            elif isinstance(default, list):
                settings[key] = (
                    [entry for entry in value if isinstance(entry, str)][:512]
                    if isinstance(value, list)
                    else list(default)
                )

        if settings.get("log_level") not in LOG_LEVELS:
            settings["log_level"] = "warning"
        if settings.get("mode") not in MODES:
            settings["mode"] = "vpn" if settings.get("tun_enabled") else "proxy"
        if settings.get("ping_type") not in PING_TYPES:
            settings["ping_type"] = "tcp"
        if settings.get("color_scheme") not in ("system", "light", "dark"):
            settings["color_scheme"] = "system"
        if settings.get("accent_mode") not in ("preset", "custom", "wallpaper"):
            settings["accent_mode"] = "preset"
        accent = settings.get("accent_color")
        settings["accent_color"] = accent if isinstance(accent, str) else "#2B5CE6"
        settings["tun_enabled"] = settings["mode"] in ("vpn", "router")

        for key, low, high in (
            ("socks_port", 1, 65535),
            ("http_port", 1, 65535),
            ("auto_update_interval", 1, 168),
            ("health_interval", 5, 3600),
            ("health_timeout", 1, 60),
        ):
            value = settings[key]
            settings[key] = min(high, max(low, value))
        settings["ping_timeout"] = min(30.0, max(1.0, settings["ping_timeout"]))
        if settings["socks_port"] == settings["http_port"]:
            settings["socks_port"], settings["http_port"] = 10808, 10809

    def save(self) -> None:
        self._sanitize()
        payload = {
            "version": 1,
            "profiles": [asdict(profile) for profile in self.profiles],
            "subscriptions": [asdict(sub) for sub in self.subscriptions],
            "settings": self.settings,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        fd, tmp_name = tempfile.mkstemp(prefix=".state-", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        finally:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass

    # ------------------------------------------------------------- profiles
    def get_profile(self, profile_id: str | None) -> Profile | None:
        if not profile_id:
            return None
        return next((profile for profile in self.profiles if profile.id == profile_id), None)

    @property
    def selected_profile(self) -> Profile | None:
        return self.get_profile(self.settings.get("selected_profile_id"))

    def select_profile(self, profile_id: str | None) -> None:
        if profile_id and not self.get_profile(profile_id):
            return
        self.settings["selected_profile_id"] = profile_id
        self.save()

    def find_profile_by_uri(self, uri: str) -> Profile | None:
        return next((profile for profile in self.profiles if profile.uri == uri), None)

    def add_profile(self, name: str, uri: str, subscription_id: str | None = None) -> Profile:
        existing = self.find_profile_by_uri(uri)
        if existing:
            if name and name != existing.name:
                existing.name = name
                existing.updated_at = time.time()
            if subscription_id:
                existing.subscription_id = subscription_id
            if not self.settings.get("selected_profile_id"):
                self.settings["selected_profile_id"] = existing.id
            self.save()
            return existing
        profile = Profile(
            name=name or uri.split("@")[-1][:80],
            uri=uri,
            subscription_id=subscription_id,
        )
        self.profiles.append(profile)
        if not self.settings.get("selected_profile_id"):
            self.settings["selected_profile_id"] = profile.id
        self.save()
        return profile

    def import_profiles(self, items: list[tuple[str, str]]) -> tuple[int, int]:
        """Add or update imported profiles and persist the batch once."""
        if not items:
            return 0, 0
        by_uri = {profile.uri: profile for profile in self.profiles}
        initial_uris = set(by_uri)
        imported = 0
        last_profile: Profile | None = None
        for name, uri in items:
            profile = by_uri.get(uri)
            if profile is None:
                profile = Profile(name=name or uri.split("@")[-1][:80], uri=uri)
                self.profiles.append(profile)
                by_uri[uri] = profile
            elif name and name != profile.name:
                profile.name = name
                profile.updated_at = time.time()
            if not self.settings.get("selected_profile_id"):
                self.settings["selected_profile_id"] = profile.id
            last_profile = profile
            imported += 1
        if last_profile is not None:
            self.settings["selected_profile_id"] = last_profile.id
        self.save()
        added = len(set(by_uri) - initial_uris)
        return imported, added

    def rename_profile(self, profile_id: str, name: str) -> None:
        profile = self.get_profile(profile_id)
        if profile and name.strip():
            profile.name = name.strip()
            profile.updated_at = time.time()
            self.save()

    def remove_profile(self, profile_id: str) -> None:
        self.profiles = [profile for profile in self.profiles if profile.id != profile_id]
        self._sanitize()
        self.save()

    # -------------------------------------------------------- subscriptions
    def get_subscription(self, sub_id: str) -> Subscription | None:
        return next((sub for sub in self.subscriptions if sub.id == sub_id), None)

    def add_subscription(self, name: str, url: str) -> Subscription:
        sub = Subscription(name=name.strip() or url, url=url.strip())
        self.subscriptions.append(sub)
        self.save()
        return sub

    def remove_subscription(self, sub_id: str) -> None:
        self.subscriptions = [sub for sub in self.subscriptions if sub.id != sub_id]
        self.profiles = [
            profile for profile in self.profiles if profile.subscription_id != sub_id
        ]
        self._sanitize()
        self.save()

    def replace_subscription_profiles(
        self, sub_id: str, items: list[tuple[str, str]], error: str | None = None
    ) -> int:
        sub = self.get_subscription(sub_id)
        if not sub:
            return 0
        selected_uri = self.selected_profile.uri if self.selected_profile else None
        self.profiles = [
            profile for profile in self.profiles if profile.subscription_id != sub_id
        ]
        added = 0
        seen: set[str] = set()
        for name, uri in items:
            if uri in seen:
                continue
            seen.add(uri)
            self.profiles.append(
                Profile(name=name, uri=uri, subscription_id=sub_id)
            )
            added += 1
        sub.updated_at = time.time()
        sub.last_error = error
        if selected_uri:
            match = self.find_profile_by_uri(selected_uri)
            if match:
                self.settings["selected_profile_id"] = match.id
        self._sanitize()
        self.save()
        return added

    def set_subscription_error(self, sub_id: str, error: str) -> None:
        sub = self.get_subscription(sub_id)
        if sub:
            sub.last_error = error
            sub.updated_at = time.time()
            self.save()

    def profiles_for_subscription(self, sub_id: str) -> list[Profile]:
        return [profile for profile in self.profiles if profile.subscription_id == sub_id]

    # ------------------------------------------------------------- settings
    @property
    def mode(self) -> str:
        value = self.settings.get("mode")
        return value if value in MODES else "proxy"

    def set_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError(f"Неизвестный режим: {mode}")
        self.settings["mode"] = mode
        self.settings["tun_enabled"] = mode in ("vpn", "router")
        self.save()

    def set_setting(self, key: str, value: Any) -> None:
        self.settings[key] = value
        if key == "mode" and value in MODES:
            self.settings["tun_enabled"] = value in ("vpn", "router")
        self.save()

    def core_path(self) -> Path:
        configured = str(self.settings.get("core_path") or "").strip()
        if configured:
            return Path(configured).expanduser()
        return paths.CORE_PATH
