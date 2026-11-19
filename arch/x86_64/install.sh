#!/usr/bin/env bash
# Установщик Dma2box.
#
# Примеры:
#   ./install.sh                 # в ~/.local
#   ./install.sh --system        # в /usr (нужен root)
#   ./install.sh --uninstall     # удалить пользовательскую установку
#   ./install.sh --uninstall --purge  # удалить также профили и кэш
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_ID="io.github.dma2box.Dma2box"
APP_NAME="dma2box"
MODE="user"
PREFIX="${PREFIX:-}"
USER_HOME="${HOME}"
TARGET_UID="$EUID"
TARGET_GID="$(id -g)"
ACTION="install"
PURGE=0

usage() {
    cat <<'EOF'
Использование: ./install.sh [параметры]

  --system        установить в /usr (требуется root/sudo)
  --prefix DIR    префикс пользовательской установки (по умолчанию ~/.local)
  --uninstall     удалить приложение
  --purge         вместе с --uninstall удалить профили, кэш и автозапуск
  -h, --help      показать эту справку

Без --system файлы ставятся в ~/.local:
  ~/.local/lib/dma2box        код: бинарник (app/), исходники, данные
  ~/.local/bin/dma2box        симлинк на бинарник
  ~/.local/share/applications   ярлык
  ~/.local/share/icons          иконка
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --system)
            MODE="system"
            PREFIX="/usr"
            shift
            ;;
        --prefix)
            [[ $# -ge 2 ]] || { echo "Ошибка: --prefix требует каталог" >&2; exit 2; }
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            shift
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        --purge)
            PURGE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Неизвестный параметр: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$MODE" == "system" && "$PREFIX" != "/usr" ]]; then
    echo "Ошибка: --system всегда использует /usr" >&2
    exit 2
fi
if [[ "$MODE" == "system" && $EUID -ne 0 ]]; then
    echo "Для системной установки нужен root:" >&2
    echo "  sudo ./install.sh --system" >&2
    exit 1
fi

# sudo сбрасывает HOME в /root. Если пользовательскую установку запустили
# через sudo, ставим в домашний каталог реального пользователя, а не в /root.
if [[ "$MODE" == "user" && $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
    real_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [[ -n "$real_home" && "$real_home" != "/" ]]; then
        USER_HOME="$real_home"
        TARGET_UID="$(id -u "$SUDO_USER")"
        TARGET_GID="$(id -g "$SUDO_USER")"
    fi
fi
PREFIX="${PREFIX:-$USER_HOME/.local}"

# Права на установленные файлы должны быть пользователя, даже если
# установка запущена через sudo.
chown_user_files() {
    [[ $EUID -eq 0 && "$TARGET_UID" -ne 0 ]] || return 0
    chown -R "$TARGET_UID:$TARGET_GID" "$@" 2>/dev/null || true
}

# Действия, которые должны выполняться от имени пользователя (xdg-mime).
as_target_user() {
    if [[ $EUID -eq 0 && "$TARGET_UID" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
        sudo -u "#$TARGET_UID" env HOME="$USER_HOME" \
            XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$USER_HOME/.config}" "$@"
    else
        "$@"
    fi
}

APP_DIR="$PREFIX/lib/$APP_NAME"
BIN="$PREFIX/bin/$APP_NAME"
DESKTOP_DIR="$PREFIX/share/applications"
ICON_DIR="$PREFIX/share/icons/hicolor/scalable/apps"
DESKTOP="$DESKTOP_DIR/$APP_ID.desktop"
ICON="$ICON_DIR/$APP_ID.svg"

update_caches() {
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
    fi
    chown_user_files "$DESKTOP_DIR" "$PREFIX/share/icons/hicolor"
}

register_scheme() {
    command -v xdg-mime >/dev/null 2>&1 || return 0
    if [[ "$MODE" == "user" ]]; then
        as_target_user xdg-mime default "$APP_ID.desktop" x-scheme-handler/vless \
            >/dev/null 2>&1 || true
    elif [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]] && command -v sudo >/dev/null 2>&1; then
        sudo -u "$SUDO_USER" xdg-mime default "$APP_ID.desktop" x-scheme-handler/vless \
            >/dev/null 2>&1 || true
    fi
}

uninstall() {
    rm -f "$BIN" "$DESKTOP" "$ICON"
    rm -rf "$APP_DIR"
    update_caches
    echo "Удалено: $APP_DIR, $BIN"
    if [[ $PURGE -eq 1 ]]; then
        if [[ "$MODE" == "system" ]]; then
            echo "Профили пользователей не удаляются при системной установке." >&2
        else
            rm -rf \
                "${XDG_CONFIG_HOME:-$USER_HOME/.config}/$APP_NAME" \
                "${XDG_DATA_HOME:-$USER_HOME/.local/share}/$APP_NAME" \
                "${XDG_CACHE_HOME:-$USER_HOME/.cache}/$APP_NAME" \
                "${XDG_STATE_HOME:-$USER_HOME/.local/state}/$APP_NAME"
            rm -f "${XDG_CONFIG_HOME:-$USER_HOME/.config}/autostart/$APP_NAME.desktop"
            echo "Удалены профили, кэш и автозапуск."
        fi
    fi
    echo "Готово."
}

install_app() {
    local bin_src="$ROOT/dist/dma2box.dist/dma2box"
    if [[ ! -x "$bin_src" ]]; then
        echo "Ошибка: бинарник не собран." >&2
        echo "Скомпилируйте исходники: ./build.sh" >&2
        echo "  (результат: dist/dma2box.dist/dma2box)" >&2
        exit 1
    fi
    for source in "$bin_src" "$ROOT/dma2box" "$ROOT/data/$APP_ID.desktop" "$ROOT/data/$APP_ID.svg"; do
        [[ -e "$source" ]] || { echo "Не найден файл: $source" >&2; exit 1; }
    done

    install -d "$APP_DIR" "$PREFIX/bin" "$DESKTOP_DIR" "$ICON_DIR"
    rm -rf "$APP_DIR/dma2box" "$APP_DIR/data" "$APP_DIR/app" "$APP_DIR/bin"
    cp -a "$ROOT/dma2box" "$APP_DIR/"
    cp -a "$ROOT/data" "$APP_DIR/"
    # Скомпилированный бинарник с библиотеками, helper-скриптами и данными.
    cp -a "$ROOT/dist/dma2box.dist" "$APP_DIR/app"
    cp -f "$ROOT/LICENSE" "$APP_DIR/LICENSE" 2>/dev/null || true
    cp -f "$ROOT/README.md" "$APP_DIR/README.md" 2>/dev/null || true
    find "$APP_DIR" -type d -name __pycache__ -prune -exec rm -rf {} +
    find "$APP_DIR" -type f -name '*.pyc' -delete

    # /prefix/bin/dma2box — симлинк на бинарник (RPATH $ORIGIN переживает
    # симлинк, библиотеки ищутся рядом с настоящим файлом).
    ln -sfn "$APP_DIR/app/dma2box" "$BIN"
    install -m 0644 "$ROOT/data/$APP_ID.svg" "$ICON"

    sed "s|^Exec=dma2box$|Exec=$BIN|" \
        "$ROOT/data/$APP_ID.desktop" > "$DESKTOP"
    chmod 0644 "$DESKTOP"
    chown_user_files "$APP_DIR" "$PREFIX/bin" "$DESKTOP_DIR" "$ICON_DIR" \
        "$BIN" "$DESKTOP" "$ICON"
    update_caches
    register_scheme

    echo "Dma2box установлен:"
    echo "  приложение: $APP_DIR"
    echo "  бинарник:   $BIN -> $APP_DIR/app/dma2box"
    echo "  ярлык:      $DESKTOP"
    if [[ "$MODE" == "user" && ":$PATH:" != *":$PREFIX/bin:"* ]]; then
        echo
        echo "Внимание: $PREFIX/bin отсутствует в PATH."
        echo "Добавьте его в ~/.profile или запускайте приложение по полному пути."
    fi
    echo
    echo "Ядро sing-box можно скачать в «Настройках → Ядро → Скачать»"
}

install_system_helper() {
    # Устанавливает привилегированный хелпер для TUN-режима и polkit-политику.
    # Требует root; вызывается только при установке (не при удалении).
    if [[ $EUID -ne 0 ]]; then
        echo "Для установки system-хелпера нужен root: sudo ./install.sh --system" >&2
        echo "Продолжаю без system-хелпера (TUN-режим потребует ручной настройки polkit)."
        return 0
    fi

    local bin_src="$ROOT/dist/dma2box.dist/dma2box"
    local priv_src="$ROOT/dma2box/privileged.py"
    [[ -x "$bin_src" ]] || { echo "Бинарник не собран: $bin_src" >&2; return 1; }
    [[ -f "$priv_src" ]] || { echo "Не найден priv-скрипт: $priv_src" >&2; return 1; }

    local DIR=/usr/libexec/dma2box
    local PY
    PY=$(command -v python3)

    # TUN-процесс работает от root, поэтому он не должен запускать бинарник,
    # который может подменить пользователь. Закрепляем скачанный sing-box в
    # root-owned каталоге хелпера при системной установке.
    local install_home="$HOME"
    if [[ -n "${SUDO_USER:-}" ]]; then
        install_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    fi
    local data_home="${XDG_DATA_HOME:-$install_home/.local/share}"
    local core_src="${DMA2BOX_CORE_BIN:-$data_home/dma2box/bin/$(uname -m)/sing-box/sing-box}"

    install -d -m 755 "$DIR"
    install -m 755 "$bin_src" "$DIR/dma2box"
    install -m 755 "$priv_src" "$DIR/priv.py"
    if [[ -n "$core_src" && -x "$core_src" ]]; then
        install -o root -g root -m 755 "$core_src" "$DIR/sing-box"
        echo "Root-owned sing-box installed: $DIR/sing-box"
    else
        echo "sing-box не найден для root-owned установки. TUN пока отключён."
        echo "Скачайте sing-box в приложении и повторите: sudo DMA2BOX_CORE_BIN=/path/to/sing-box ./install.sh --system"
    fi

    cat > "$DIR/dma2box-helper" <<EOF
#!/bin/sh
exec $PY $DIR/priv.py "\$@"
EOF
    chmod 755 "$DIR/dma2box-helper"

    cat > /usr/share/polkit-1/actions/org.dma2box.run-core.policy <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
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
EOF
    echo "Готово"
}

if [[ "$ACTION" == "uninstall" ]]; then
    uninstall
else
    install_app
    install_system_helper
fi
