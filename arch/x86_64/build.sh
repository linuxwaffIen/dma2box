#!/usr/bin/env bash
# Компиляция Dma2box в единый бинарник (Nuitka, standalone-режим).
#
# Результат: dist/dma2box.dist/dma2box — самодостаточный ELF-бинарник
# (внутри каталога лежат библиотеки, helper-скрипты и данные).
#
# Запуск: ./build.sh
# Если Nuitka уже установлен системно — сборка идёт без сети. Иначе Nuitka и patchelf ставятся
# pip'ом в .build/venv (при первой сборке нужен интернет).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Keep inherited toolchain settings from silently changing the target ABI.
# The desktop environment used for builds can export clang + ld.lld configured
# for i386 while Python and Nuitka objects are x86-64. GCC is the supported
# default; callers can opt into another native toolchain explicitly.
export CC="${DMA2BOX_CC:-gcc}"
export CXX="${DMA2BOX_CXX:-g++}"
export LD="${DMA2BOX_LD:-ld}"

VENV="$ROOT/.build/venv"

ensure_venv() {
    if [ ! -x "$VENV/bin/python" ]; then
        # --without-pip — запасной путь, если ensurepip недоступен
        # (в venv всё равно виден системный site-packages).
        python3 -m venv --system-site-packages "$VENV" \
            || python3 -m venv --system-site-packages --without-pip "$VENV"
    fi
}

# -m pip работает даже если в venv не создался собственный pip
# (--system-site-packages подхватывает системный python-pip).
pip_install() {
    ensure_venv
    "$VENV/bin/python" -m pip install --quiet "$@" || true
}

echo "1/4: окружение сборки..."
if python3 -c "import nuitka" >/dev/null 2>&1; then
    # Системный Nuitka — собираем сразу, без venv и сети.
    PY="python3"
    echo "     использую системный nuitka ($(python3 -c 'import nuitka, importlib.metadata as m; print(m.version(\"nuitka\"))' 2>/dev/null || echo '?'))"
else
    ensure_venv
    if ! "$VENV/bin/python" -c "import nuitka" >/dev/null 2>&1; then
        echo "     ставлю nuitka через pip..."
        pip_install nuitka
    fi
    if ! "$VENV/bin/python" -c "import nuitka" >/dev/null 2>&1; then
        echo "Ошибка: не удалось установить nuitka (нужен интернет," >&2
        echo "либо установите его: pip install nuitka)" >&2
        exit 1
    fi
    PY="$VENV/bin/python"
fi

# Nuitka ищет patchelf и scons в PATH: сначала свой (venv), затем системный
# (системный patchelf).
[ -d "$VENV/bin" ] && export PATH="$VENV/bin:$PATH"
# patchelf 0.18.0 — известный багованный релиз, Nuitka отказывается с ним работать.
patchelf_ok() {
    command -v patchelf >/dev/null 2>&1 || return 1
    [ "$(patchelf --version 2>/dev/null)" != "patchelf 0.18.0" ]
}

if ! patchelf_ok; then
    echo "     ставлю свежий patchelf через pip (нужен для standalone-режима)..."
    pip_install "patchelf>=0.19" || sudo apt-get install -y patchelf || true
fi
if ! patchelf_ok; then
    echo "Ошибка: patchelf не найден или это багованная версия 0.18.0." >&2
    echo "Установите patchelf != 0.18.0: pip install 'patchelf>=0.19'" >&2
    exit 1
fi

# Ограничение параллелизма/памяти для слабых машин (например QEMU-гость):
#   DMA2BOX_JOBS=2 DMA2BOX_LOW_MEMORY=1 ./build.sh
NA_OPTS=()
if [ -n "${DMA2BOX_JOBS:-}" ]; then
    NA_OPTS+=(--jobs="$DMA2BOX_JOBS")
fi
if [ "${DMA2BOX_LOW_MEMORY:-0}" = "1" ]; then
    NA_OPTS+=(--low-memory)
fi

echo "2/4: точка входа (.build/entry.py)..."
mkdir -p "$ROOT/.build"
cat > "$ROOT/.build/entry.py" <<'EOF'
# Точка входа для сборки: run.py удалён, приложение компилируется в бинарник.
import sys

from dma2box.app import main

raise SystemExit(main())
EOF

echo "3/4: компиляция (1-3 минуты)..."
rm -rf "$ROOT/dist"
"$PY" -m nuitka \
    --standalone \
    --output-dir="$ROOT/dist" \
    --output-filename=dma2box \
    --include-package=gi \
    --assume-yes-for-downloads \
    ${NA_OPTS[@]+"${NA_OPTS[@]}"} \
    "$ROOT/.build/entry.py"
mv "$ROOT/dist/entry.dist" "$ROOT/dist/dma2box.dist"

echo "4/4: helper-скрипты и данные рядом с бинарником..."
# __file__ скомпилированных модулей указывает внутрь dist-каталога,
# поэтому privileged.py/tray_helper.py и data/ кладутся туда же.
mkdir -p "$ROOT/dist/dma2box.dist/helpers"
cp -a "$ROOT/dma2box/privileged.py" "$ROOT/dma2box/tray_helper.py" \
      "$ROOT/dist/dma2box.dist/helpers/"
# priv_setup.py — авто-подготовка TUN из приложения; есть не во всех
# архитектурных снимках, поэтому копируем только при наличии.
if [ -f "$ROOT/dma2box/priv_setup.py" ]; then
    cp -a "$ROOT/dma2box/priv_setup.py" "$ROOT/dist/dma2box.dist/helpers/"
fi
cp -a "$ROOT/data" "$ROOT/dist/dma2box.dist/"
cp -a "$ROOT/LICENSE" "$ROOT/README.md" "$ROOT/dist/dma2box.dist/" 2>/dev/null || true

echo
echo "Готово: dist/dma2box.dist/dma2box"
ls -lh "$ROOT/dist/dma2box.dist/dma2box"
"$ROOT/dist/dma2box.dist/dma2box" --version
