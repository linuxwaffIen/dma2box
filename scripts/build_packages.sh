#!/usr/bin/env bash
# Сборка пакетов из исходников под архитектуру текущей машины.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=arch/detect.sh
source "$ROOT/arch/detect.sh"
TARGET="$(detect_arch_dir)" || {
    echo "Неподдерживаемая архитектура: $(uname -m)" >&2
    exit 1
}
cd "$ROOT/arch/$TARGET"
exec bash scripts/build_packages.sh "$@"
