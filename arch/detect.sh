#!/usr/bin/env bash
# Возвращает относительный каталог исходников под архитектуру хоста.
detect_arch_dir() {
  local machine
  machine="$(uname -m | tr '[:upper:]' '[:lower:]')"
  case "$machine" in
    x86_64|amd64) printf 'x86_64' ;;
    i386|i486|i586|i686|i786) printf 'x86' ;;
    armv6*|armv7*) printf 'arm/armv7' ;;
    armv8l|arm32*|aarch32) printf 'arm/aarch32' ;;
    aarch64|arm64) printf 'arm/aarch64' ;;
    *) return 1 ;;
  esac
}
