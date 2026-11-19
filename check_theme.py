#!/usr/bin/env python3
"""Проверка темы из исходников под архитектуру текущей машины."""
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MACHINE = os.uname().machine.lower()
TARGET = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "i386": "x86",
    "i486": "x86",
    "i586": "x86",
    "i686": "x86",
    "armv6l": "arm/armv7",
    "armv7l": "arm/armv7",
    "armv8l": "arm/aarch32",
    "aarch32": "arm/aarch32",
    "aarch64": "arm/aarch64",
    "arm64": "arm/aarch64",
}.get(MACHINE)
if TARGET is None:
    raise SystemExit(f"Неподдерживаемая архитектура: {MACHINE}")

script = ROOT / "arch" / TARGET / "check_theme.py"
sys.path.insert(0, str(script.parent))
os.chdir(script.parent)
sys.argv[0] = str(script)
runpy.run_path(str(script), run_name="__main__")
