# ARM

Деревья исходников dma2box для ARM:

- `armv7/` — ARMv7 / armhf (`armv7l`, `armv6l`);
- `aarch32/` — 32-битный режим ARMv8 (`armv8l`, `aarch32`);
- `aarch64/` — AArch64 / ARM64 (`aarch64`, `arm64`).

Каждое дерево автономное: со своими `build.sh`, `install.sh`, `tests/` и
интерфейсом. Это базовые снимки кода из `arch/x86_64/`, которые адаптируются
независимо друг от друга.
