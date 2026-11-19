"""Embedded icons for Dma2box."""

from __future__ import annotations

APP_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#3584e4"/>
      <stop offset="1" stop-color="#1a5fb4"/>
    </linearGradient>
    <linearGradient id="shield" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset="1" stop-color="#dbe9ff"/>
    </linearGradient>
  </defs>
  <rect width="128" height="128" rx="28" fill="url(#bg)"/>
  <path d="M64 18 102 32v30c0 24-16 41-38 50-22-9-38-26-38-50V32z" fill="url(#shield)" opacity="0.96"/>
  <path d="M64 30 90 39v23c0 17-11 29-26 36-15-7-26-19-26-36V39z" fill="#1c71d8" opacity="0.16"/>
  <path d="M45 61l12 12 26-27" fill="none" stroke="#1c71d8" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""

_TRAY_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <path d="M32 4 56 13v17c0 15-10 25-24 30C18 55 8 45 8 30V13z" fill="{bg}"/>
  <path d="M32 10 50 17v13c0 11-7 19-18 23-11-4-18-12-18-23V17z" fill="{fg}"/>
  {mark}
</svg>
"""

TRAY_ICONS: dict[str, str] = {
    "stopped": _TRAY_TEMPLATE.format(
        bg="#77767b",
        fg="#f6f5f4",
        mark='<path d="M22 32h20" fill="none" stroke="#5e5c64" stroke-width="5" stroke-linecap="round"/>',
    ),
    "starting": _TRAY_TEMPLATE.format(
        bg="#62a0ea",
        fg="#ffffff",
        mark=(
            '<circle cx="23" cy="32" r="3.5" fill="#1c5aa8"/>'
            '<circle cx="32" cy="32" r="3.5" fill="#1c5aa8"/>'
            '<circle cx="41" cy="32" r="3.5" fill="#1c5aa8"/>'
        ),
    ),
    "running": _TRAY_TEMPLATE.format(
        bg="#26a269",
        fg="#ffffff",
        mark='<path d="M21 32l7 7 15-16" fill="none" stroke="#1b6e46" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>',
    ),
}

VPN_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M8 1L2 3.5V8c0 3.7 2.6 6.4 6 7 3.4-.6 6-3.3 6-7V3.5L8 1zm0 2.2l4 1.7v3.1c0 2.6-1.7 4.6-4 5.2-2.3-.6-4-2.6-4-5.2V4.9l4-1.7z" fill="currentColor"/>
</svg>
"""

SPEED_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M5 2L1 6h3v5h2V6h3L5 2zm6 3v5H8l4 4 4-4h-3V5h-2z" fill="currentColor"/>
</svg>
"""

SIGNAL_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <rect x="1" y="11" width="2" height="4" rx="0.5" fill="currentColor"/>
  <rect x="5" y="8" width="2" height="7" rx="0.5" fill="currentColor"/>
  <rect x="9" y="5" width="2" height="10" rx="0.5" fill="currentColor"/>
  <rect x="13" y="2" width="2" height="13" rx="0.5" fill="currentColor"/>
</svg>
"""

STOP_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <rect x="3" y="3" width="10" height="10" rx="1.5" fill="currentColor"/>
</svg>
"""

SYSTEM_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M7 1v1.1a5 5 0 0 0-1.9.8l-.8-.8-1.4 1.4.8.8A5 5 0 0 0 2.9 6.2H1.8v2h1.1a5 5 0 0 0 .8 1.9l-.8.8 1.4 1.4.8-.8a5 5 0 0 0 1.9.8v1.1h2v-1.1a5 5 0 0 0 1.9-.8l.8.8 1.4-1.4-.8-.8a5 5 0 0 0 .8-1.9h1.1v-2h-1.1a5 5 0 0 0-.8-1.9l.8-.8-1.4-1.4-.8.8A5 5 0 0 0 9 2.1V1H7zm1 4.2a2.8 2.8 0 1 1 0 5.6 2.8 2.8 0 0 1 0-5.6z" fill="currentColor"/>
</svg>
"""

SECURITY_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M8 1L2 3.5v5c0 3.7 2.6 6.4 6 7 3.4-.6 6-3.3 6-7v-5L8 1zm0 2.2l4 1.7v3.6c0 2.6-1.7 4.6-4 5.2-2.3-.6-4-2.6-4-5.2V4.9l4-1.7z" fill="currentColor"/>
</svg>
"""

EDIT_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M12.3.8c-.6 0-1.2.2-1.7.7l-9 9c-.4.4-.6.9-.6 1.4v3h3c.5 0 1-.2 1.4-.6l9-9c.9-.9.9-2.5 0-3.4-.6-.7-1.4-1.1-2.1-1.1zm-1.8 3.6l1.1 1.1-7.1 7.1-1.1-1.1 7.1-7.1z" fill="currentColor"/>
</svg>
"""

APPLY_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M13.7 4.7a1 1 0 0 0-1.4-1.4L6 9.6 3.7 7.3a1 1 0 0 0-1.4 1.4l3 3c.4.4 1 .4 1.4 0l7-7z" fill="currentColor"/>
</svg>
"""

WIRELESS_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M8 2.5a11 11 0 0 1 7.8 3.2l-1.4 1.4A9 9 0 0 0 8 4.5a9 9 0 0 0-6.4 2.6L.2 5.7A11 11 0 0 1 8 2.5zm0 4a7 7 0 0 1 4.9 2l-1.4 1.5A5 5 0 0 0 8 8.5a5 5 0 0 0-3.5 1.5L3.1 8.5a7 7 0 0 1 4.9-2zm0 4a3 3 0 0 1 2.1.9L8 13.5l-2.1-2.1A3 3 0 0 1 8 10.5z" fill="currentColor"/>
</svg>
"""

WIRED_ICON_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">
  <path d="M4 2a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h3v2H5v1h6v-1H9v-2h3a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H4zm0 2h8v6H4V4z" fill="currentColor"/>
</svg>
"""

# Small, filled symbolic glyphs designed as one family. `currentColor` lets
# GTK recolor them from the active light/dark palette without raster assets.
_SYMBOLIC_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
  <path fill="currentColor" d="{path}"/>
</svg>
'''

SYMBOLIC_ICONS: dict[str, str] = {
    "dma2box-server-symbolic": "M4 3h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm0 10h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2Zm2-7a1 1 0 1 0 0 2 1 1 0 0 0 0-2Zm0 10a1 1 0 1 0 0 2 1 1 0 0 0 0-2Zm11-10a1 1 0 1 0 0 2 1 1 0 0 0 0-2Zm0 10a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z",
    "dma2box-subscription-symbolic": "M6 2h8l5 5v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Zm7 2v4h4M8 12h8v2H8zm0 4h8v2H8z",
    "dma2box-route-symbolic": "M5 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6Zm14 12a3 3 0 1 0 0 6 3 3 0 0 0 0-6ZM8 5h6a4 4 0 0 1 4 4v3h-2V9a2 2 0 0 0-2-2H8V5Zm8 5 3 3 3-3h-6ZM5 10h2v5a2 2 0 0 0 2 2h5v2H9a4 4 0 0 1-4-4v-5Z",
    "dma2box-speed-symbolic": "M12 3a9 9 0 1 0 8.5 12h-3.2a6 6 0 1 1 0-6H21A9 9 0 0 0 12 3Zm5.2 5.2-4.1 4.1a2 2 0 1 1-1.4-1.4l4.1-4.1 1.4 1.4Z",
    "dma2box-shield-symbolic": "M12 2 3.5 5v6.1c0 5.1 3.5 9.1 8.5 10.9 5-1.8 8.5-5.8 8.5-10.9V5L12 2Zm-1.2 13.8-3.4-3.4 1.7-1.7 1.7 1.7 4.1-4.1 1.7 1.7-5.8 5.8Z",
    "dma2box-globe-symbolic": "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20Zm6.9 9h-3a15 15 0 0 0-1.4-5.1 8 8 0 0 1 4.4 5.1ZM12 4c1.1 1.5 1.8 4 2 7h-4c.2-3 1-5.5 2-7ZM4.1 13h3a15 15 0 0 0 1.4 5.1A8 8 0 0 1 4.1 13Zm3-2h-3a8 8 0 0 1 4.4-5.1A15 15 0 0 0 7.1 11Zm4.9 9c-1.1-1.5-1.8-4-2-7h4c-.2 3-1 5.5-2 7Zm2.5-1.9a15 15 0 0 0 1.4-5.1h3a8 8 0 0 1-4.4 5.1Z",
    "dma2box-qr-symbolic": "M3 3h8v8H3V3Zm2 2v4h4V5H5Zm8-2h8v8h-8V3Zm2 2v4h4V5h-4ZM3 13h8v8H3v-8Zm2 2v4h4v-4H5Zm8-2h3v3h-3v-3Zm5 0h3v5h-3v-2h-2v-3h2Zm-5 5h3v3h-3v-3Zm5 2h3v1h-3v-1Z",
    "dma2box-import-symbolic": "M11 2h2v10l3.5-3.5 1.4 1.4-5.9 5.9-5.9-5.9 1.4-1.4L11 12V2ZM4 16h2v3h12v-3h2v5H4v-5Z",
    "dma2box-add-symbolic": "M11 3h2v8h8v2h-8v8h-2v-8H3v-2h8V3Z",
    "dma2box-refresh-symbolic": "M12 4a8 8 0 0 1 7.5 5H22l-4 4-4-4h2.3A5.5 5.5 0 0 0 6 8l-2-1.1A8 8 0 0 1 12 4Zm-8 7 4 4h-2.3A5.5 5.5 0 0 0 18 16l2 1.1A8 8 0 0 1 4.5 15H2l2-4Z",
    "dma2box-settings-symbolic": "M19.4 13a7.7 7.7 0 0 0 0-2l2-1.5-2-3.5-2.4 1a8 8 0 0 0-1.7-1L15 3h-6l-.4 3a8 8 0 0 0-1.7 1l-2.4-1-2 3.5 2 1.5a7.7 7.7 0 0 0 0 2l-2 1.5 2 3.5 2.4-1a8 8 0 0 0 1.7 1L9 22h6l.4-3a8 8 0 0 0 1.7-1l2.4 1 2-3.5-2.1-1.5ZM12 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7Z",
    "dma2box-copy-symbolic": "M8 3h11a2 2 0 0 1 2 2v12h-2V5H8V3ZM5 7h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2Zm0 2v10h10V9H5Z",
    "dma2box-check-symbolic": "m9.2 17.2-5-5 1.8-1.8 3.2 3.2 8.8-8.8 1.8 1.8-10.6 10.6Z",
    "dma2box-trash-symbolic": "M8 3h8l1 2h4v2H3V5h4l1-2Zm-3 6h14l-1 12H6L5 9Zm4 2v8h2v-8H9Zm4 0v8h2v-8h-2Z",
    "dma2box-sort-symbolic": "M4 5h16v2H4V5Zm0 6h11v2H4v-2Zm0 6h6v2H4v-2Z",
    "dma2box-stop-symbolic": "M6 4h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z",
}

SYMBOLIC_ICONS = {
    name: _SYMBOLIC_TEMPLATE.format(path=path)
    for name, path in SYMBOLIC_ICONS.items()
}

ICONS: dict[str, str] = {
    "io.github.dma2box.Dma2box": APP_ICON_SVG,
    "dma2box-tray-stopped": TRAY_ICONS["stopped"],
    "dma2box-tray-starting": TRAY_ICONS["starting"],
    "dma2box-tray-running": TRAY_ICONS["running"],
    "network-vpn-symbolic": VPN_ICON_SVG,
    "network-transmit-receive-symbolic": SPEED_ICON_SVG,
    "network-receive-symbolic": SPEED_ICON_SVG,
    "network-cellular-signal-excellent-symbolic": SIGNAL_ICON_SVG,
    "network-wireless-signal-excellent-symbolic": WIRELESS_ICON_SVG,
    "network-wired-symbolic": WIRED_ICON_SVG,
    "media-playback-stop-symbolic": STOP_ICON_SVG,
    "applications-system-symbolic": SYSTEM_ICON_SVG,
    "security-high-symbolic": SECURITY_ICON_SVG,
    "document-edit-symbolic": EDIT_ICON_SVG,
    "adw-entry-apply-symbolic": APPLY_ICON_SVG,
    **SYMBOLIC_ICONS,
}
