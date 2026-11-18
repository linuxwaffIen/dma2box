#!/bin/bash
set -euo pipefail

BIN="dist/dma2box.dist/dma2box"
ARCH="${1:-amd64}"

case "$ARCH" in
    amd64)
        DEB_ARCH="amd64"
        PKG_ARCH="x86_64"
        APK_ARCH="x86_64"
        ;;
    arm64)
        DEB_ARCH="arm64"
        PKG_ARCH="aarch64"
        APK_ARCH="aarch64"
        ;;
    *)
        echo "Unknown arch: $ARCH"
        exit 1
        ;;
esac

STAGE="pkg_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/usr/lib/dma2box/app"
mkdir -p "$STAGE/usr/bin"
mkdir -p "$STAGE/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$STAGE/usr/share/applications"

cp -a "$BIN" "$STAGE/usr/lib/dma2box/app/dma2box"
chmod 755 "$STAGE/usr/lib/dma2box/app/dma2box"
ln -s ../lib/dma2box/app/dma2box "$STAGE/usr/bin/dma2box"

cp -a data/io.github.dma2box.Dma2box.svg "$STAGE/usr/share/icons/hicolor/scalable/apps/"
cp -a data/io.github.dma2box.Dma2box.desktop "$STAGE/usr/share/applications/"
cp -a LICENSE README.md "$STAGE/usr/lib/dma2box/"

# Копируем все .so и вспомогательные файлы
cp -a dist/dma2box.dist/helpers "$STAGE/usr/lib/dma2box/app/helpers"
cp -a dist/dma2box.dist/girepository "$STAGE/usr/lib/dma2box/app/girepository"
cp -a dist/dma2box.dist/*.so "$STAGE/usr/lib/dma2box/app/" 2>/dev/null || true
cp -a dist/dma2box.dist/_*.so "$STAGE/usr/lib/dma2box/app/" 2>/dev/null || true
cp -a dist/dma2box.dist/array.so dist/dma2box.dist/zlib.so dist/dma2box.dist/unicodedata.so \
    dist/dma2box.dist/select.so dist/dma2box.dist/pyexpat.so dist/dma2box.dist/mmap.so \
    dist/dma2box.dist/math.so dist/dma2box.dist/grp.so dist/dma2box.dist/binascii.so \
    dist/dma2box.dist/libpython3.14.so.1.0 dist/dma2box.dist/libexpat.so.1 \
    dist/dma2box.dist/libuuid.so.1 dist/dma2box.dist/libssl.so.3 dist/dma2box.dist/liblzma.so.5 \
    dist/dma2box.dist/libbrotlicommon.so.1 dist/dma2box.dist/libzstd.so.1 \
    dist/dma2box.dist/libbrotlidec.so.1 dist/dma2box.dist/libbrotlienc.so.1 \
    dist/dma2box.dist/libcrypto.so.3 dist/dma2box.dist/libmpdec.so.4 \
    dist/dma2box.dist/libffi.so.8 dist/dma2box.dist/libbz2.so.1.0 \
    "$STAGE/usr/lib/dma2box/app/" 2>/dev/null || true

# --- DEB ---
DEB_STAGE="deb_stage"
rm -rf "$DEB_STAGE"
mkdir -p "$DEB_STAGE/DEBIAN"
cat > "$DEB_STAGE/DEBIAN/control" <<DEBCONTROL
Package: dma2box
Version: 0.2.0-1
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: Dma2box contributors <linuxwaffIen@users.noreply.github.com>
Description: Dma2box - VLESS client for Linux (GTK4/libadwaita, sing-box)
 Homepage: https://github.com/linuxwaffIen/dma2ray
DEBCONTROL

# Копируем файлы из STAGING в DEB_STAGE
mkdir -p "$DEB_STAGE/usr/lib/dma2box/app"
mkdir -p "$DEB_STAGE/usr/bin"
mkdir -p "$DEB_STAGE/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$DEB_STAGE/usr/share/applications"
cp -a "$STAGE/usr/lib/dma2box/app/dma2box" "$DEB_STAGE/usr/lib/dma2box/app/dma2box"
chmod 755 "$DEB_STAGE/usr/lib/dma2box/app/dma2box"
ln -s ../lib/dma2box/app/dma2box "$DEB_STAGE/usr/bin/dma2box"
cp -a "$STAGE/usr/share/icons/hicolor/scalable/apps/io.github.dma2box.Dma2box.svg" \
    "$DEB_STAGE/usr/share/icons/hicolor/scalable/apps/"
cp -a "$STAGE/usr/share/applications/io.github.dma2box.Dma2box.desktop" \
    "$DEB_STAGE/usr/share/applications/"
cp -a "$STAGE/usr/lib/dma2box/LICENSE" "$DEB_STAGE/usr/lib/dma2box/LICENSE"
cp -a "$STAGE/usr/lib/dma2box/README.md" "$DEB_STAGE/usr/lib/dma2box/README.md"
cp -a "$STAGE/usr/lib/dma2box/app/helpers" "$DEB_STAGE/usr/lib/dma2box/app/helpers"
cp -a "$STAGE/usr/lib/dma2box/app/girepository" "$DEB_STAGE/usr/lib/dma2box/app/girepository"
cp -a "$STAGE/usr/lib/dma2box/app/"*.so "$DEB_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true
cp -a "$STAGE/usr/lib/dma2box/app/"_*.so "$DEB_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true

dpkg-deb --build "$DEB_STAGE" "dma2box_0.2.0-1_${DEB_ARCH}.deb"
echo "Built: dma2box_0.2.0-1_${DEB_ARCH}.deb"
ls -lh "dma2box_0.2.0-1_${DEB_ARCH}.deb"

# --- ARCH ---
ARCH_STAGE="arch_stage"
rm -rf "$ARCH_STAGE"
mkdir -p "$ARCH_STAGE/usr/lib/dma2box/app"
mkdir -p "$ARCH_STAGE/usr/bin"
mkdir -p "$ARCH_STAGE/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$ARCH_STAGE/usr/share/applications"

cp -a "$BIN" "$ARCH_STAGE/usr/lib/dma2box/app/dma2box"
chmod 755 "$ARCH_STAGE/usr/lib/dma2box/app/dma2box"
ln -s ../lib/dma2box/app/dma2box "$ARCH_STAGE/usr/bin/dma2box"

cp -a data/io.github.dma2box.Dma2box.svg "$ARCH_STAGE/usr/share/icons/hicolor/scalable/apps/"
cp -a data/io.github.dma2box.Dma2box.desktop "$ARCH_STAGE/usr/share/applications/"
cp -a LICENSE README.md "$ARCH_STAGE/usr/lib/dma2box/"
cp -a dist/dma2box.dist/helpers "$ARCH_STAGE/usr/lib/dma2box/app/helpers"
cp -a dist/dma2box.dist/girepository "$ARCH_STAGE/usr/lib/dma2box/app/girepository"
cp -a dist/dma2box.dist/*.so "$ARCH_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true
cp -a dist/dma2box.dist/_*.so "$ARCH_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true
cp -a dist/dma2box.dist/array.so dist/dma2box.dist/zlib.so dist/dma2box.dist/unicodedata.so \
    dist/dma2box.dist/select.so dist/dma2box.dist/pyexpat.so dist/dma2box.dist/mmap.so \
    dist/dma2box.dist/math.so dist/dma2box.dist/grp.so dist/dma2box.dist/binascii.so \
    dist/dma2box.dist/libpython3.14.so.1.0 dist/dma2box.dist/libexpat.so.1 \
    dist/dma2box.dist/libuuid.so.1 dist/dma2box.dist/libssl.so.3 dist/dma2box.dist/liblzma.so.5 \
    dist/dma2box.dist/libbrotlicommon.so.1 dist/dma2box.dist/libzstd.so.1 \
    dist/dma2box.dist/libbrotlidec.so.1 dist/dma2box.dist/libbrotlienc.so.1 \
    dist/dma2box.dist/libcrypto.so.3 dist/dma2box.dist/libmpdec.so.4 \
    dist/dma2box.dist/libffi.so.8 dist/dma2box.dist/libbz2.so.1.0 \
    "$ARCH_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true

cat > "$ARCH_STAGE/.PKGINFO" <<PKGINFO
pkgname = dma2box
pkgver = 0.2.0-1
pkgdesc = Dma2box VLESS client (GTK4/libadwaita, sing-box)
url = https://github.com/linuxwaffIen/dma2ray
arch = $PKG_ARCH
license = GPL-3.0-only
size = 14484153
PKGINFO

bsdtar -cf - -C "$ARCH_STAGE" usr .PKGINFO | zstd -19 -f -o "dma2box-0.2.0-1-${PKG_ARCH}.pkg.tar.zst"
echo "Built: dma2box-0.2.0-1-${PKG_ARCH}.pkg.tar.zst"
ls -lh "dma2box-0.2.0-1-${PKG_ARCH}.pkg.tar.zst"

# --- APK ---
APK_STAGE="apk_stage"
rm -rf "$APK_STAGE"
mkdir -p "$APK_STAGE/usr/lib/dma2box/app"
mkdir -p "$APK_STAGE/usr/bin"
mkdir -p "$APK_STAGE/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$APK_STAGE/usr/share/applications"

cp -a "$BIN" "$APK_STAGE/usr/lib/dma2box/app/dma2box"
chmod 755 "$APK_STAGE/usr/lib/dma2box/app/dma2box"
ln -s ../lib/dma2box/app/dma2box "$APK_STAGE/usr/bin/dma2box"

cp -a data/io.github.dma2box.Dma2box.svg "$APK_STAGE/usr/share/icons/hicolor/scalable/apps/"
cp -a data/io.github.dma2box.Dma2box.desktop "$APK_STAGE/usr/share/applications/"
cp -a LICENSE README.md "$APK_STAGE/usr/lib/dma2box/"
cp -a dist/dma2box.dist/helpers "$APK_STAGE/usr/lib/dma2box/app/helpers"
cp -a dist/dma2box.dist/girepository "$APK_STAGE/usr/lib/dma2box/app/girepository"
cp -a dist/dma2box.dist/*.so "$APK_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true
cp -a dist/dma2box.dist/_*.so "$APK_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true
cp -a dist/dma2box.dist/array.so dist/dma2box.dist/zlib.so dist/dma2box.dist/unicodedata.so \
    dist/dma2box.dist/select.so dist/dma2box.dist/pyexpat.so dist/dma2box.dist/mmap.so \
    dist/dma2box.dist/math.so dist/dma2box.dist/grp.so dist/dma2box.dist/binascii.so \
    dist/dma2box.dist/libpython3.14.so.1.0 dist/dma2box.dist/libexpat.so.1 \
    dist/dma2box.dist/libuuid.so.1 dist/dma2box.dist/libssl.so.3 dist/dma2box.dist/liblzma.so.5 \
    dist/dma2box.dist/libbrotlicommon.so.1 dist/dma2box.dist/libzstd.so.1 \
    dist/dma2box.dist/libbrotlidec.so.1 dist/dma2box.dist/libbrotlienc.so.1 \
    dist/dma2box.dist/libcrypto.so.3 dist/dma2box.dist/libmpdec.so.4 \
    dist/dma2box.dist/libffi.so.8 dist/dma2box.dist/libbz2.so.1.0 \
    "$APK_STAGE/usr/lib/dma2box/app/" 2>/dev/null || true

SIZE=$(stat -c%s "$APK_STAGE/usr/lib/dma2box/app/dma2box")
cat > "$APK_STAGE/.PKGINFO" <<PKGINFO
pkgname = dma2box
pkgver = 0.2.0-r1
pkgdesc = Dma2box VLESS client (GTK4/libadwaita, sing-box)
url = https://github.com/linuxwaffIen/dma2ray
arch = $APK_ARCH
license = GPL-3.0-only
size = $SIZE
PKGINFO

tar --format=ustar -czf "$APK_STAGE/pkg.tar" -C "$APK_STAGE" .PKGINFO usr
gzip -9 -c "$APK_STAGE/pkg.tar" > "dma2box-0.2.0-r1-${APK_ARCH}.apk"
rm -f "$APK_STAGE/pkg.tar"
echo "Built: dma2box-0.2.0-r1-${APK_ARCH}.apk"
ls -lh "dma2box-0.2.0-r1-${APK_ARCH}.apk"