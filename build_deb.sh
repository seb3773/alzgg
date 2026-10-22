#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="${VERSION:-1.0.0-1}"
ARCH="amd64"
DIST_DIR="${SCRIPT_DIR}/dist"
PKG_DIR="${SCRIPT_DIR}/build/pkg_deb"
DEB_NAME="alzgg_${VERSION}_${ARCH}.deb"

echo "=========================================================="
echo "  Building Debian Package: alzgg ${VERSION} (${ARCH})"
echo "=========================================================="

echo "=== Compiling alzgg from source ==="
make clean
make -j"$(nproc)" alzgg

echo "=== Staging Debian package filesystem ==="
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/doc/alzgg"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${DIST_DIR}"

# Install binary
cp -f "${SCRIPT_DIR}/alzgg" "${PKG_DIR}/usr/bin/alzgg"
chmod 755 "${PKG_DIR}/usr/bin/alzgg"

# Documentation
if [ -f "${SCRIPT_DIR}/README.md" ]; then
    cp "${SCRIPT_DIR}/README.md" "${PKG_DIR}/usr/share/doc/alzgg/"
fi
if [ -f "${SCRIPT_DIR}/README.txt" ]; then
    cp "${SCRIPT_DIR}/README.txt" "${PKG_DIR}/usr/share/doc/alzgg/"
fi
if [ -f "${SCRIPT_DIR}/FORMAT-ALZ.md" ]; then
    cp "${SCRIPT_DIR}/FORMAT-ALZ.md" "${PKG_DIR}/usr/share/doc/alzgg/"
fi
if [ -f "${SCRIPT_DIR}/FORMAT-EGG.md" ]; then
    cp "${SCRIPT_DIR}/FORMAT-EGG.md" "${PKG_DIR}/usr/share/doc/alzgg/"
fi

# Copyright notice
cat << 'COPYRIGHT_EOF' > "${PKG_DIR}/usr/share/doc/alzgg/copyright"
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: alzgg
Upstream-Contact: seb3773 <https://github.com/seb3773/alzgg>
Source: https://github.com/seb3773/alzgg

Files: *
Copyright: 2026 seb3773
License: Interoperability / Freestanding C
 Digital format preservation and interoperability under European Directive
 2009/24/EC and French CPI Article L122-6-1 IV.
 "ALZip", ".alz", and ".egg" remain the trademarks and property of ESTsoft Corp.

Files: src/zlib_deflate/*
Copyright: 1995-2024 Jean-loup Gailly and Mark Adler
License: Zlib

Files: src/bzip2_dec/*
Copyright: 1996-2010 Julian R Seward
License: Bzip2

Files: src/lzma_sdk/*
Copyright: Igor Pavlov
License: Public-Domain
COPYRIGHT_EOF

# Control file
cat << CTRL_EOF > "${PKG_DIR}/DEBIAN/control"
Package: alzgg
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: seb3773 <https://github.com/seb3773/alzgg>
Depends: libc6 (>= 2.15)
Provides: alzgg
Description: Bit-exact pure C encoder/decoder for ALZ and EGG archives
 Standalone, freestanding pure C tool combining both compressor and
 decompressor into a single binary (alzgg), achieving 100% bidirectional
 bit-exact parity with ESTsoft ALZip (ALZipCon 12.30 and 8.0).
 Features:
  - Containers: ALZ (.alz) and EGG (.egg) archive creation, listing and extraction
  - Codecs: Store (m0), Deflate (m1/m2), BZip2 (m2), AZO (m3), LZMA (m4)
  - Full Optimized profile routing table reproduced bit for bit (148 extensions)
  - Encryption: ZipCrypto, AES-128/256, and LEA-128/256 block ciphers
  - Split multi-volume archives (.alz, .a01... / .vol1.egg, .vol2.egg...)
  - Solid EGG archives with on-the-fly streaming CRC verification
  - Path traversal & Zip-Slip protection
  - Developed for digital format preservation & interoperability (EU 2009/24/EC)
CTRL_EOF

# Build package
dpkg-deb --build --root-owner-group "${PKG_DIR}" "${DIST_DIR}/${DEB_NAME}"

# Clean temp directory
rm -rf "${PKG_DIR}"

echo ""
echo "=== Package Generated Successfully ==="
ls -lh "${DIST_DIR}/${DEB_NAME}"

echo ""
echo "=== Package Information ==="
dpkg-deb -I "${DIST_DIR}/${DEB_NAME}"

echo ""
echo "=== Package Contents ==="
dpkg-deb -c "${DIST_DIR}/${DEB_NAME}"
