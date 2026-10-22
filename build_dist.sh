#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="${VERSION:-12.30.0}"
ARCH="linux-x86_64"
DIST_DIR="${SCRIPT_DIR}/dist"
TAR_NAME="alzgg-v${VERSION}-${ARCH}.tar.gz"
STAGE_DIR="${SCRIPT_DIR}/build/tar_stage/alzgg-v${VERSION}-${ARCH}"

echo "=========================================================="
echo "  Building Full Distribution Packages: alzgg v${VERSION}"
echo "=========================================================="

mkdir -p "${DIST_DIR}"

echo "=== 1. Building release binary ==="
make clean
make -j"$(nproc)" alzgg

echo "=== 2. Creating .tar.gz binary distribution package ==="
rm -rf "${SCRIPT_DIR}/build/tar_stage"
mkdir -p "${STAGE_DIR}"

cp -f "${SCRIPT_DIR}/alzgg" "${STAGE_DIR}/"
chmod 755 "${STAGE_DIR}/alzgg"

if [ -f "${SCRIPT_DIR}/README.txt" ]; then
    cp "${SCRIPT_DIR}/README.txt" "${STAGE_DIR}/"
fi
if [ -f "${SCRIPT_DIR}/README.md" ]; then
    cp "${SCRIPT_DIR}/README.md" "${STAGE_DIR}/"
fi
if [ -f "${SCRIPT_DIR}/FORMAT-ALZ.md" ]; then
    cp "${SCRIPT_DIR}/FORMAT-ALZ.md" "${STAGE_DIR}/"
fi
if [ -f "${SCRIPT_DIR}/FORMAT-EGG.md" ]; then
    cp "${SCRIPT_DIR}/FORMAT-EGG.md" "${STAGE_DIR}/"
fi

tar -czf "${DIST_DIR}/${TAR_NAME}" -C "${SCRIPT_DIR}/build/tar_stage" "alzgg-v${VERSION}-${ARCH}"
rm -rf "${SCRIPT_DIR}/build/tar_stage"

echo "Tarball created: ${DIST_DIR}/${TAR_NAME}"

echo ""
echo "=== 3. Creating Debian .deb package ==="
VERSION="${VERSION}-1" ./build_deb.sh

echo ""
echo "=== 4. Generating SHA256 checksums ==="
cd "${DIST_DIR}"
sha256sum *.deb *.tar.gz > SHA256SUMS
cd "$SCRIPT_DIR"

echo ""
echo "=========================================================="
echo "  Distribution Artifacts in ${DIST_DIR}:"
echo "=========================================================="
ls -lh "${DIST_DIR}"
cat "${DIST_DIR}/SHA256SUMS"
echo ""
echo "=== Distribution packaging finished successfully ==="
