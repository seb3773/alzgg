#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="release"
ACTION="build"
MAKE_ARGS=()

for arg in "$@"; do
    case "$arg" in
        debug|-DEBUG|--debug|DEBUG=1)
            MODE="debug"
            ;;
        release|--release)
            MODE="release"
            ;;
        sanitize|--sanitize|asan)
            ACTION="sanitize"
            ;;
        clean)
            ACTION="clean"
            ;;
        test)
            ACTION="test"
            ;;
        heavy)
            ACTION="heavy"
            ;;
        deb)
            ACTION="deb"
            ;;
        dist|package|tar)
            ACTION="dist"
            ;;
        install)
            ACTION="install"
            ;;
        uninstall)
            ACTION="uninstall"
            ;;
        help|-h|--help)
            ACTION="help"
            ;;
        *)
            MAKE_ARGS+=("$arg")
            ;;
    esac
done

if [ "$ACTION" = "help" ]; then
    echo "=========================================================="
    echo "  alzgg build script (Pure C ALZ/EGG Archiver)"
    echo "=========================================================="
    echo "Usage: $0 [command/option]"
    echo ""
    echo "Commands:"
    echo "  (default)  Build release binary (alzgg)"
    echo "  debug      Build debug binary with symbols and no optimization"
    echo "  sanitize   Build and test with ASan/UBSan/LSan"
    echo "  test       Run the full test suite (make test)"
    echo "  heavy      Run heavy multi-block test (5 GiB)"
    echo "  deb        Build Debian .deb package in dist/"
    echo "  dist       Build both .deb and .tar.gz packages in dist/"
    echo "  install    Install binary to /usr/local/bin (or PREFIX)"
    echo "  uninstall  Remove installed binary"
    echo "  clean      Clean all build artifacts and packaging directories"
    exit 0
fi

if [ "$ACTION" = "clean" ]; then
    make clean
    rm -rf dist build
    echo "Cleaned build artifacts, build/ and dist/."
    exit 0
fi

if [ "$ACTION" = "test" ]; then
    make test
    exit 0
fi

if [ "$ACTION" = "heavy" ]; then
    make heavy
    exit 0
fi

if [ "$ACTION" = "sanitize" ]; then
    make sanitize
    exit 0
fi

if [ "$ACTION" = "deb" ]; then
    chmod +x build_deb.sh
    ./build_deb.sh
    exit 0
fi

if [ "$ACTION" = "dist" ]; then
    chmod +x build_dist.sh
    ./build_dist.sh
    exit 0
fi

if [ "$ACTION" = "install" ]; then
    make install
    exit 0
fi

if [ "$ACTION" = "uninstall" ]; then
    make uninstall
    exit 0
fi

echo "=========================================================="
if [ "$MODE" = "debug" ]; then
    echo "  Building alzgg (DEBUG mode)"
    make debug "${MAKE_ARGS[@]}"
else
    echo "  Building alzgg (Release mode)"
    make -j"$(nproc)" "${MAKE_ARGS[@]}"
fi
echo "=========================================================="

echo ""
echo "=== Summary of Generated Binaries ==="
if [ -f "$SCRIPT_DIR/alzgg" ]; then
    ls -lh "$SCRIPT_DIR/alzgg"
fi
echo "Done."
