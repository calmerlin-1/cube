#!/usr/bin/env bash
# install.sh - build cube and install to a prefix.
#
# Usage:
#   ./install.sh                       # install to $PREFIX (Termux) or /usr/local (else)
#   ./install.sh --prefix=/opt/cube    # custom prefix
#   ./install.sh --destdir=/tmp/stage  # for package builders
#   ./install.sh --no-build            # skip make, install existing binaries
#
# Installs:
#   $PREFIX/bin/cube
#   $PREFIX/include/cube/*.h
#   $PREFIX/lib/liburl.a libtcp.a ...
#
set -eu

PREFIX=""
DESTDIR=""
DO_BUILD=1

for arg in "$@"; do
    case "$arg" in
        --prefix=*)   PREFIX="${arg#--prefix=}" ;;
        --destdir=*)  DESTDIR="${arg#--destdir=}" ;;
        --no-build)   DO_BUILD=0 ;;
        -h|--help)
            sed -n '2,16p' "$0"
            exit 0
            ;;
        *) echo "install.sh: unknown arg: $arg" >&2; exit 1 ;;
    esac
done

if [ -z "$PREFIX" ]; then
    if [ -n "${PREFIX_TERMUX:-}" ]; then
        PREFIX="$PREFIX_TERMUX"
    elif [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; then
        PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
    else
        PREFIX="/usr/local"
    fi
fi

BIN_DIR="$DESTDIR$PREFIX/bin"
INC_DIR="$DESTDIR$PREFIX/include/cube"
LIB_DIR="$DESTDIR$PREFIX/lib"

cd "$(dirname "$0")"

if [ "$DO_BUILD" = 1 ]; then
    echo "building..."
    make 2>&1 | tail -3
fi

echo "installing to prefix: $PREFIX"
mkdir -p "$BIN_DIR" "$INC_DIR" "$LIB_DIR"

# binary
cp cube "$BIN_DIR/"
chmod 755 "$BIN_DIR/cube"

# CA bundle — find_ca_bundle() looks for this at runtime
SHARE_DIR="$DESTDIR$PREFIX/share/cube"
mkdir -p "$SHARE_DIR"
if [ -f data/cacert.pem ]; then
    cp data/cacert.pem "$SHARE_DIR/"
    echo "  CA bundle: $SHARE_DIR/cacert.pem"
fi

# headers - one subdirectory per library
for d in flywheel/url flywheel/json flywheel/html flywheel/dom flywheel/css \
         net/crisptls net/dns net/tcp net/http_client net/quic \
         utils; do
    if [ -d "$d/include" ]; then
        name="$(basename "$d")"
        mkdir -p "$INC_DIR/$name"
        cp "$d/include"/*.h "$INC_DIR/$name/" 2>/dev/null || true
    fi
done

# static libraries
for f in $(find . -name '*.a' -path '*/build/*' 2>/dev/null); do
    cp "$f" "$LIB_DIR/"
done

echo "installed:"
echo "  binary:  $BIN_DIR/cube"
echo "  headers: $INC_DIR/"
echo "  libs:    $LIB_DIR/"
