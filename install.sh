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
#   $PREFIX/share/cube/cacert.pem
#   $PREFIX/include/cube/*/*.h
#   $PREFIX/lib/liburl.a libtcp.a ...
#
# The archiver is auto-detected (llvm-ar or ar), so a plain GNU toolchain
# works as well as Termux/LLVM.

set -eu

PREFIX="${PREFIX:-}"
DESTDIR=""
DO_BUILD=1

usage() { sed -n '2,19p' "$0"; }

for arg in "$@"; do
    case "$arg" in
        --prefix=*)   PREFIX="${arg#--prefix=}" ;;
        --destdir=*)  DESTDIR="${arg#--destdir=}" ;;
        --no-build)   DO_BUILD=0 ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) echo "install.sh: unknown arg: $arg" >&2; exit 1 ;;
    esac
done

if [ -z "$PREFIX" ]; then
    if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; then
        PREFIX="/data/data/com.termux/files/usr"
    else
        PREFIX="/usr/local"
    fi
fi

BIN_DIR="$DESTDIR$PREFIX/bin"
SHARE_DIR="$DESTDIR$PREFIX/share/cube"
INC_DIR="$DESTDIR$PREFIX/include/cube"
LIB_DIR="$DESTDIR$PREFIX/lib"

cd "$(dirname "$0")"

# ---- Pick an archiver -------------------------------------------------------
# Several Makefiles used to hardcode llvm-ar. Pass the detected one on the
# make command line so the same script works on GNU and LLVM toolchains.
AR_BIN=""
for cand in "${AR:-}" llvm-ar ar; do
    [ -n "$cand" ] || continue
    if command -v "$cand" >/dev/null 2>&1; then
        AR_BIN="$cand"
        break
    fi
done
if [ -z "$AR_BIN" ]; then
    echo "install.sh: no archiver found (install 'ar' or 'llvm-ar')" >&2
    exit 1
fi

RANLIB_BIN=""
for cand in "${RANLIB:-}" llvm-ranlib ranlib; do
    [ -n "$cand" ] || continue
    if command -v "$cand" >/dev/null 2>&1; then
        RANLIB_BIN="$cand"
        break
    fi
done

MAKE_ARGS=(AR="$AR_BIN")
[ -n "$RANLIB_BIN" ] && MAKE_ARGS+=(RANLIB="$RANLIB_BIN")

# crisptls currently needs libsodium's X25519. Fail early with a useful
# message instead of a cryptic "sodium.h: No such file" from the compiler.
if [ "$DO_BUILD" = 1 ] && ! printf '#include <sodium.h>\n' | "${CC:-cc}" -E - >/dev/null 2>&1; then
    echo "install.sh: libsodium headers not found (needed by net/crisptls)" >&2
    echo "  Debian/Ubuntu: sudo apt install libsodium-dev" >&2
    echo "  Fedora/RHEL:   sudo dnf install libsodium-devel" >&2
    echo "  macOS:         brew install libsodium" >&2
    echo "  Termux:        pkg install libsodium" >&2
    exit 1
fi

# ---- Build ------------------------------------------------------------------
if [ "$DO_BUILD" = 1 ]; then
    echo "building... (archiver: $AR_BIN)"
    LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cube-install.XXXXXX")"
    trap 'rm -rf "$LOG_DIR"' EXIT

    # Required to link cube. Order respects header/lib dependencies.
    REQUIRED="utils flywheel/json flywheel/css flywheel/url flywheel/html \
              flywheel/dom net/tcp net/dns net/crisptls net/http_client"
    # Not linked into cube today; a failure here must not block install.
    OPTIONAL="flywheel/js net/quic"

    build_one() {
        dir="$1"
        [ -f "$dir/Makefile" ] || return 0
        echo "  building $dir"
        log="$LOG_DIR/$(echo "$dir" | tr '/' '_').log"
        if ! make -C "$dir" "${MAKE_ARGS[@]}" >"$log" 2>&1; then
            echo "FAILED: $dir" >&2
            sed 's/^/    /' "$log" | tail -40 >&2
            return 1
        fi
        return 0
    }

    for d in $REQUIRED; do
        build_one "$d" || { echo "install.sh: required build failed: $d" >&2; exit 1; }
    done
    for d in $OPTIONAL; do
        if ! build_one "$d"; then
            echo "  warning: optional module failed: $d (continuing)" >&2
        fi
    done

    # Link the top-level cube binary.
    echo "  linking cube"
    rm -f cube
    log="$LOG_DIR/cube-link.log"
    if ! make cube "${MAKE_ARGS[@]}" >"$log" 2>&1; then
        echo "FAILED: cube link" >&2
        sed 's/^/    /' "$log" | tail -40 >&2
        exit 1
    fi
    echo "  cube built"
elif [ ! -f cube ]; then
    echo "install.sh: --no-build given but ./cube does not exist" >&2
    exit 1
fi

# ---- Install ----------------------------------------------------------------
echo "installing to prefix: $PREFIX"
mkdir -p "$BIN_DIR" "$SHARE_DIR" "$INC_DIR" "$LIB_DIR"

# binary
cp cube "$BIN_DIR/"
chmod 755 "$BIN_DIR/cube"

# CA bundle - find_ca_bundle() looks for this at runtime
CA_SRC=""
for c in data/cacert.pem net/crisptls/data/cacert.pem; do
    if [ -f "$c" ]; then CA_SRC="$c"; break; fi
done
if [ -n "$CA_SRC" ]; then
    cp "$CA_SRC" "$SHARE_DIR/"
    echo "  CA bundle: $SHARE_DIR/cacert.pem"
fi

# headers - one subdirectory per library
for d in \
    flywheel/url flywheel/json flywheel/html flywheel/dom flywheel/css \
    flywheel/js net/crisptls net/dns net/tcp net/http_client net/quic
do
    if [ -d "$d/include" ]; then
        name="$(basename "$d")"
        mkdir -p "$INC_DIR/$name"
        cp "$d/include"/*.h "$INC_DIR/$name/" 2>/dev/null || true
    fi
done
# utils keeps its public headers at the module root, not under include/.
if ls utils/*.h >/dev/null 2>&1; then
    mkdir -p "$INC_DIR/utils"
    cp utils/*.h "$INC_DIR/utils/"
fi

# static libraries
find . -type f -name '*.a' -path '*/build/*' -exec cp {} "$LIB_DIR/" \;

echo "installed:"
echo "  binary:  $BIN_DIR/cube"
echo "  CA:      $SHARE_DIR/cacert.pem"
echo "  headers: $INC_DIR/"
echo "  libs:    $LIB_DIR/"

# Custom prefixes are not in the runtime's compiled-in CA search list.
case "$PREFIX" in
    /usr|/usr/local|/data/data/com.termux/files/usr) ;;
    *)
        echo ""
        echo "note: custom prefix '$PREFIX'. If TLS cannot find the CA bundle,"
        echo "      set CUBE_ROOT=$PREFIX or SSL_CERT_FILE=$SHARE_DIR/cacert.pem"
        ;;
esac
