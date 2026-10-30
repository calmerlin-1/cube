#!/bin/sh
set -eu
CUBE=${CUBE:-../cube}
PORT=${PORT:-18099}
build/server "$PORT" >/dev/null 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 0.3

check() {
    got=$("$CUBE" -b "$1")
    if [ "$got" != "$2" ]; then
        echo "FAIL $1: expected [$2] got [$got]"
        exit 1
    fi
    echo "PASS $1"
}

check "http://127.0.0.1:$PORT/" 'hello'
check "http://127.0.0.1:$PORT/gzip" 'hello gzip'
check "http://127.0.0.1:$PORT/deflate" 'hello deflate'
check "http://127.0.0.1:$PORT/chunked" "$(printf 'alpha\nbeta')"
check "http://127.0.0.1:$PORT/redirect" 'final'
check "http://127.0.0.1:$PORT/eof" 'eof body'
echo "ALL SERVER SMOKE TESTS PASSED"
