#!/data/data/com.termux/files/usr/bin/bash
# Confirm stateless-reset hypothesis by dumping rsp[0..120] from quic_probe.
set -eu
cd "$(dirname "$0")"

TMPDIR="$(cd .. && pwd)/.tmp"
mkdir -p "$TMPDIR"
DUMP="$TMPDIR/qrsp.bin"
OUT="$TMPDIR/qp.out"

echo "=== 1. back up and inject dump block into quic_probe.c ==="
cp quic_probe.c quic_probe.c.bak

python3 - <<PY
import re
src = open('quic_probe.c').read()
needle = 'printf("[quic_probe] received %zd bytes\\\\n", rn);'
inject = needle + ' { FILE *f_ = fopen("'"$DUMP"'","wb"); if (f_) { fwrite(rsp,1,rn,f_); fclose(f_); } }'
if needle in src:
    src = src.replace(needle, inject, 1)
    open('quic_probe.c','w').write(src)
    print("injected dump -> $DUMP")
else:
    print("NEEDLE NOT FOUND")
PY

echo ""
echo "=== 2. rebuild and run ==="
make clean >/dev/null 2>&1
make quic_probe >/dev/null 2>&1 || { echo "BUILD FAILED"; tail -20; exit 1; }
rm -f "$DUMP"
./quic_probe 162.159.137.85 443 cloudflare-quic.com >"$OUT" 2>&1 || true
tail -20 "$OUT"

echo ""
echo "=== 3. response dump analysis ==="
if [ -f "$DUMP" ]; then
    SZ=$(wc -c < "$DUMP")
    echo "response file size: $SZ bytes"
    echo ""
    echo "first 80 bytes (hex, 16 per line):"
    od -An -tx1 -v -N80 "$DUMP" | sed 's/^ *//' | fold -w 48 | head -6
    echo ""
    echo "bytes 56-96 (the region right after the 20-byte SCID):"
    dd if="$DUMP" bs=1 skip=56 count=40 2>/dev/null | od -An -tx1 -v
    echo ""
    echo "last byte (byte 1199):"
    dd if="$DUMP" bs=1 skip=1199 count=1 2>/dev/null | od -An -tx1 -v
    echo ""
    echo "bytes 63-80 (hypothesis: all zeros = UDP padding after 63-byte QUIC packet):"
    dd if="$DUMP" bs=1 skip=63 count=18 2>/dev/null | od -An -tx1 -v
    echo ""
    echo "bytes 61-65 (last 2 bytes of '23-byte payload' + padding start):"
    dd if="$DUMP" bs=1 skip=61 count=5 2>/dev/null | od -An -tx1 -v
else
    echo "(no dump file — dump block didn't execute)"
fi

echo ""
echo "=== 4. interpretation ==="
echo "  header 38 bytes (first+ver+dcid_len+dcid+scid_len+scid+tok_len)"
echo "  PN 2 bytes (at offset 38)"
echo "  payload 23 bytes per length varint (at offsets 40..62)"
echo "  total QUIC packet: 63 bytes"
echo "  remaining 63..1199 = $(($SZ - 63)) bytes of UDP-level padding"

echo ""
echo "=== 5. restore quic_probe.c ==="
mv quic_probe.c.bak quic_probe.c
