#!/data/data/com.termux/files/usr/bin/bash
set -eu
cd "$(dirname "$0")"

TMPDIR="$(cd .. && pwd)/.tmp"
mkdir -p "$TMPDIR"
PKT="$TMPDIR/quic_out.bin"
RSP="$TMPDIR/quic_rsp.bin"
LOG="$TMPDIR/quic_full.log"

echo "=== 1. back up and instrument quic_probe for full dump ==="
cp quic_probe.c quic_probe.c.bak

python3 - <<PY
import re
src = open('quic_probe.c').read()

# Dump the CLIENT packet just before udp_send
needle_send = 'if (udp_send(fd, pkt, p, 5000) != 0) {'
inject_send = '    { FILE *f_ = fopen("'"$PKT"'","wb"); if (f_) { fwrite(pkt,1,p,f_); fclose(f_); } }\n' + needle_send
if needle_send in src:
    src = src.replace(needle_send, inject_send, 1)

# Dump the SERVER response just after udp_recv succeeds
needle_recv = 'printf("[quic_probe] received %zd bytes\\\\n", rn);'
inject_recv = needle_recv + ' { FILE *f_ = fopen("'"$RSP"'","wb"); if (f_) { fwrite(rsp,1,rn,f_); fclose(f_); } }'
if needle_recv in src:
    src = src.replace(needle_recv, inject_recv, 1)

open('quic_probe.c','w').write(src)
print("instrumented")
PY

echo ""
echo "=== 2. rebuild and run ==="
make clean >/dev/null 2>&1
make quic_probe >/dev/null 2>&1 || { echo "BUILD FAILED"; tail -20; exit 1; }
rm -f "$PKT" "$RSP"
./quic_probe 162.159.137.85 443 cloudflare-quic.com >"$LOG" 2>&1 || true
cat "$LOG"

echo ""
echo "=== 3. CLIENT packet ($(wc -c < "$PKT" 2>/dev/null || echo 0) bytes) — first 120 ==="
if [ -f "$PKT" ]; then
    od -An -tx1 -v -N120 "$PKT" | sed 's/^ *//' | fold -w 48 | head -8
else
    echo "(no client dump)"
fi

echo ""
echo "=== 4. SERVER response ($(wc -c < "$RSP" 2>/dev/null || echo 0) bytes) — first 120 ==="
if [ -f "$RSP" ]; then
    od -An -tx1 -v -N120 "$RSP" | sed 's/^ *//' | fold -w 48 | head -8
else
    echo "(no server dump)"
fi

echo ""
echo "=== 5. QUIC decode of server response — manual field extraction ==="
if [ -f "$RSP" ]; then
    python3 - "$RSP" <<'PY'
import sys
b = open(sys.argv[1],'rb').read()
print(f"total {len(b)} bytes")
print(f"first_byte = 0x{b[0]:02x}  (long={b[0]>>7} fixed={(b[0]>>6)&1} type={(b[0]>>4)&3} pn_len={(b[0]&3)+1})")
print(f"version    = 0x{b[1]:02x}{b[2]:02x}{b[3]:02x}{b[4]:02x}")
q = 5
dcid_len = b[q]; q += 1
print(f"dcid_len   = {dcid_len}")
print(f"dcid       = {b[q:q+dcid_len].hex()}"); q += dcid_len
scid_len = b[q]; q += 1
print(f"scid_len   = {scid_len}")
print(f"scid       = {b[q:q+scid_len].hex()}"); q += scid_len
# token length varint
def varint(bb, off):
    v = bb[off]
    if v < 0x40: return v, 1
    if v < 0x80: return ((v & 0x3f) << 8) | bb[off+1], 2
    if v < 0xc0: return (((v & 0x3f) << 24) | (bb[off+1]<<16) | (bb[off+2]<<8) | bb[off+3]), 4
    return (((v & 0x3f) << 56) | (bb[off+1]<<48) | (bb[off+2]<<40) | (bb[off+3]<<32) | (bb[off+4]<<24) | (bb[off+5]<<16) | (bb[off+6]<<8) | bb[off+7]), 8

tok_len, nb = varint(b, q); q += nb
print(f"token_len  = {tok_len}  ({nb}-byte varint)")
q += tok_len
len_val, nb = varint(b, q)
print(f"length     = {len_val}  ({nb}-byte varint)  <- this should be ~1160 for a real Initial")
q += nb
pn_len = (b[0] & 3) + 1
print(f"pn_offset  = {q}, pn_len={pn_len}")
print(f"payload bytes after PN: {len_val - pn_len - 16} ciphertext + 16 tag = {len_val - pn_len}")
print(f"packet ends at byte {q + len_val}")
PY
fi

echo ""
echo "=== 6. restore ==="
mv quic_probe.c.bak quic_probe.c
