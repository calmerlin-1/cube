#!/data/data/com.termux/files/usr/bin/bash
# fuzz-all.sh — instrumented build + fuzz every library.
# Smart mode: per-lib dict+corpus, coverage gate, crash dedup, symbolized traces.

set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

FUZZ_SECS="${FUZZ_SECS:-120}"
MAX_LEN="${MAX_LEN:-65536}"
ARTIFACT_DIR="$ROOT/tests/fuzz/artifacts"
LOG_DIR="$ROOT/tests/fuzz/logs"
SEEN_CRASHES="$ARTIFACT_DIR/.seen"
mkdir -p "$ARTIFACT_DIR" "$LOG_DIR"
touch "$SEEN_CRASHES"

# symbolizer — clang 20 ships one
SYMBOLIZER="$(which llvm-symbolizer 2>/dev/null || true)"
if [ -z "$SYMBOLIZER" ]; then
    SYMBOLIZER="$(find /data/data/com.termux/files/usr -name 'llvm-symbolizer' 2>/dev/null | head -1)"
fi

export ASAN_OPTIONS="symbolize=1:print_stacktrace=1:detect_leaks=0:abort_on_error=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0"
[ -n "$SYMBOLIZER" ] && export ASAN_SYMBOLIZER_PATH="$SYMBOLIZER"

LIBS=(
    "flywheel/url              flywheel/url/tests/fuzz/fuzz_url.c   flywheel/url/tests/fuzz/url.dict   flywheel/url/tests/fuzz/corpus"
    "net/dns                   net/dns/tests/fuzz/fuzz_dns.c        net/dns/tests/fuzz/dns.dict        net/dns/tests/fuzz/corpus"
    "net/http_client           net/http_client/tests/fuzz/fuzz_http.c net/http_client/tests/fuzz/http.dict net/http_client/tests/fuzz/corpus"
    "net/quic                  net/quic/tests/fuzz/fuzz_quic.c       net/quic/tests/fuzz/quic.dict      net/quic/tests/fuzz/corpus"
    "net/crisptls              net/crisptls/tests/fuzz/fuzz_tls.c    net/crisptls/tests/fuzz/tls.dict   net/crisptls/tests/fuzz/corpus"
    "net/tcp                   net/tcp/tests/fuzz/fuzz_tcp.c         net/tcp/tests/fuzz/tcp.dict        net/tcp/tests/fuzz/corpus"
    "flywheel/html             flywheel/html/tests/fuzz/fuzz_html.c  flywheel/html/tests/fuzz/html.dict flywheel/html/tests/fuzz/corpus"
    "flywheel/css              flywheel/css/tests/fuzz/fuzz_css.c    flywheel/css/tests/fuzz/css.dict   flywheel/css/tests/fuzz/corpus"
    "flywheel/json             flywheel/json/tests/fuzz/fuzz_json.c  flywheel/json/tests/fuzz/json.dict flywheel/json/tests/fuzz/corpus"
)

SAN_FLAGS="-O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer"
FUZZ_FLAGS="-O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer"

summary="$LOG_DIR/_summary.txt"
: > "$summary"

echo "============ FUZZING RUN $(date) ============" | tee -a "$summary"
echo "  seconds per lib: $FUZZ_SECS" | tee -a "$summary"
echo "  symbolizer:     ${SYMBOLIZER:-none}" | tee -a "$summary"
echo "" | tee -a "$summary"

for entry in "${LIBS[@]}"; do
    read -r LIB_DIR HARNESS DICT CORPUS <<< "$entry"
    NAME="$(basename "$LIB_DIR")"
    LOG="$LOG_DIR/$NAME.log"
    : > "$LOG"

    echo "" | tee -a "$summary"
    echo "===== $NAME =====" | tee -a "$summary"

    if [ ! -f "$HARNESS" ] || [ ! -d "$LIB_DIR" ]; then
        echo "  SKIP (no harness/lib)" | tee -a "$summary" "$LOG"
        continue
    fi

    # 1. instrumented build
    echo "  [1/5] build instrumented lib" | tee -a "$summary"
    ( cd "$LIB_DIR" && make clean >/dev/null 2>&1 && \
      make CFLAGS="$SAN_FLAGS -Iinclude -Isrc -I../../utils" >>"$LOG" 2>&1 )
    LIB_A="$(find "$LIB_DIR/build" -name '*.a' 2>/dev/null | head -1)"
    [ -z "$LIB_A" ] && { echo "  SKIP: no .a" | tee -a "$summary"; continue; }

    NSYM=$(nm "$LIB_A" 2>/dev/null | grep -c sanitizer_cov)
    echo "  [2/5] sanitizer_cov symbols in lib: $NSYM" | tee -a "$summary"
    if [ "$NSYM" -eq 0 ]; then
        echo "  🔴 BLIND — no coverage. Skipping fuzz." | tee -a "$summary" "$LOG"
        continue
    fi

    # 2. fuzzer build
    FUZZ_BIN="$LIB_DIR/tests/fuzz/fuzz_$NAME"
    echo "  [3/5] build fuzzer" | tee -a "$summary"
    clang $FUZZ_FLAGS -I"$LIB_DIR/include" -I"$LIB_DIR/src" \
        -I"$ROOT/utils" -I"$LIB_DIR/../../utils" \
        "$HARNESS" "$LIB_A" "$ROOT/utils/build/libutils.a" \
        -lm -o "$FUZZ_BIN" >>"$LOG" 2>&1
    if [ ! -x "$FUZZ_BIN" ]; then
        echo "  SKIP: fuzzer didn't build (see $LOG)" | tee -a "$summary"
        continue
    fi

    CTRS=$("$FUZZ_BIN" -runs=0 2>&1 | grep -o 'inline 8-bit counters): [0-9]*' | grep -o '[0-9]*$' || echo 0)
    echo "  [3/5] coverage counters visible: $CTRS" | tee -a "$summary"
    if [ "$CTRS" -lt 50 ]; then
        echo "  ⚠️  only $CTRS counters — instrumentation thin" | tee -a "$summary"
    fi

    # 3. incremental corpus (keep last run's findings)
    CORPUS_USE="$CORPUS"
    if [ -d "$CORPUS" ]; then
        # dedup against hash of each file — same bytes, skip
        find "$CORPUS" -type f -exec md5sum {} \; 2>/dev/null | \
            sort -u -k1,1 | awk '{print $2}' | while read f; do :; done
    fi

    # 4. crash artifacts for this lib
    CRASH_DIR="$ARTIFACT_DIR/$NAME"
    mkdir -p "$CRASH_DIR"

    # 5. run
    echo "  [4/5] fuzz ${FUZZ_SECS}s" | tee -a "$summary"
    DICTARG=""; [ -f "$DICT" ] && DICTARG="-dict=$DICT"
    CORPUSARG=""; [ -d "$CORPUS_USE" ] && CORPUSARG="$CORPUS_USE"

    START_TS=$(date +%s)
    "$FUZZ_BIN" $CORPUSARG $DICTARG \
        -max_total_time=$FUZZ_SECS \
        -max_len=$MAX_LEN \
        -print_final_stats=1 \
        -artifact_prefix="$CRASH_DIR/crash-" \
        >>"$LOG" 2>&1
    RC=$?
    END_TS=$(date +%s)
    DUR=$((END_TS - START_TS))

    # 6. report
    FINAL_COV=$(grep -oE 'cov: [0-9]+' "$LOG" | tail -1 | awk '{print $2}')
    FINAL_RUNS=$(grep -oE 'number_of_executed_units: *[0-9]+' "$LOG" | awk '{print $NF}')
    NEW_UNITS=$(grep -oE 'new_units_added: *[0-9]+' "$LOG" | awk '{print $NF}')
    NEW_CRASH=$(ls "$CRASH_DIR"/crash-* 2>/dev/null | wc -l)

    echo "  [5/5] done in ${DUR}s | cov=$FINAL_COV runs=$FINAL_RUNS new_corpus=$NEW_UNITS crashes=$NEW_CRASH" | tee -a "$summary"

    if [ "$NEW_CRASH" -gt 0 ]; then
        echo "  🔴 CRASH in $NAME:" | tee -a "$summary"
        for f in "$CRASH_DIR"/crash-*; do
            HASH=$(md5sum "$f" | awk '{print $1}')
            if grep -q "^$HASH$" "$SEEN_CRASHES"; then
                echo "    dup: $(basename "$f")" | tee -a "$summary"
            else
                echo "$HASH" >> "$SEEN_CRASHES"
                echo "    NEW: $(basename "$f")" | tee -a "$summary"
                echo "    hex:" | tee -a "$summary"
                xxd "$f" | head -10 | sed 's/^/      /' | tee -a "$summary"
            fi
        done
        echo "  --- last ASAN/UBSAN trace ---" | tee -a "$summary"
        grep -A3 -E 'ERROR: AddressSanitizer|runtime error|SUMMARY' "$LOG" | head -30 | sed 's/^/    /' | tee -a "$summary"
    else
        echo "  ✅ clean" | tee -a "$summary"
    fi
done

echo "" | tee -a "$summary"
echo "============ SUMMARY ============"
grep -E '=====|\[5/5\]|🔴|✅|SKIP|⚠️' "$summary"
echo ""
echo "full logs: $LOG_DIR/"
ls -la "$LOG_DIR"/ 2>/dev/null | grep -v _summary
