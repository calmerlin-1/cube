#!/usr/bin/env bash
# cube test harness
# Usage: ./tests/run.sh [-v]
#   -v: show captured output for failures
#
# Exit: 0 if no unexpected failures; 1 otherwise.
#
# Design notes (from lessons paid for in the 2026-10 session):
#   1. NEVER pipe cube to head/grep during measurement — SIGPIPE kills cube
#      mid-write and produces false failures. Always redirect to file first.
#   2. sleep 2 between hosts — DNS rate-limits hard after bursts.
#   3. Use -i (headers only) — we only need the status line, not multi-MB bodies.
#   4. Use -q + redirect stderr to /dev/null — some traces leak despite -q.
#   5. timeout each run — a hang must become a visible TIMEOUT result, not a stuck test.

set -u
VERBOSE=0
[ "${1:-}" = "-v" ] && VERBOSE=1

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/.." || exit 1

HOSTS="$HERE/hosts.txt"
RESULTS_DIR="$HERE/.results"
mkdir -p "$RESULTS_DIR"

pass=0; fail=0; xfail=0; timeout_n=0; segv=0
total=0
fail_lines=()

while IFS='|' read -r raw_url raw_expect raw_note; do
    # strip leading/trailing whitespace
    url=$(echo "$raw_url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    expect=$(echo "$raw_expect" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    note=$(echo "$raw_note" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    [ -z "$url" ] && continue
    case "$url" in \#*) continue ;; esac

    total=$((total + 1))
    tag=$(printf '%03d' "$total")
    out="$RESULTS_DIR/$tag.out"

    # Capture to file (never pipe). -i for headers-only, -q for quiet,
    # --timeout 10s per-stage. Redirect stderr to /dev/null except when verbose.
    if [ "$VERBOSE" -eq 1 ]; then
        timeout 15 ./cube -q -i --timeout 10000 "$url" > "$out" 2>&1
    else
        timeout 15 ./cube -q -i --timeout 10000 "$url" > "$out" 2>/dev/null
    fi
    rc=$?

    # Sleep between hosts to avoid DNS rate limits
    sleep 2

    # Classify
    status=$(grep -aE '^HTTP/' "$out" 2>/dev/null | head -1 | awk '{print $2}')

    case "$rc" in
        124) verdict="TIMEOUT"; reason="15s wall clock" ;;
        139|134) verdict="SEGV"; reason="signal $rc" ;;
        0)
            if [ -z "$status" ]; then
                verdict="FAIL"; reason="no HTTP status line"
            elif [ "$expect" = "any" ] || [ "$expect" = "$status" ]; then
                verdict="PASS"; reason="$status"
            else
                verdict="FAIL"; reason="expected $expect, got $status"
            fi
            ;;
        *)  verdict="FAIL"; reason="exit $rc" ;;
    esac

    # Apply xfail transformation
    if [ "$expect" = "xfail" ]; then
        if [ "$verdict" = "PASS" ]; then
            # Bug is fixed! Report as PASS but flag as "fixed xfail"
            pass=$((pass + 1))
            printf "%-7s %s  [xfail-fixed!]  %s\n" "PASS" "$url" "$reason"
        else
            xfail=$((xfail + 1))
            printf "%-7s %s  [xfail: %s]  %s\n" "XFAIL" "$url" "$reason" "$note"
        fi
        continue
    fi

    case "$verdict" in
        PASS)    pass=$((pass + 1));    printf "%-7s %s  %s\n" "$verdict" "$url" "$reason" ;;
        TIMEOUT) timeout_n=$((timeout_n+1)); fail=$((fail+1)); fail_lines+=("$url  $reason"); printf "%-7s %s  %s\n" "$verdict" "$url" "$reason" ;;
        SEGV)    segv=$((segv+1));      fail=$((fail+1)); fail_lines+=("$url  $reason"); printf "%-7s %s  %s\n" "$verdict" "$url" "$reason" ;;
        FAIL)    fail=$((fail+1));      fail_lines+=("$url  $reason"); printf "%-7s %s  %s\n" "$verdict" "$url" "$reason" ;;
    esac

done < "$HOSTS"

echo ""
echo "=== summary ==="
echo "total:   $total"
echo "  PASS:  $pass"
echo "  XFAIL: $xfail  (known bugs, not counted as failures)"
echo "  FAIL:  $fail  (timeout=$timeout_n, segv=$segv)"

if [ "$fail" -gt 0 ]; then
    echo ""
    echo "=== failures ==="
    for line in "${fail_lines[@]}"; do
        echo "  $line"
    done
    exit 1
fi
exit 0
