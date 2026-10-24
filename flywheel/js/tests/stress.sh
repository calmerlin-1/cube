#!/data/data/com.termux/files/usr/bin/bash
# Flywheel lexer stress test — every case must exit 0 or 2 (error caught cleanly).
# Any crash (segfault, timeout, exit>2) is a real bug.

BIN=./js/build/test_lexer
PASS=0
FAIL=0
CRASH=0
TIMEOUT=0

run_one() {
    local label="$1"
    local src="$2"
    local expected_exit="$3"   # 0 = ok, 2 = error caught, 9 = crash expected

    local out
    out=$(timeout 3 "$BIN" "$src" 2>&1)
    local ec=$?

    if [ $ec -eq 124 ]; then
        echo "TIMEOUT  [$label] ec=$ec  src=$(printf '%q' "$src")"
        TIMEOUT=$((TIMEOUT+1))
        return
    fi

    if [ $ec -gt 2 ]; then
        echo "CRASH    [$label] ec=$ec  src=$(printf '%q' "$src")"
        echo "         output: $(echo "$out" | tail -3)"
        CRASH=$((CRASH+1))
        return
    fi

    if [ $ec -eq $expected_exit ]; then
        PASS=$((PASS+1))
    else
        echo "WRONG    [$label] got=$ec want=$expected_exit  src=$(printf '%q' "$src")"
        FAIL=$((FAIL+1))
    fi
}

# ---------- 1. Empty / whitespace ----------
run_one "empty"           ""                                      0
run_one "space"           " "                                     0
run_one "newline"         "$(printf '\n')"                        0
run_one "tab"             "$(printf '\t')"                        0
run_one "crlf"            "$(printf '\r\n')"                      0
run_one "many spaces"     "                                                    "   0

# ---------- 2. Numbers ----------
run_one "zero"            "0"                                     0
run_one "huge int"        "999999999999999999999999999"           0
run_one "negative hex"    "-0xFF"                                 0
run_one "hex upper"       "0XABCDEF"                              0
run_one "octal"           "0o755"                                 0
run_one "binary"          "0b11111111"                            0
run_one "exp plus"        "1e+10"                                 0
run_one "exp minus"       "1e-10"                                 0
run_one "exp no frac"     "1E5"                                   0
run_one "float no lead"   ".5"                                    0
run_one "float no trail"  "5."                                    0
run_one "underscore int"  "1_000_000"                             0
run_one "underscore hex"  "0xFF_FF"                               0
run_one "bigint"          "9007199254740993n"                     0
run_one "bad hex"         "0x"                                    2
run_one "bad bin"         "0b2"                                   2
run_one "bad exp"         "1e"                                    2

# ---------- 3. Strings ----------
run_one "dquote"          "\"hi\""                                0
run_one "squote"          "'hi'"                                  0
run_one "empty str"       "\"\""                                  0
run_one "escape quote"    "\"a\\\"b\""                            0
run_one "escape back"     "\"a\\\\b\""                            0
run_one "unicode str"     "\"日本語\""                             0
run_one "emoji str"       "\"🔥\""                                 0
run_one "unterminated"    "\"no close"                            2
run_one "unterminated sq" "'no close"                             2

# ---------- 4. Templates ----------
run_one "plain tmpl"      "\`hi\`"                                0
run_one "one sub"         "\`\${x}\`"                             0
run_one "two subs"        "\`\${x}\${y}\`"                        0
run_one "sub obj"         "\`\${a.b.c}\`"                         0
run_one "sub call"        "\`\${f(1,2)}\`"                        0
run_one "sub nested"      "\`\${a[b][c]}\`"                       0
run_one "unterm tmpl"     "\`no close"                            2
run_one "unterm sub"      "\`\${"                                 0

# ---------- 5. Identifiers ----------
run_one "simple"          "x"                                     0
run_one "dollar"          "\$x"                                   0
run_one "underscore"      "_x"                                    0
run_one "digits end"      "x1"                                    0
run_one "unicode ident"   "日本語"                                0
run_one "greek"           "π"                                     0
run_one "dollar only"     "\$"                                    0
run_one "underscore only" "_"                                     0

# ---------- 6. Operators ----------
run_one "plusplus"        "a++ + ++b"                             0
run_one "long eq"         "a === b !== c"                         0
run_one "spread"          "f(...args)"                            0
run_one "optional chain"  "a?.b?.c"                               0
run_one "nullish"         "a ?? b"                                0
run_one "nullish assign"  "a ??= b"                               0
run_one "pow"             "a ** b ** c"                           0
run_one "pow assign"      "a **= 2"                               0
run_one "shift assign"    "a <<= 1; b >>= 1; c >>>= 1"            0
run_one "and or"          "a && b || c"                           0
run_one "bitwise"         "a & b | c ^ d ~e"                      0
run_one "compare chain"   "a < b <= c > d >= e"                   0

# ---------- 7. Comments ----------
run_one "line comment"    "a // x"                                0
run_one "block comment"   "a /* x */ b"                           0
run_one "multiline cmt"   "$(printf 'a /* line1\nline2 */ b')"    0
run_one "comment only"    "// nothing"                            0
run_one "cmt at eof"      "a /* x"                                2

# ---------- 8. Regex vs division ----------
run_one "div"             "a / b"                                 0
run_one "div assign"      "a /= 2"                                0
run_one "regex simple"    "/abc/"                                 0
run_one "regex flags"     "/abc/gi"                               0
run_one "regex class"     "/[a-z]/"                               0
run_one "regex slash in class" "/[a/b]/"                          0
run_one "regex after ("   "(/abc/)"                               0
run_one "unterm regex"    "/abc"                                  2

# ---------- 9. Real-world JS ----------
run_one "hello"           "console.log('hi')"                     0
run_one "var assign"      "var x = 10;"                           0
run_one "const let"       "const a = 1; let b = 2;"               0
run_one "function"        "function f(a) { return a * 2; }"       0
run_one "arrow"           "const f = (x) => x * 2;"               0
run_one "arrow obj"       "const f = () => ({a: 1});"             0
run_one "if else"         "if (x) { a() } else { b() }"           0
run_one "for loop"        "for (let i = 0; i < 10; i++) { }"      0
run_one "for of"          "for (const x of arr) { }"              0
run_one "for in"          "for (const k in obj) { }"              0
run_one "while"           "while (x) { }"                         0
run_one "do while"        "do { } while (x);"                     0
run_one "switch"          "switch (x) { case 1: break; default: break; }"  0
run_one "try catch"       "try { f() } catch (e) { }"             0
run_one "try finally"     "try { f() } finally { }"               0
run_one "throw"           "throw new Error('x')"                  0
run_one "class"           "class A { constructor(x) { this.x = x } }"  0
run_one "class extends"   "class A extends B { }"                 0
run_one "async await"     "async function f() { await g(); }"     0
run_one "obj literal"     "const o = {a: 1, b: 'x', c: [1,2]}"    0
run_one "nested funcs"    "f(g(h(x)))"                            0
run_one "member chain"    "a.b.c.d.e.f"                           0
run_one "index chain"     "a[0][1][2]"                            0
run_one "ternary"         "x ? y : z"                             0
run_one "comma expr"      "a, b, c"                               0
run_one "array literal"   "[1, 2, 3, 4, 5]"                       0
run_one "sparse array"    "[1, , , 4]"                            0
run_one "semicolon asr"   ";;;a;;;"                               0

# ---------- 10. Nasty edge cases ----------
run_one "null byte"       "$(printf 'a\0b')"                      0
run_one "only backslash"  "\\\\"                                    2
run_one "backslash quote" "'\\\\'"                                0
run_one "just paren"      "("                                     0
run_one "just rbrace"     ")"                                     0
run_one "just bracket"    "]"                                     0
run_one "many rbraces"    "}}}"                                   0
run_one "many lbraces"    "{{{"                                   0
run_one "long string"     "\"$(printf 'a%.0s' {1..5000})\""       0
run_one "many tokens"     "$(printf 'a %.0s' {1..500})"           0
run_one "deep nest"       "$(printf '(%.0s' {1..200}; printf ')%.0s' {1..200})"  0
run_one "many newlines"   "$(printf '\n%.0s' {1..500})"           0

# ---------- 11. Fuzz: random bytes ----------
for i in 1 2 3 4 5 6 7 8 9 10; do
    SRC=$(head -c 200 /dev/urandom | base64 | tr -d '\n' | head -c 200)
    run_one "fuzz$i" "$SRC" 0  # parser may exit 0 or 2, both acceptable
done
# binary garbage (may exit 0 or 2)
for i in 1 2 3 4 5; do
    SRC=$(head -c 100 /dev/urandom | tr -d '\0')
    out=$(timeout 3 "$BIN" "$SRC" > /dev/null 2>&1)
    ec=$?
    if [ $ec -gt 2 ]; then
        echo "CRASH    [binary$i] ec=$ec"
        CRASH=$((CRASH+1))
    else
        PASS=$((PASS+1))
    fi
done

echo ""
echo "====================="
echo "PASS:    $PASS"
echo "FAIL:    $FAIL"
echo "CRASH:   $CRASH"
echo "TIMEOUT: $TIMEOUT"
echo "====================="
