#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/interp.h"

static int total = 0;
static int ok = 0;
static int parse_err = 0;
static int runtime_err = 0;
static int crash = 0;

static void run_one(const char *label, const char *src) {
    total++;
    Interp *I = flywheel_new();
    if (!I) { printf("  [%s] cannot create interp\n", label); crash++; return; }
    flywheel_load_natives(I);
    FlyResult r = flywheel_eval(I, src, label);
    if (r.status == FLY_OK) {
        printf("  [OK]   %-40s -> ", label);
        val_print(r.value);
        printf("\n");
        ok++;
    } else if (r.status == FLY_PARSE_ERROR) {
        printf("  [PE]   %-40s -> %s (line %d)\n", label, r.error_msg, r.error_line);
        parse_err++;
    } else if (r.status == FLY_RUNTIME_ERROR) {
        printf("  [RE]   %-40s -> %s (line %d)\n", label, r.error_msg, r.error_line);
        runtime_err++;
    } else {
        printf("  [??]   %-40s -> status=%d %s\n", label, r.status, r.error_msg);
        crash++;
    }
    flywheel_free(I);
}

int main(void) {
    printf("=============================================\n");
    printf(" FLYWHEEL ENGINE STRESS TEST\n");
    printf("=============================================\n\n");

    
    /* 1. Basics                                                    */
    
    printf("--- 1. Basic expressions ---\n");
    run_one("num",          "42");
    run_one("add",          "1 + 2");
    run_one("precedence",   "1 + 2 * 3");
    run_one("parens",       "(1 + 2) * 3");
    run_one("float",        "10 / 4");
    run_one("neg",          "-5");
    run_one("not",          "!true");
    run_one("pow",          "2 ** 10");
    run_one("mod",          "17 % 5");
    run_one("bitops",       "(5 & 3) | (5 ^ 3)");
    run_one("compare",      "10 > 5");
    run_one("eq",           "\"a\" === \"a\"");
    run_one("loose eq",     "\"5\" == 5");
    run_one("strict neq",   "\"5\" !== 5");

    
    /* 2. Strings                                                   */
    
    printf("\n--- 2. Strings ---\n");
    run_one("concat",       "\"hello\" + \" \" + \"world\"");
    run_one("length",       "\"hello\".length");
    run_one("upper",        "\"hello\".toUpperCase()");
    run_one("lower",        "\"HELLO\".toLowerCase()");
    run_one("slice",        "\"hello\".slice(1, 4)");
    run_one("indexOf",      "\"hello\".indexOf(\"l\")");
    run_one("includes",     "\"hello\".includes(\"ell\")");
    run_one("nested calls", "\"hello\".toUpperCase().toLowerCase()");

    
    /* 3. Variables & assignment                                    */
    
    printf("\n--- 3. Variables ---\n");
    run_one("let",          "let x = 5; x");
    run_one("const",        "const y = 10; y");
    run_one("reassign",     "let x = 1; x = 99; x");
    run_one("compound",     "let x = 10; x += 5; x");
    run_one("shadow",       "let x = 1; { let x = 2; } x");
    run_one("undefined",    "let z; z");
    run_one("const assign", "const c = 1; c = 2; c");

    
    /* 4. Control flow                                              */
    
    printf("\n--- 4. Control flow ---\n");
    run_one("if true",      "if (1) 100; else 200");
    run_one("if false",     "if (0) 100; else 200");
    run_one("nested if",    "let x = 5; if (x > 3) { if (x < 10) 1; else 2; } else 3");
    run_one("ternary",      "true ? 1 : 2");
    run_one("ternary nest", "1 ? 2 ? 3 : 4 : 5");
    run_one("while",        "let i = 0; while (i < 5) i = i + 1; i");
    run_one("for",          "let s = 0; for (let i = 0; i < 5; i = i + 1) s = s + i; s");
    run_one("for break",    "let s = 0; for (let i = 0; i < 10; i = i + 1) { if (i == 5) break; s = s + i; } s");
    run_one("for continue", "let s = 0; for (let i = 0; i < 5; i = i + 1) { if (i == 2) continue; s = s + i; } s");
    run_one("switch",       "let x = 2; let r = 0; switch (x) { case 1: r = 10; break; case 2: r = 20; break; default: r = 30; } r");
    run_one("switch fall",  "let x = 1; let r = ''; switch (x) { case 1: r = r + 'a'; case 2: r = r + 'b'; break; case 3: r = r + 'c'; } r");

    
    /* 5. Functions                                                 */
    
    printf("\n--- 5. Functions ---\n");
    run_one("fn basic",     "function f(x) { return x * 2; } f(21)");
    run_one("fn two args",  "function add(a, b) { return a + b; } add(3, 4)");
    run_one("fn nested",    "function f(x) { function g(y) { return y * 2; } return g(x) + 1; } f(5)");
    run_one("fn closure",   "function outer() { let x = 100; function inner() { return x; } return inner(); } outer()");
    run_one("fn recurs",    "function fact(n) { if (n < 2) return 1; return n * fact(n-1); } fact(5)");
    run_one("fn fib",       "function fib(n) { if (n < 2) return n; return fib(n-1) + fib(n-2); } fib(10)");
    run_one("arrow",        "let f = x => x * 2; f(21)");
    run_one("arrow block",  "let f = x => { return x + 1; }; f(10)");
    run_one("immediate",    "(function() { return 42; })()");

    
    /* 6. Arrays                                                    */
    
    printf("\n--- 6. Arrays ---\n");
    run_one("lit",          "[1, 2, 3].length");
    run_one("index",        "[10, 20, 30][1]");
    run_one("assign",       "let a = [1, 2, 3]; a[1] = 99; a[1]");
    run_one("push",         "let a = [1, 2]; a.push(3); a.length");
    run_one("pop",          "let a = [1, 2, 3]; a.pop()");
    run_one("join",         "[1, 2, 3].join(\"-\")");
    run_one("nested",       "[[1, 2], [3, 4]][1][0]");
    run_one("mixed",        "[1, \"two\", true, null]");

    
    /* 7. Objects                                                   */
    
    printf("\n--- 7. Objects ---\n");
    run_one("lit",          "({ a: 1 }).a");
    run_one("two keys",     "({ a: 1, b: 2 }).a + ({ a: 1, b: 2 }).b");
    run_one("nested",       "({ a: { b: { c: 42 } } }).a.b.c");
    run_one("shorthand",    "let x = 5; ({ x }).x");
    run_one("method",       "({ f: function() { return 1; } }).f()");
    run_one("method short", "({ f() { return 42; } }).f()");
    run_one("assign key",   "let o = { a: 1 }; o.b = 2; o.b");
    run_one("computed",     "let k = \"x\"; ({ [k]: 5 }).x");

    
    /* 8. Templates                                                 */
    
    printf("\n--- 8. Templates ---\n");
    run_one("plain",        "`hello`");
    run_one("one sub",      "`x=${5}`");
    run_one("multi sub",    "`a=${1} b=${2} c=${3}`");
    run_one("expr sub",     "`sum=${1 + 2 + 3}`");
    run_one("nested",       "`x=${`y=${1}`}`");
    run_one("var",          "let n = 7; `n=${n}`");

    
    /* 9. try/catch                                                 */
    
    printf("\n--- 9. try/catch/throw ---\n");
    run_one("throw str",    "try { throw \"err\" } catch (e) { e }");
    run_one("throw num",    "try { throw 42 } catch (e) { e + 1 }");
    run_one("no throw",     "try { 100 } catch (e) { 0 }");
    run_one("nested try",   "try { try { throw 1 } catch (e) { throw e + 1 } } catch (e) { e }");
    run_one("rethrow",      "let r = 0; try { throw 5 } catch (e) { r = e * 2 } r");

    
    /* 10. Natives                                                  */
    
    printf("\n--- 10. Native objects ---\n");
    run_one("math floor",   "Math.floor(3.7)");
    run_one("math ceil",    "Math.ceil(3.1)");
    run_one("math round",   "Math.round(2.5)");
    run_one("math abs",     "Math.abs(-7)");
    run_one("math max",     "Math.max(1, 5, 3, 2)");
    run_one("math min",     "Math.min(4, 1, 9)");
    run_one("math pow",     "Math.pow(2, 8)");
    run_one("math sqrt",    "Math.sqrt(16)");
    run_one("json obj",     "JSON.stringify({ a: 1 })");
    run_one("json arr",     "JSON.stringify([1, 2, 3])");
    run_one("json nested",  "JSON.stringify({ a: [1, 2], b: { c: 3 } })");

    
    /* 11. Real programs                                            */
    
    printf("\n--- 11. Composite programs ---\n");
    run_one("fib+array",
        "function fib(n) { if (n < 2) return n; return fib(n-1) + fib(n-2); }"
        "let a = [];"
        "for (let i = 0; i < 10; i = i + 1) a[i] = fib(i);"
        "let t = 0; for (let i = 0; i < a.length; i = i + 1) t = t + a[i];"
        "t");
    run_one("word count",
        "let s = \"the quick brown fox jumps over the lazy dog\";"
        "let c = 0;"
        "for (let i = 0; i < s.length; i = i + 1) { if (s.charAt(i) == \" \") c = c + 1; }"
        "c + 1");
    run_one("map filter",
        "let a = [1, 2, 3, 4, 5];"
        "let sum = 0;"
        "for (let i = 0; i < a.length; i = i + 1) {"
        "  if (a[i] > 2) sum = sum + a[i];"
        "}"
        "sum");
    run_one("string builder",
        "let out = '';"
        "for (let i = 1; i <= 5; i = i + 1) {"
        "  out = out + i;"
        "  if (i < 5) out = out + ',';"
        "}"
        "out");

    
    /* 12. Hostile inputs                                           */
    
    printf("\n--- 12. Hostile / edge inputs ---\n");
    run_one("empty",        "");
    run_one("whitespace",   "   \n\t  ");
    run_one("unterminated", "\"abc");
    run_one("bad syntax",   "let x = ;");
    run_one("undefined var","notDefined");
    run_one("call non-fn",  "let x = 5; x()");
    run_one("prop of null", "null.foo");
    run_one("div zero",     "1 / 0");
    run_one("infinity",     "1e308 * 10");
    run_one("nan prop",     "let x = 1/0; x > 5");
    run_one("long chain",   "\"a\".toUpperCase().toLowerCase().toUpperCase().toLowerCase().toUpperCase()");
    run_one("deep nest",    "((((((((((42))))))))))");
    run_one("stack depth",  "function f(n) { if (n < 1) return 0; return f(n - 1); } f(400)");

    
    /* Summary                                                      */
    
    printf("\n=============================================\n");
    printf(" TOTAL:       %d\n", total);
    printf(" OK:          %d\n", ok);
    printf(" PARSE_ERR:   %d\n", parse_err);
    printf(" RUNTIME_ERR: %d\n", runtime_err);
    printf(" UNEXPECTED:  %d\n", crash);
    printf("=============================================\n");
    printf("\nInterpretation:\n");
    printf("  PARSE_ERR   = source had a syntax error (correct)\n");
    printf("  RUNTIME_ERR = error was thrown/caught (correct)\n");
    printf("  UNEXPECTED  = TRUE BUG — this should never happen\n");

    return crash > 0 ? 1 : 0;
}
