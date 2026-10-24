#include <stdio.h>
#include "../include/interp.h"

int main(void) {
    Interp *I = flywheel_new();
    flywheel_load_natives(I);

    const char *tests[] = {
        "console.log(\"hello world\")",
        "console.log(1 + 2)",
        "console.log(\"sum:\", 3 + 4)",
        "\"abc\".toUpperCase()",
        "\"Hello\".toLowerCase()",
        "\"hello\".length",
        "\"hello world\".includes(\"world\")",
        "\"abcdef\".slice(1, 4)",
        "[1, 2, 3].join(\"-\")",
        "[1, 2, 3].length",
        "let a = [1, 2, 3]; a.push(4); a.join(\",\")",
        "let a = [1, 2, 3]; a.pop()",
        "Math.floor(3.7)",
        "Math.max(1, 5, 3)",
        "Math.PI",
        "JSON.stringify({a: 1, b: [2, 3]})",
        "`hello ${1 + 2}`",
        "`x=${10} y=${20}`",
        "let x = 5; if (x > 3) { console.log(\"big\") } else { console.log(\"small\") }; x * 2",
        "for (let i = 0; i < 3; i = i + 1) { console.log(i) }",
        "function greet(name) { return \"hi \" + name; } greet(\"world\")",
        "function fact(n) { if (n < 2) return 1; return n * fact(n-1); } fact(5)",
        "try { throw \"oops\" } catch (e) { \"caught: \" + e }",
    };
    int n = sizeof(tests) / sizeof(tests[0]);
    for (int i = 0; i < n; i++) {
        FlyResult r = flywheel_eval(I, tests[i], "<t>");
        printf("[%02d] %-65s -> ", i, tests[i]);
        if (r.status == FLY_OK) { val_print(r.value); printf("\n"); }
        else printf("ERROR: %s (line %d col %d)\n",
                    r.error_msg, r.error_line, r.error_column);
    }
    flywheel_free(I);
    return 0;
}
