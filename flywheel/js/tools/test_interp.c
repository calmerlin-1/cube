#include <stdio.h>
#include <string.h>
#include "../include/interp.h"

int main(void) {
    Interp *I = flywheel_new();
    if (!I) { fprintf(stderr, "cannot create interp\n"); return 1; }

    const char *tests[] = {
        "1 + 2",
        "2 * 3 + 4",
        "10 / 4",
        "2 ** 8",
        "\"hello\" + \" \" + \"world\"",
        "1 < 2",
        "\"a\" === \"a\"",
        "true && false",
        "null ?? 42",
        "1 + 2 * 3 - 4 / 2",
    };
    int n = sizeof(tests) / sizeof(tests[0]);

    for (int i = 0; i < n; i++) {
        FlyResult r = flywheel_eval(I, tests[i], "<test>");
        printf("[%d] %-35s -> ", i, tests[i]);
        if (r.status == FLY_OK) {
            val_print(r.value);
            printf("\n");
        } else {
            printf("ERROR: %s (line %d col %d)\n",
                   r.error_msg, r.error_line, r.error_column);
        }
    }

    flywheel_free(I);
    return 0;
}
