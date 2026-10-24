#include <stdio.h>
#include "../include/interp.h"

int main(void) {
    Interp *I = flywheel_new();
    const char *prog =
        "let a = 10;"
        "let b = 20;"
        "let sum = a + b;"
        "if (sum > 25) {"
        "    let bonus = 5;"
        "    sum = sum + bonus;"
        "}"
        "sum";
    FlyResult r = flywheel_eval(I, prog, "<prog>");
    printf("program result: ");
    if (r.status == FLY_OK) { val_print(r.value); printf("\n"); }
    else printf("ERROR: %s (line %d col %d)\n",
                r.error_msg, r.error_line, r.error_column);
    flywheel_free(I);
    return 0;
}
