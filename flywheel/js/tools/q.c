#include <stdio.h>
#include "../include/interp.h"
int main(void) {
    const char *tests[] = {
        "try {} finally {}",
        "try { 100 } finally {}",
        "try { throw 1 } finally {}",
        "try { throw 1 } catch(e) { e } finally {}",
        "try { 42 } catch(e) { 0 } finally {}",
    };
    for (int i = 0; i < 5; i++) {
        Interp *I = flywheel_new();
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, tests[i], "<t>");
        printf("[%d] %-50s -> ", i, tests[i]);
        if (r.status == FLY_OK) { val_print(r.value); printf("\n"); }
        else printf("status=%d err=%s\n", r.status, r.error_msg);
        flywheel_free(I);
    }
    return 0;
}
