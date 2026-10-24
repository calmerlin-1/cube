#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../include/interp.h"

int main(void) {
    srand(time(NULL));
    int N = 2000;
    int crashes = 0;
    int ok = 0, parse_err = 0, runtime_err = 0, internal = 0;
    const char *chars = "abcxyz=+-*/(){}[];\"'`.,?!<>&|^~%:0123456789 \n\t";
    int nchars = 0;
    while (chars[nchars]) nchars++;

    for (int i = 0; i < N; i++) {
        int len = 1 + rand() % 80;
        char *buf = malloc(len + 1);
        if (!buf) break;
        for (int j = 0; j < len; j++) {
            buf[j] = chars[rand() % nchars];
        }
        buf[len] = '\0';

        Interp *I = flywheel_new();
        if (!I) { crashes++; free(buf); continue; }
        flywheel_load_natives(I);
        FlyResult r = flywheel_eval(I, buf, "<fuzz>");
        switch (r.status) {
        case FLY_OK:            ok++; break;
        case FLY_PARSE_ERROR:   parse_err++; break;
        case FLY_RUNTIME_ERROR: runtime_err++; break;
        default:                internal++;
        }
        flywheel_free(I);
        free(buf);
    }

    printf("fuzz: %d random inputs\n", N);
    printf("  OK:            %d\n", ok);
    printf("  PARSE_ERROR:   %d\n", parse_err);
    printf("  RUNTIME_ERROR: %d\n", runtime_err);
    printf("  INTERNAL:      %d\n", internal);
    printf("  CRASHES:       %d\n", crashes);
    return crashes + internal;
}
