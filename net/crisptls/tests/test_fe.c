/* test_fe.c — field arithmetic sanity for native P-256. */
#include "crypto_p256.h"
#include <stdio.h>
#include <string.h>

/* We expose internal fe64 funcs from crypto_p256.c via a test-only include trick.
 * Instead, we instrument by declaring them here — they are static in p256.c,
 * so this WON'T work. We need to expose them, or write an internal test in p256.c. */
int main(void) { return 0; }
