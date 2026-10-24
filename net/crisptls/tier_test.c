/** tier_test.c — exhaustively test crisptls_policy_check(). */
#include "crisptls.h"
#include "crisptls_policy.h"
#include "crisptls_tier.h"
#include <stdio.h>
#include <string.h>

static int pass = 0, fail = 0;

static void check(const char *label, int expect_ok,
                  const crisptls_policy_t *p, uint16_t ver, uint16_t suite)
{
    const char *reason = "?";
    int rc = crisptls_policy_check(p, ver, suite, &reason);
    int ok = (rc == CRISPTLS_GATE_OK);
    int match = (ok == expect_ok);
    printf("  %s  %-50s  ver=0x%04x suite=0x%04x  rc=%d  %s\n",
           match ? "PASS" : "FAIL", label, ver, suite, rc, reason);
    if (match) pass++; else fail++;
}

int main(void) {
    crisptls_policy_t modern, compat, legacy, ancient;

    crisptls_policy_tier(&modern,  CRISPTLS_TIER_MODERN);
    crisptls_policy_tier(&compat,  CRISPTLS_TIER_COMPAT);
    crisptls_policy_tier(&legacy,  CRISPTLS_TIER_LEGACY);
    crisptls_policy_tier(&ancient, CRISPTLS_TIER_ANCIENT);

    printf("─── MODERN tier ───\n");
    check("modern / TLS1.3 + AES128GCM",    1, &modern,  0x0304, 0x1301);
    check("modern / TLS1.2 + ECDHE-AES128GCM", 1, &modern, 0x0303, 0xC02F);
    check("modern / TLS1.2 + AES128-SHA (CBC)", 0, &modern, 0x0303, 0x002F);
    check("modern / TLS1.0 (denied)",        0, &modern,  0x0301, 0x002F);

    printf("─── COMPAT tier ───\n");
    check("compat / TLS1.2 + ECDHE-AES128GCM", 1, &compat, 0x0303, 0xC02F);
    check("compat / TLS1.2 + AES128-SHA (CBC)", 1, &compat, 0x0303, 0x002F);
    check("compat / TLS1.0 (denied)",        0, &compat,  0x0301, 0x002F);
    check("compat / 3DES (denied)",          0, &compat,  0x0303, 0x000A);
    check("compat / RC4 (denied)",           0, &compat,  0x0303, 0x0005);

    printf("─── LEGACY tier ───\n");
    check("legacy / TLS1.1 + 3DES (allowed)",  1, &legacy, 0x0302, 0x000A);
    check("legacy / TLS1.0 + RC4 (allowed)",   1, &legacy, 0x0301, 0x0005);
    check("legacy / TLS1.2 + AES128-SHA CBC",  1, &legacy, 0x0303, 0x002F);
    check("legacy / SSL3.0 (denied)",          0, &legacy, 0x0300, 0x000A);

    printf("─── ANCIENT tier ───\n");
    check("ancient / SSL3.0 + 3DES (allowed)", 1, &ancient, 0x0300, 0x000A);
    check("ancient / SSL3.0 + RC4 (allowed)",  1, &ancient, 0x0300, 0x0005);
    check("ancient / TLS1.3 still works",      1, &ancient, 0x0304, 0x1301);

    printf("\n%d passed · %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
