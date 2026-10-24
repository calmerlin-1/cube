/** policy_test.c — load a generated policy and print what was parsed.
 *  Standalone. Does not touch the client. */
#include <stdio.h>
#include <string.h>
#include "crisptls_policy.h"

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "../cache/policy.generated.txt";

    crisptls_policy_t p;
    int rc = crisptls_policy_from_generated(&p, path);
    printf("crisptls_policy_from_generated(\"%s\") = %d\n", path, rc);
    printf("\n");

    printf("min_version          = 0x%04x\n", p.min_version);
    printf("max_version          = 0x%04x\n", p.max_version);
    printf("legacy_version_field = 0x%04x\n", p.legacy_version_field);

    printf("cipher_suites_13     =");
    if (p.cipher_suites_13)
        for (size_t i = 0; p.cipher_suites_13[i]; i++)
            printf(" 0x%04x", p.cipher_suites_13[i]);
    printf("\n");

    printf("cipher_suites_12     =");
    if (p.cipher_suites_12)
        for (size_t i = 0; p.cipher_suites_12[i]; i++)
            printf(" 0x%04x", p.cipher_suites_12[i]);
    printf("\n");

    printf("\nfirst 1.3 suite      = 0x%04x\n",
           p.cipher_suites_13 ? p.cipher_suites_13[0] : 0);
    printf("first 1.2 suite      = 0x%04x\n",
           p.cipher_suites_12 ? p.cipher_suites_12[0] : 0);

    return rc == CRISPTLS_OK ? 0 : 1;
}
