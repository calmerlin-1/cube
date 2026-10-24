/** hash.c — deterministic content hashing for --patch safety. */

#include "erdict.h"
#include <stdio.h>
#include <string.h>

/* FNV-1a 64-bit over the bytes of lines [s..e] (0-based, inclusive).
 * The hash covers each line's exact content plus a '\n' between lines,
 * so that moving lines around always changes the hash. */
void erdict_hash_range(const erdict_file_t *f, size_t s, size_t e, char out_buf[17]) {
    if (!out_buf) return;
    uint64_t h = 0xcbf29ce484222325ULL;   /* FNV offset basis */
    const uint64_t prime = 0x100000001b3ULL;
    for (size_t i = s; i <= e && i < f->n_lines; i++) {
        const erdict_line_t *l = &f->lines[i];
        for (size_t j = 0; j < l->len; j++) {
            h ^= (unsigned char)l->p[j];
            h *= prime;
        }
        h ^= '\n';
        h *= prime;
    }
    snprintf(out_buf, 17, "%016llx", (unsigned long long)h);
}
