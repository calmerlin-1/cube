/**
 * scan_scalar.h — reference scalar implementation of the scan API.
 *
 * This is the correctness oracle. Every architecture-specific version
 * must produce identical results. Do not optimize this — its job is
 * to be obviously correct.
 */

#ifndef FLYWHEEL_URL_SCAN_SSE2_H
#define FLYWHEEL_URL_SCAN_SSE2_H

static inline size_t scan_bad_char(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) return i;
    }
    return n;
}

static inline size_t scan_find(const char *s, size_t n, char c) {
    for (size_t i = 0; i < n; i++)
        if (s[i] == c) return i;
    return n;
}

static inline size_t scan_find_any4(const char *s, size_t n,
                                    char a, char b, char c, char d) {
    for (size_t i = 0; i < n; i++) {
        char x = s[i];
        if (x == a || x == b || x == c || x == d) return i;
    }
    return n;
}

static inline int scan_all_scheme(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        int ok = (c >= 'a' && c <= 'z')
              || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9')
              || c == '+' || c == '-' || c == '.';
        if (!ok) return 0;
    }
    return 1;
}

#endif /* FLYWHEEL_URL_SCAN_SSE2_H */
