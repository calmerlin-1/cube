/**
 * scan_neon.h — NEON implementation of the scan API (AArch64).
 *
 * Same contract as scan_scalar.h: return the index of the first matching
 * byte, or n if none matched. Every function must agree with scan_scalar.h
 * byte for byte on the same input. tests/scan_parity.c proves it.
 *
 * Strategy: process 16 bytes per iteration with vld1q_u8. If the vector
 * compare finds any match, fall through to a scalar tail that identifies
 * the exact index. If not, advance by 16. Tail handles the < 16 remainder.
 */

#ifndef FLYWHEEL_URL_SCAN_NEON_H
#define FLYWHEEL_URL_SCAN_NEON_H

#include <arm_neon.h>

static inline size_t scan_bad_char(const char *s, size_t n) {
    const uint8_t *p = (const uint8_t *)s;
    size_t i = 0;
    const uint8x16_t sp  = vdupq_n_u8(0x1f);   /* < 0x20 */
    const uint8x16_t dl  = vdupq_n_u8(0x7f);
    for (; i + 16 <= n; i += 16) {
        uint8x16_t v = vld1q_u8(p + i);
        uint8x16_t lt = vcleq_u8(v, sp);
        uint8x16_t eq = vceqq_u8(v, dl);
        uint8x16_t m  = vorrq_u8(lt, eq);
        if (vmaxvq_u8(m)) break;
    }
    for (; i < n; i++) {
        unsigned char c = p[i];
        if (c < 0x20 || c == 0x7f) return i;
    }
    return n;
}

static inline size_t scan_find(const char *s, size_t n, char c) {
    const uint8_t *p = (const uint8_t *)s;
    size_t i = 0;
    const uint8x16_t needle = vdupq_n_u8((uint8_t)c);
    for (; i + 16 <= n; i += 16) {
        uint8x16_t v = vld1q_u8(p + i);
        uint8x16_t m = vceqq_u8(v, needle);
        if (vmaxvq_u8(m)) break;
    }
    for (; i < n; i++)
        if (p[i] == (uint8_t)c) return i;
    return n;
}

static inline size_t scan_find_any4(const char *s, size_t n,
                                    char a, char b, char c, char d) {
    const uint8_t *p = (const uint8_t *)s;
    size_t i = 0;
    const uint8x16_t va = vdupq_n_u8((uint8_t)a);
    const uint8x16_t vb = vdupq_n_u8((uint8_t)b);
    const uint8x16_t vc = vdupq_n_u8((uint8_t)c);
    const uint8x16_t vd = vdupq_n_u8((uint8_t)d);
    for (; i + 16 <= n; i += 16) {
        uint8x16_t v = vld1q_u8(p + i);
        uint8x16_t m = vorrq_u8(
            vorrq_u8(vceqq_u8(v, va), vceqq_u8(v, vb)),
            vorrq_u8(vceqq_u8(v, vc), vceqq_u8(v, vd)));
        if (vmaxvq_u8(m)) break;
    }
    for (; i < n; i++) {
        uint8_t x = p[i];
        if (x == (uint8_t)a || x == (uint8_t)b ||
            x == (uint8_t)c || x == (uint8_t)d) return i;
    }
    return n;
}

static inline int scan_all_scheme(const char *s, size_t n) {
    /* Not vectorized in first pass — scheme names are short (2-10 chars),
     * and the branch-heavy char class check doesn't gain from SIMD. */
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

#endif /* FLYWHEEL_URL_SCAN_NEON_H */
