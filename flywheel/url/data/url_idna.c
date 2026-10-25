/* url_idna.c — punycode encoder per RFC 3492. Encodes only, decodes only. */

#include "url_idna.h"
#include <string.h>

/* Punycode constants. */
#define PC_BASE        36
#define PC_TMIN        1
#define PC_TMAX        26
#define PC_SKEW        38
#define PC_DAMP        700
#define PC_INITIAL_BIAS 72
#define PC_INITIAL_N   128

/* Return lowercase of c. */
static unsigned char to_lower_b(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

/* Encode a basic code point (0..127) into out. */
static size_t digit_to_char(unsigned d, char *out) {
    if (d < 26) { out[0] = (char)('a' + d); return 1; }
    if (d < 36) { out[0] = (char)('0' + (d - 26)); return 1; }
    return 0;
}

/* Adapt bias per RFC 3492 §6.1. */
static unsigned adapt(unsigned delta, unsigned numpoints, int firsttime) {
    delta = firsttime ? delta / PC_DAMP : delta / 2;
    delta += delta / numpoints;
    unsigned k = 0;
    while (delta > ((PC_BASE - PC_TMIN) * PC_TMAX) / 2) {
        delta /= PC_BASE - PC_TMIN;
        k += PC_BASE;
    }
    return k + (((PC_BASE - PC_TMIN + 1) * delta) / (delta + PC_SKEW));
}

/* Punycode-encode `input` (UTF-8) into `out` after "xn--". */
static int punycode_encode(const unsigned *cp, size_t n,
                           char *out, size_t outcap, size_t *outlen) {
    size_t w = 0;

    /* Copy basic code points first (ASCII). */
    for (size_t i = 0; i < n; i++) {
        if (cp[i] < 0x80) {
            if (w >= outcap) return URLI_ERR_OVERFLOW;
            out[w++] = (char)to_lower_b((unsigned char)cp[i]);
        }
    }
    size_t h = w;
    size_t b = w;
    if (b > 0) {
        if (w >= outcap) return URLI_ERR_OVERFLOW;
        out[w++] = '-';
    }

    unsigned n_acc = PC_INITIAL_N;
    unsigned delta = 0;
    unsigned bias = PC_INITIAL_BIAS;

    while (h < n) {
        unsigned m = 0xFFFFFFFFu;
        for (size_t i = 0; i < n; i++) if (cp[i] >= n_acc && cp[i] < m) m = cp[i];

        if (m - n_acc > (0xFFFFFFFFu - delta) / (unsigned)(h + 1))
            return URLI_ERR_OVERFLOW;
        delta += (m - n_acc) * (unsigned)(h + 1);
        n_acc = m;

        for (size_t i = 0; i < n; i++) {
            if (cp[i] < n_acc) {
                if (++delta == 0) return URLI_ERR_OVERFLOW;
            }
            if (cp[i] == n_acc) {
                unsigned q = delta;
                for (unsigned k = PC_BASE; ; k += PC_BASE) {
                    unsigned t = (k <= bias) ? PC_TMIN
                             : (k >= bias + PC_TMAX) ? PC_TMAX
                             : (k - bias);
                    if (q < t) break;
                    char d;
                    size_t dl = digit_to_char(t + (q - t) % (PC_BASE - t), &d);
                    if (dl == 0 || w >= outcap) return URLI_ERR_OVERFLOW;
                    out[w++] = d;
                    q = (q - t) / (PC_BASE - t);
                }
                char d;
                size_t dl = digit_to_char(q, &d);
                if (dl == 0 || w >= outcap) return URLI_ERR_OVERFLOW;
                out[w++] = d;
                bias = adapt(delta, (unsigned)(h + 1), h == b);
                delta = 0;
                h++;
            }
        }
        delta++;
        n_acc++;
    }
    if (outlen) *outlen = w;
    return URLI_OK;
}

/* Decode one UTF-8 sequence into a codepoint. Returns length consumed, or 0. */
static size_t utf8_decode(const char *s, size_t n, unsigned *cp) {
    if (n == 0) return 0;
    unsigned char c = (unsigned char)s[0];
    if (c < 0x80) { *cp = c; return 1; }
    if (c < 0xC2) return 0;
    if (c < 0xE0) {
        if (n < 2 || (s[1] & 0xC0) != 0x80) return 0;
        *cp = ((c & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (c < 0xF0) {
        if (n < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (c == 0xE0 && (unsigned char)s[1] < 0xA0) return 0;  /* overlong */
        if (c == 0xED && (unsigned char)s[1] >= 0xA0) return 0; /* surrogate */
        *cp = ((c & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    }
    if (c < 0xF5) {
        if (n < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        if (c == 0xF0 && (unsigned char)s[1] < 0x90) return 0;  /* overlong */
        if (c == 0xF4 && (unsigned char)s[1] >= 0x90) return 0; /* > U+10FFFF */
        *cp = ((c & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    return 0;
}

/* Encode one codepoint as UTF-8. Returns bytes written, or 0. */
#if 0  /* unused helper kept for reference */
static size_t utf8_encode(unsigned cp, char *out, size_t cap) {
    if (cp < 0x80) { if (cap < 1) return 0; out[0] = (char)cp; return 1; }
    if (cp < 0x800) { if (cap < 2) return 0; out[0] = (char)(0xC0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { if (cap < 3) return 0; out[0] = (char)(0xE0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[2] = (char)(0x80 | (cp & 0x3F)); return 3; }
    if (cap < 4) return 0;
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

#endif  /* unused helper kept for reference */

/* Encode one label: if it has non-ASCII, produce "xn--...". Else copy as-is. */
static int idna_encode_label(const char *in, size_t inlen,
                             char *out, size_t outcap, size_t *outlen) {
    int has_non_ascii = 0;
    for (size_t i = 0; i < inlen; i++) {
        if ((unsigned char)in[i] >= 0x80) { has_non_ascii = 1; break; }
    }
    if (!has_non_ascii) {
        if (inlen > outcap) return URLI_ERR_OVERFLOW;
        for (size_t i = 0; i < inlen; i++)
            out[i] = (char)to_lower_b((unsigned char)in[i]);
        if (outlen) *outlen = inlen;
        return URLI_OK;
    }

    /* decode UTF-8 into codepoints */
    unsigned cp[1024];
    size_t n = 0;
    size_t i = 0;
    while (i < inlen) {
        if (n >= 1024) return URLI_ERR_TOO_LONG;
        size_t cl = utf8_decode(in + i, inlen - i, &cp[n]);
        if (cl == 0) return URLI_ERR_BAD_UTF8;
        n++;
        i += cl;
    }

    /* write "xn--" prefix */
    if (outcap < 4) return URLI_ERR_OVERFLOW;
    out[0] = 'x'; out[1] = 'n'; out[2] = '-'; out[3] = '-';
    size_t w = 4;
    size_t pw = 0;
    int r = punycode_encode(cp, n, out + w, outcap - w, &pw);
    if (r) return r;
    w += pw;
    if (outlen) *outlen = w;
    return URLI_OK;
}

int url_idna_to_ascii(const char *in, size_t inlen,
                      char *out, size_t outcap, size_t *outlen) {
    size_t w = 0;
    size_t i = 0;
    while (i <= inlen) {
        /* find next '.' or end */
        size_t j = i;
        while (j < inlen && in[j] != '.') j++;
        size_t lbl = j - i;
        if (lbl > 0) {
            if (lbl > 63) return URLI_ERR_TOO_LONG;   /* RFC 1035 label limit */
            size_t lw = 0;
            int r = idna_encode_label(in + i, lbl, out + w, outcap - w, &lw);
            if (r) return r;
            w += lw;
        }
        if (j < inlen) {
            if (w >= outcap) return URLI_ERR_OVERFLOW;
            out[w++] = '.';
        }
        if (j >= inlen) break;
        i = j + 1;
    }
    if (outlen) *outlen = w;
    return URLI_OK;
}

/* Not implemented yet — placeholder returns input unchanged. */
int url_idna_to_unicode(const char *in, size_t inlen,
                        char *out, size_t outcap, size_t *outlen) {
    if (inlen >= outcap) return URLI_ERR_OVERFLOW;
    memcpy(out, in, inlen);
    if (outlen) *outlen = inlen;
    return URLI_OK;
}
