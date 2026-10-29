/** h2_hpack.c — HPACK (RFC 7541). Static table + integer + literal,
 *  no Huffman, no dynamic table. Servers accept this.
 *
 * Wire formats we use:
 *   Indexed Header Field (0x80 | idx)          — for entries in static table
 *   Literal Never-Indexed (0x10 | 0 | name_len) — full name + value
 *     0x00 prefix means "literal without indexing, new name" in 4 bits
 *     Actually: 0000xxxx = literal without indexing, new name (xxxx=0)
 *                0001xxxx = literal without indexing, indexed name
 *                0100xxxx = literal never indexed, new name
 *                0101xxxx = literal never indexed, indexed name
 *                We use 0x00 (literal, new name) — simplest.
 */

#include "h2_internal.h"
#include "http_client.h"
#include <stdio.h>
#include <string.h>

extern int g_h2_trace;
#define H2_TRACE(...) do { if (g_h2_trace) fprintf(stderr, __VA_ARGS__); } while (0)
#include <stdlib.h>

/* from h2_huffman.c */
int h2_huff_decode(const uint8_t *in, size_t in_len, char **out);

/* ---- HPACK static table (RFC 7541 Appendix A) ---- */
typedef struct { const char *name; const char *value; } hpack_entry_t;

static const hpack_entry_t HPACK_STATIC[62] = {
    { "",                        ""                     },  /* 0 unused */
    { ":authority",              ""                     },
    { ":method",                 "GET"                  },
    { ":method",                 "POST"                 },
    { ":path",                   "/"                    },
    { ":path",                   "/index.html"          },
    { ":scheme",                 "http"                 },
    { ":scheme",                 "https"                },
    { ":status",                 "200"                  },
    { ":status",                 "204"                  },
    { ":status",                 "206"                  },
    { ":status",                 "304"                  },
    { ":status",                 "400"                  },
    { ":status",                 "404"                  },
    { ":status",                 "500"                  },
    { "accept-charset",          ""                     },
    { "accept-encoding",         "gzip, deflate"        },
    { "accept-language",         ""                     },
    { "accept-ranges",           ""                     },
    { "accept",                  ""                     },
    { "access-control-allow-origin",""                  },
    { "age",                     ""                     },
    { "allow",                   ""                     },
    { "authorization",           ""                     },
    { "cache-control",           ""                     },
    { "content-disposition",     ""                     },
    { "content-encoding",        ""                     },
    { "content-language",        ""                     },
    { "content-length",          ""                     },
    { "content-location",        ""                     },
    { "content-range",           ""                     },
    { "content-type",            ""                     },
    { "cookie",                  ""                     },
    { "date",                    ""                     },
    { "etag",                    ""                     },
    { "expect",                  ""                     },
    { "expires",                 ""                     },
    { "from",                    ""                     },
    { "host",                    ""                     },
    { "if-match",                ""                     },
    { "if-modified-since",       ""                     },
    { "if-none-match",           ""                     },
    { "if-range",                ""                     },
    { "if-unmodified-since",     ""                     },
    { "last-modified",           ""                     },
    { "link",                    ""                     },
    { "location",                ""                     },
    { "max-forwards",            ""                     },
    { "proxy-authenticate",      ""                     },
    { "proxy-authorization",     ""                     },
    { "range",                   ""                     },
    { "referer",                 ""                     },
    { "refresh",                 ""                     },
    { "retry-after",             ""                     },
    { "server",                  ""                     },
    { "set-cookie",              ""                     },
    { "strict-transport-security",""                    },
    { "transfer-encoding",       ""                     },
    { "user-agent",              ""                     },
    { "vary",                    ""                     },
    { "via",                     ""                     },
    { "www-authenticate",        ""                     },
};

/* Look up exact name+value match in static table → index or 0 */
static int hpack_find_exact(const char *n, const char *v) {
    for (int i = 1; i <= 61; i++) {
        if (strcmp(HPACK_STATIC[i].name, n) == 0 &&
            strcmp(HPACK_STATIC[i].value, v) == 0)
            return i;
    }
    return 0;
}

/* Look up name-only match → smallest index or 0 */
static int hpack_find_name(const char *n) {
    for (int i = 1; i <= 61; i++) {
        if (strcmp(HPACK_STATIC[i].name, n) == 0) return i;
    }
    return 0;
}

/* ---- HPACK integer encoding (RFC 7541 §5.1) ---- */

/* Encode `value` with `prefix_bits` bits available in the first byte.
 * `first_byte_high` = high bits to OR into the first byte
 * (e.g. 0x00 for literal, 0x80 for indexed).
 */
static int hpack_enc_int(h2_buf_t *out, uint32_t value,
                         int prefix_bits, uint8_t first_byte_high) {
    uint32_t max_prefix = (1u << prefix_bits) - 1;
    if (value < max_prefix) {
        return h2_buf_append_u8(out, first_byte_high | (uint8_t)value);
    }
    if (h2_buf_append_u8(out, first_byte_high | (uint8_t)max_prefix) != 0)
        return -1;
    value -= max_prefix;
    while (value >= 128) {
        if (h2_buf_append_u8(out, (uint8_t)((value & 0x7f) | 0x80)) != 0)
            return -1;
        value >>= 7;
    }
    return h2_buf_append_u8(out, (uint8_t)value);
}

/* Decode HPACK integer. *pos advanced past the integer.
 * Returns 0 on success and sets *out. */
static int hpack_dec_int(const uint8_t *in, size_t in_len, size_t *pos,
                         int prefix_bits, uint32_t *out) {
    if (*pos >= in_len) return -1;
    uint32_t max_prefix = (1u << prefix_bits) - 1;
    uint32_t val = in[*pos] & max_prefix;
    (*pos)++;
    if (val < max_prefix) { *out = val; return 0; }
    uint32_t shift = 0;
    for (;;) {
        if (*pos >= in_len) return -1;
        if (shift > 21) return -1;
        uint8_t b = in[*pos];
        (*pos)++;
        val += (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    *out = val;
    return 0;
}

/* Encode a string: length + bytes (no Huffman, high bit of length = 0). */
static int hpack_enc_str(h2_buf_t *out, const char *s) {
    size_t n = strlen(s);
    if (hpack_enc_int(out, (uint32_t)n, 7, 0x00) != 0) return -1;
    return h2_buf_append(out, s, n);
}

/* Decode a string (may be Huffman — we don't decode Huffman,
 * so if H bit is set we fail). */
static int hpack_dec_str(const uint8_t *in, size_t in_len, size_t *pos,
                         char **out, size_t *out_len) {
    if (*pos >= in_len) return -1;
    int huffman = (in[*pos] & 0x80) ? 1 : 0;
    uint32_t n = 0;
    if (hpack_dec_int(in, in_len, pos, 7, &n) != 0) return -1;
    if (*pos + n > in_len) return -1;
    if (huffman) {
        if (h2_huff_decode(in + *pos, n, out) != 0) return -1;
        if (out_len) *out_len = strlen(*out);
    } else {
        char *s = malloc(n + 1);
        if (!s) return -1;
        memcpy(s, in + *pos, n);
        s[n] = 0;
        *out = s;
        if (out_len) *out_len = n;
    }
    *pos += n;
    return 0;
}

/* ---- Public encode ---- */

int h2_hpack_encode(const http_headers_t *hdrs, h2_buf_t *out) {
    if (!hdrs || !out) return -1;

    for (size_t i = 0; i < hdrs->count; i++) {
        const char *n = hdrs->items[i].name;
        const char *v = hdrs->items[i].value;

        int idx_exact = hpack_find_exact(n, v);
        if (idx_exact > 0) {
            /* Indexed Header Field: 1xxxxxxx */
            if (hpack_enc_int(out, (uint32_t)idx_exact, 7, 0x80) != 0)
                return -1;
            continue;
        }

        int idx_name = hpack_find_name(n);
        if (idx_name > 0) {
            /* Literal without indexing, indexed name:
             *   0000xxxx (prefix 4 bits) = index into static table */
            if (hpack_enc_int(out, (uint32_t)idx_name, 4, 0x00) != 0)
                return -1;
        } else {
            /* Literal without indexing, new name:
             *   0000 0000 (0x00) then length-prefixed name */
            if (h2_buf_append_u8(out, 0x00) != 0) return -1;
            if (hpack_enc_str(out, n) != 0) return -1;
        }
        /* Value string */
        if (hpack_enc_str(out, v) != 0) return -1;
    }
    return 0;
}

/* ---- Public decode ---- */

/* HPACK dynamic table (RFC 7541 §2.3). Process-local, thread-local,
 * reset per-connection in a future patch. For now: shared across decodes. */
#define HPACK_DYN_MAX 128
typedef struct { char *name; char *value; size_t size; } hpack_dyn_t;

int h2_hpack_decode(const uint8_t *in, size_t in_len, http_headers_t *out) {
    if (!in || !out) return -1;
    size_t pos = 0;

    static __thread hpack_dyn_t dyn[HPACK_DYN_MAX];
    static __thread size_t dyn_count = 0;
    static __thread size_t dyn_size = 0;
    static __thread size_t dyn_max = 4096;

    while (pos < in_len) {
        uint8_t b = in[pos];

        /* Dynamic Table Size Update: 001xxxxx */
        if ((b & 0xe0) == 0x20) {
            uint32_t new_size = 0;
            if (hpack_dec_int(in, in_len, &pos, 5, &new_size) != 0) return -1;
            dyn_max = new_size;
            while (dyn_size > dyn_max && dyn_count > 0) {
                dyn_count--;
                dyn_size -= dyn[dyn_count].size;
                free(dyn[dyn_count].name);
                free(dyn[dyn_count].value);
            }
            H2_TRACE("[hpack] size update to %u\n", new_size);
            continue;
        }

        /* Indexed Header Field: 1xxxxxxx */
        if (b & 0x80) {
            uint32_t idx = 0;
            if (hpack_dec_int(in, in_len, &pos, 7, &idx) != 0) return -1;
            if (idx == 0) return -1;
            if (idx <= 61) {
                http_headers_add(out, HPACK_STATIC[idx].name, HPACK_STATIC[idx].value);
            } else {
                size_t di = idx - 62;
                if (di >= dyn_count) return -1;
                http_headers_add(out, dyn[di].name, dyn[di].value);
            }
            continue;
        }

        /* Literal with incremental indexing: 01xxxxxx */
        if ((b & 0xc0) == 0x40) {
            uint32_t idx = 0;
            if (hpack_dec_int(in, in_len, &pos, 6, &idx) != 0) return -1;
            char *name = NULL, *value = NULL;
            size_t name_len = 0, val_len = 0;
            if (idx == 0) {
                if (hpack_dec_str(in, in_len, &pos, &name, &name_len) != 0) return -1;
            } else if (idx <= 61) {
                name = strdup(HPACK_STATIC[idx].name);
                name_len = strlen(name);
            } else {
                size_t di = idx - 62;
                if (di >= dyn_count) return -1;
                name = strdup(dyn[di].name);
                name_len = strlen(name);
            }
            if (hpack_dec_str(in, in_len, &pos, &value, &val_len) != 0) {
                free(name); return -1;
            }
            http_headers_add(out, name, value);

            /* Insert into dynamic table (newest first) if it fits. */
            size_t esz = name_len + val_len + 32;
            if (esz <= dyn_max) {
                while (dyn_size + esz > dyn_max && dyn_count > 0) {
                    dyn_count--;
                    dyn_size -= dyn[dyn_count].size;
                    free(dyn[dyn_count].name);
                    free(dyn[dyn_count].value);
                }
                if (dyn_count == HPACK_DYN_MAX) {
                    dyn_count--;
                    dyn_size -= dyn[dyn_count].size;
                    free(dyn[dyn_count].name);
                    free(dyn[dyn_count].value);
                }
                memmove(&dyn[1], &dyn[0], dyn_count * sizeof(dyn[0]));
                dyn[0].name = strdup(name);
                dyn[0].value = strdup(value);
                dyn[0].size = esz;
                dyn_size += esz;
                dyn_count++;
            }
            free(name);
            free(value);
            continue;
        }

        /* Literal without indexing / never indexed: 0000xxxx or 0001xxxx */
        {
            uint32_t idx = 0;
            if (hpack_dec_int(in, in_len, &pos, 4, &idx) != 0) return -1;
            char *name = NULL, *value = NULL;
            size_t name_len = 0, val_len = 0;
            if (idx == 0) {
                if (hpack_dec_str(in, in_len, &pos, &name, &name_len) != 0) return -1;
            } else if (idx <= 61) {
                name = strdup(HPACK_STATIC[idx].name);
                name_len = strlen(name);
            } else {
                size_t di = idx - 62;
                if (di >= dyn_count) return -1;
                name = strdup(dyn[di].name);
                name_len = strlen(name);
            }
            if (hpack_dec_str(in, in_len, &pos, &value, &val_len) != 0) {
                free(name); return -1;
            }
            http_headers_add(out, name, value);
            free(name);
            free(value);
        }
    }
    return 0;
}
