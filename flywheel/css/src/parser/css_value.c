/** css_value.c — value inference. Turn raw text into structured form. */

#include "css_value.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static int is_num_start(char c) {
    return (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.';
}

static int is_hex_color(const char *s, int n) {
    if (n != 4 && n != 7) return 0;
    if (s[0] != '#') return 0;
    for (int i = 1; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static uint32_t parse_hex_rgb(const char *s, int n) {
    if (n == 4) {
        int r = hexval(s[1]);
        int g = hexval(s[2]);
        int b = hexval(s[3]);
        return (uint32_t)((r << 20) | (r << 16) | (g << 12) | (g << 8) | (b << 4) | b);
    }
    uint32_t r = (uint32_t)((hexval(s[1]) << 4) | hexval(s[2]));
    uint32_t g = (uint32_t)((hexval(s[3]) << 4) | hexval(s[4]));
    uint32_t b = (uint32_t)((hexval(s[5]) << 4) | hexval(s[6]));
    return (r << 16) | (g << 8) | b;
}

css_value_t *css_value_parse(css_arena_t *ar, const char *text, int len) {
    if (!text || len <= 0) return NULL;
    css_value_t *v = (css_value_t *)css_arena_alloc(ar, sizeof(*v));
    if (!v) return NULL;
    v->text = text;
    v->text_len = len;

    /* Trim leading whitespace */
    while (len > 0 && (text[0] == ' ' || text[0] == '\t')) { text++; len--; }
    /* Trim trailing whitespace */
    while (len > 0 && (text[len-1] == ' ' || text[len-1] == '\t')) len--;
    if (len == 0) { v->kind = CSSV_UNKNOWN; return v; }

    /* Hex color */
    if (is_hex_color(text, len)) {
        v->kind = CSSV_COLOR_HEX;
        v->rgb = parse_hex_rgb(text, len);
        return v;
    }

    /* String */
    if (text[0] == '"' || text[0] == '\'') {
        v->kind = CSSV_STRING;
        /* Strip quotes */
        if (len >= 2 && text[len-1] == text[0]) {
            v->text = text + 1;
            v->text_len = len - 2;
        }
        return v;
    }

    /* Function: name( ... ) */
    {
        int i = 0;
        while (i < len && (isalnum((unsigned char)text[i]) || text[i] == '-' || text[i] == '_')) i++;
        if (i > 0 && i < len && text[i] == '(') {
            v->kind = CSSV_FUNCTION;
            v->fn_name = text;
            v->fn_name_len = i;
            /* Find the matching close paren */
            int depth = 1;
            int j = i + 1;
            while (j < len && depth > 0) {
                if (text[j] == '(') depth++;
                else if (text[j] == ')') { depth--; if (depth == 0) break; }
                j++;
            }
            v->fn_args = text + i + 1;
            v->fn_args_len = j - (i + 1);
            return v;
        }
    }

    /* Number, dimension, percentage */
    if (is_num_start(text[0])) {
        char buf[64];
        int n = len < 63 ? len : 63;
        memcpy(buf, text, (size_t)n);
        buf[n] = '\0';

        char *endp = NULL;
        double d = strtod(buf, &endp);
        int consumed = (int)(endp - buf);

        if (consumed > 0 && consumed <= len) {
            /* Is the remainder a unit? */
            if (consumed == len) {
                v->kind = CSSV_NUMBER;
                v->number = d;
                return v;
            }
            if (len - consumed == 1 && text[consumed] == '%') {
                v->kind = CSSV_PERCENT;
                v->number = d;
                return v;
            }
            /* Length or other dimension */
            v->kind = CSSV_LENGTH;
            v->number = d;
            v->unit = text + consumed;
            v->unit_len = len - consumed;
            return v;
        }
    }

    /* Keyword (simple ident with only [a-z-]) */
    {
        int all_kw = 1;
        for (int i = 0; i < len; i++) {
            char c = text[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-'))
                { all_kw = 0; break; }
        }
        if (all_kw) {
            v->kind = CSSV_KEYWORD;
            return v;
        }
    }

    v->kind = CSSV_UNKNOWN;
    return v;
}

void css_value_dump(const css_value_t *v) {
    if (!v) { printf("(null value)"); return; }
    switch (v->kind) {
        case CSSV_NUMBER:    printf("NUM(%.6g)", v->number); break;
        case CSSV_LENGTH:    printf("LEN(%.6g%.*s)", v->number, v->unit_len, v->unit); break;
        case CSSV_PERCENT:   printf("PCT(%.6g%%)", v->number); break;
        case CSSV_COLOR_HEX: printf("COLOR(#%06x)", v->rgb); break;
        case CSSV_STRING:    printf("STR(%.*s)", v->text_len, v->text); break;
        case CSSV_URL:       printf("URL(%.*s)", v->text_len, v->text); break;
        case CSSV_KEYWORD:   printf("KW(%.*s)", v->text_len, v->text); break;
        case CSSV_FUNCTION:  printf("FN(%.*s(%.*s))",
                                    v->fn_name_len, v->fn_name,
                                    v->fn_args_len, v->fn_args); break;
        default:             printf("RAW(%.*s)", v->text_len, v->text); break;
    }
}
