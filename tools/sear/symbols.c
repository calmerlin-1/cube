/** symbols.c — heuristic C symbol scanner.
 *
 * Not a real parser. Catches common cases:
 *   #include <...> or "..."
 *   #define NAME  (and function-like #define NAME(...))
 *   struct/enum/union NAME {
 *   typedef ... NAME;
 *   <type> name(...)  at column 0
 *   file-scope variable declarations
 *
 * Strings and comments are skipped so function-like text inside string
 * literals doesn't get counted as a function.
 */

#include "symbols.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int is_ident_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

/* C keywords and common type qualifiers that must not be reported as
 * function or variable names. */
static const char *KEYWORDS[] = {
    "if","else","for","while","do","switch","case","default","break","continue",
    "return","goto","sizeof","typeof","alignof","_Alignof",
    "void","int","char","short","long","float","double","signed","unsigned",
    "const","volatile","static","extern","inline","register","auto","restrict",
    "struct","union","enum","typedef",
    "defined",
    NULL
};
static int is_keyword(const char *s, size_t n) {
    for (int i = 0; KEYWORDS[i]; i++)
        if (strlen(KEYWORDS[i]) == n && !strncmp(s, KEYWORDS[i], n)) return 1;
    return 0;
}

static void add(sear_sym_t **arr, size_t *n, size_t *cap,
                sear_sym_kind_t k, size_t line, const char *name, size_t name_len)
{
    if (!name || name_len == 0) return;
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 32;
        *arr = sear_xrealloc(*arr, *cap * sizeof(**arr));
    }
    sear_sym_t *s = &(*arr)[*n];
    s->kind = k;
    s->line_no = line;
    s->name = sear_xstrndup(name, name_len);
    (*n)++;
}

/* Update brace nesting depth by scanning a line of code.
 * The line should already have strings blanked and line comments cut. */
static void update_depth(const char *p, size_t n, int *depth) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '{') (*depth)++;
        else if (p[i] == '}') { if (*depth > 0) (*depth)--; }
    }
}

static const char *skip_ws(const char *p, size_t *rem) {
    while (*rem > 0 && (*p == ' ' || *p == '\t')) { p++; (*rem)--; }
    return p;
}

/* Read identifier. Returns pointer just past it. name/name_len get the
 * identifier itself (start of first char, exact length). */
static const char *read_ident(const char *p, size_t *rem,
                              const char **name, size_t *name_len)
{
    const char *start = p;
    size_t n = 0;
    while (*rem > 0 && is_ident_char(*p)) { p++; n++; (*rem)--; }
    *name = start;
    *name_len = n;
    return p;
}

/* Copy this line, blanking out string contents (keeps length). Returned
 * buffer is malloc'd. This makes all substring searches on the line see
 * spaces where the string was, so keywords like "return (" inside a
 * string literal no longer look like a call. */
static char *blank_strings(const char *p, size_t n, int *in_str_out) {
    char *out = sear_xmalloc(n + 1);
    memcpy(out, p, n);
    out[n] = 0;
    int in_str = *in_str_out;
    char quote = 0;
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (in_str) {
            if (c == '\\' && i + 1 < n) { out[i] = ' '; out[i+1] = ' '; i++; continue; }
            if (c == quote) { in_str = 0; quote = 0; }
            out[i] = ' ';
            continue;
        }
        if (c == '"' || c == '\'') { in_str = 1; quote = c; out[i] = ' '; }
    }
    *in_str_out = in_str;
    return out;
}

static char *blank_comments(const char *p, size_t n, int *in_block) {
    char *out = sear_xmalloc(n + 1);
    memcpy(out, p, n);
    out[n] = 0;
    size_t i = 0;
    if (*in_block) {
        int closed = 0;
        while (i + 1 < n) {
            if (p[i] == '*' && p[i+1] == '/') { i += 2; closed = 1; break; }
            out[i] = ' ';
            i++;
        }
        if (!closed) { *in_block = 1; return out; }
        *in_block = 0;
    }
    while (i + 1 < n) {
        if (p[i] == '/' && p[i+1] == '*') {
            out[i] = ' '; out[i+1] = ' ';
            size_t j = i + 2;
            int closed = 0;
            while (j + 1 < n) {
                if (p[j] == '*' && p[j+1] == '/') { out[j] = ' '; out[j+1] = ' '; j += 2; closed = 1; break; }
                out[j] = ' ';
                j++;
            }
            if (!closed) { *in_block = 1; return out; }
            i = j;
        } else if (p[i] == '/' && p[i+1] == '/') {
            memset(out + i, ' ', n - i);
            return out;
        } else i++;
    }
    return out;
}
int sear_symbols_scan(const sear_file_t *f, sear_sym_t **out, size_t *out_n) {
    sear_sym_t *arr = NULL;
    size_t n = 0, cap = 0;
    int in_block_comment = 0;
    int in_string = 0;
    int depth = 0;   /* brace nesting depth; 0 = file scope */

    for (size_t i = 0; i < f->n_lines; i++) {
        const sear_line_t *l = &f->lines[i];
        const char *raw = l->p;
        size_t rem_raw = l->len;


        /* Blank out string contents in a copy of the line. */
        char *nocom = blank_comments(raw, rem_raw, &in_block_comment);
        char *clean = blank_strings(nocom, rem_raw, &in_string);
        free(nocom);

        /* Classify symbols using prev_depth (before this line's braces).
         * Then update depth for the next iteration. Doing this up front
         * means every `continue` below is safe. */
        int prev_depth = depth;
        update_depth(clean, l->len, &depth);

        size_t rem = rem_raw;
        const char *p = clean;

        p = skip_ws(p, &rem);

        if (rem > 0 && *p == '#') {
            if (rem >= 8 && !strncmp(p, "#include", 8)) {
                /* include paths are safe to scan on the raw line */
                const char *q = raw;
                size_t qr = rem_raw;
                q = skip_ws(q, &qr);
                q += 8; qr -= 8;
                q = skip_ws(q, &qr);
                if (qr > 0 && (*q == '<' || *q == '"')) {
                    char close = (*q == '<') ? '>' : '"';
                    const char *start = q + 1;
                    const char *end = memchr(start, close, qr - 1);
                    if (end) {
                        size_t hdr_len = (size_t)(end - q) + 1;
                        add(&arr, &n, &cap, SEAR_SYM_IMPORT, l->line_no, q, hdr_len);
                    }
                }
            } else if (rem >= 7 && !strncmp(p, "#define", 7)) {
                const char *q = p + 7;
                size_t qr = rem - 7;
                if (qr == 0 || (*q != ' ' && *q != '\t')) { free(clean); continue; }
                q = skip_ws(q, &qr);
                const char *name = NULL;
                size_t name_len = 0;
                q = read_ident(q, &qr, &name, &name_len);
                if (name_len > 0) {
                    size_t extra = 0;
                    if (qr > 0 && *q == '(') {
                        const char *close = memchr(q, ')', qr);
                        if (close) extra = (size_t)(close - q) + 1;
                    }
                    add(&arr, &n, &cap, SEAR_SYM_MACRO, l->line_no,
                        name, name_len + extra);
                }
            }
            free(clean);
            continue;
        }

        p = skip_ws(p, &rem);

        if (rem == 0) { free(clean); continue; }

        /* struct/enum/union NAME */
        if ((!strncmp(p, "struct ", 7) ||
             !strncmp(p, "union ",  6) ||
             !strncmp(p, "enum ",   5)))
        {
            const char *kw_end = strchr(p, ' ');
            const char *q = kw_end + 1;
            size_t qr = rem - (size_t)(q - p);
            const char *name = NULL;
            size_t name_len = 0;
            read_ident(q, &qr, &name, &name_len);
            if (name_len > 0 && !is_keyword(name, name_len))
                if (prev_depth == 0 && !is_keyword(name, name_len))
                add(&arr, &n, &cap, SEAR_SYM_STRUCT, l->line_no, name, name_len);
            free(clean);
            continue;
        }

        /* typedef ... NAME; */
        if (!strncmp(p, "typedef ", 8)) {
            const char *semi = memchr(p, ';', rem);
            if (semi) {
                const char *q = semi - 1;
                while (q > p && (*q == ' ' || *q == '\t')) q--;
                const char *end = q + 1;
                while (q >= p && is_ident_char(*q)) q--;
                const char *name = q + 1;
                size_t nl = (size_t)(end - name);
                if (prev_depth == 0 && nl > 0 && !is_keyword(name, nl))
                    add(&arr, &n, &cap, SEAR_SYM_STRUCT, l->line_no, name, nl);
            }
            free(clean);
            continue;
        }

        /* function vs global */
        {
            const char *paren = memchr(p, '(', rem);
            const char *semi  = memchr(p, ';', rem);
            const char *brace = memchr(p, '{', rem);

            const char *bound = p + rem;
            if (semi  && semi  < bound) bound = semi;
            if (brace && brace < bound) bound = brace;

            if (paren && paren < bound) {
                const char *q = paren - 1;
                while (q > p && (*q == ' ' || *q == '\t')) q--;
                const char *end = q + 1;
                while (q >= p && is_ident_char(*q)) q--;
                const char *name = q + 1;
                size_t nl = (size_t)(end - name);
                if (nl > 0 && !is_keyword(name, nl)) {
                    /* require the char before the name to be whitespace or '*' */
                    if (prev_depth == 0 &&
                        (name == p || name[-1] == ' ' || name[-1] == '\t' || name[-1] == '*'))
                        add(&arr, &n, &cap, SEAR_SYM_FUNC, l->line_no, name, nl);
                }
                free(clean);
                continue;
            }

            if (semi || (!paren && !brace)) {
                const char *eq = memchr(p, '=', rem);
                const char *bound2 = p + rem;
                if (semi && semi < bound2) bound2 = semi;
                if (eq && eq < bound2) bound2 = eq;

                const char *q = bound2 - 1;
                while (q > p && (*q == ' ' || *q == '\t')) q--;
                const char *end = q + 1;
                while (q >= p && is_ident_char(*q)) q--;
                const char *name = q + 1;
                size_t nl = (size_t)(end - name);
                if (nl > 0 && nl < 128 && !is_keyword(name, nl)) {
                    if (prev_depth == 0 &&
                        name > p &&
                        (name[-1] == ' ' || name[-1] == '\t' || name[-1] == '*') &&
                        (name[0] == '_' || (name[0] >= 'a' && name[0] <= 'z') ||
                         (name[0] >= 'A' && name[0] <= 'Z')))
                        add(&arr, &n, &cap, SEAR_SYM_GLOBAL, l->line_no, name, nl);
                }
            }
        }

        free(clean);
    }

    *out = arr;
    *out_n = n;
    return 0;
}
