/** syntax.c — lexical integrity checks.
 *
 * Not a full parser. Catches the errors that break compilation:
 *   - unbalanced braces, parens, brackets
 *   - unbalanced #if/#endif
 *   - unterminated block comments
 *   - simple unterminated string check
 */

#include "sear.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    int brace, paren, bracket;
    int ifdef, endif;
    int in_block_comment;
    int in_string;
    char string_quote;
    int bad;
} lex_state_t;

static void process_line(lex_state_t *st, const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (st->in_block_comment) {
            if (c == '*' && i + 1 < n && p[i+1] == '/') { st->in_block_comment = 0; i++; }
            continue;
        }
        if (st->in_string) {
            if (c == '\\' && i + 1 < n) { i++; continue; }
            if (c == st->string_quote) st->in_string = 0;
            continue;
        }
        if (c == '/' && i + 1 < n && p[i+1] == '/') return;   /* line comment */
        if (c == '/' && i + 1 < n && p[i+1] == '*') { st->in_block_comment = 1; i++; continue; }
        if (c == '"' || c == '\'') { st->in_string = 1; st->string_quote = c; continue; }
        switch (c) {
        case '{': st->brace++;   break;
        case '}': st->brace--;   if (st->brace < 0) st->bad = 1; break;
        case '(': st->paren++;   break;
        case ')': st->paren--;   if (st->paren < 0) st->bad = 1; break;
        case '[': st->bracket++; break;
        case ']': st->bracket--; if (st->bracket < 0) st->bad = 1; break;
        }
    }
    /* unterminated string at end of line: bad */
    if (st->in_string) {
        /* C allows this only with \ continuation; treat as error for now */
        st->bad = 1;
    }
}

int sear_mode_syntax(const sear_file_t *f, const sear_opts_t *o) {
    (void)o;
    lex_state_t st = {0};

    size_t tw_lines = 0, cr_lines = 0, tab_lines = 0;

    for (size_t i = 0; i < f->n_lines; i++) {
        sear_line_t *l = &f->lines[i];
        sear_ws_classify(f, l);
        if (l->trail) tw_lines++;
        if (l->cr)    cr_lines++;
        if (l->lead_tab > 0) tab_lines++;

        /* count preprocessor directives on this line (best effort) */
        const char *p = l->p;
        size_t j = 0;
        while (j < l->len && (p[j] == ' ' || p[j] == '\t')) j++;
        if (p[j] == '#') {
            if (!strncmp(p + j, "#if",   3) ||
                !strncmp(p + j, "#ifdef",6) ||
                !strncmp(p + j, "#ifndef",7)) st.ifdef++;
            else if (!strncmp(p + j, "#endif", 6)) st.endif++;
        }

        process_line(&st, l->p, l->len);
    }

    printf("  %s\n", f->path);
    printf("  braces     %-6s (net %+d)\n", st.brace   == 0 ? "OK" : "FAIL", st.brace);
    printf("  parens     %-6s (net %+d)\n", st.paren   == 0 ? "OK" : "FAIL", st.paren);
    printf("  brackets   %-6s (net %+d)\n", st.bracket == 0 ? "OK" : "FAIL", st.bracket);
    printf("  ifdef      %-6s (if %d, endif %d)\n",
           st.ifdef == st.endif ? "OK" : "FAIL", st.ifdef, st.endif);
    printf("  comments   %-6s\n", st.in_block_comment ? "FAIL (unterminated)" : "OK");
    printf("  strings    %-6s\n", st.in_string ? "FAIL (unterminated)" : "OK");
    printf("  trailing   %zu line%s\n", tw_lines, tw_lines == 1 ? "" : "s");
    printf("  tabs       %zu line%s\n", tab_lines, tab_lines == 1 ? "" : "s");
    printf("  CR         %zu line%s\n", cr_lines, cr_lines == 1 ? "" : "s");

    int ok = (st.brace == 0 && st.paren == 0 && st.bracket == 0 &&
              st.ifdef == st.endif && !st.in_block_comment && !st.in_string && !st.bad);

    printf("\n  syntax %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
