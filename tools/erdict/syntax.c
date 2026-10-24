/** syntax.c — lexical integrity checks.
 *
 * Not a full parser. Catches the errors that break compilation:
 *   - unbalanced braces, parens, brackets
 *   - unbalanced #if/#endif
 *   - unterminated block comments
 *   - simple unterminated string check
 *
 * Refactor note (step 0): the lex pass is now erdict_syntax_check(), which
 * returns a result struct instead of printing. erdict_mode_syntax() is a thin
 * formatter over it. Output is byte-identical to the pre-refactor version.
 * erdict_syntax_check() is what --check and --safe-write will call.
 */

#include "erdict.h"
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
    if (st->in_string) st->bad = 1;
}

/* Run the lexer over the whole file. Pure: no printing, no writes.
 * Returns 0 if the file is lexically clean, 1 if not. */
int erdict_syntax_check(const erdict_file_t *f, erdict_syntax_result_t *out) {
    lex_state_t st = {0};
    size_t tw = 0, cr = 0, tab = 0;
    size_t first_brace = 0, first_paren = 0, first_bracket = 0;
    size_t first_comment = 0, first_string = 0;

    for (size_t i = 0; i < f->n_lines; i++) {
        erdict_line_t *l = &f->lines[i];
        erdict_ws_classify(f, l);
        if (l->trail) tw++;
        if (l->cr)    cr++;
        if (l->lead_tab > 0) tab++;

        const char *p = l->p;
        size_t j = 0;
        while (j < l->len && (p[j] == ' ' || p[j] == '\t')) j++;
        if (p[j] == '#') {
            if (!strncmp(p + j, "#if",   3) ||
                !strncmp(p + j, "#ifdef",6) ||
                !strncmp(p + j, "#ifndef",7)) st.ifdef++;
            else if (!strncmp(p + j, "#endif", 6)) st.endif++;
        }

        int b0 = st.brace, p0 = st.paren, k0 = st.bracket;
        int c0 = st.in_block_comment, s0 = st.in_string;
        process_line(&st, l->p, l->len);
        if ((st.brace < 0 && b0 >= 0) && !first_brace) first_brace = i + 1;
        if ((st.paren < 0 && p0 >= 0) && !first_paren) first_paren = i + 1;
        if ((st.bracket < 0 && k0 >= 0) && !first_bracket) first_bracket = i + 1;
        if (st.in_block_comment && !c0 && !first_comment) first_comment = i + 1;
        if (st.in_string && !s0 && !first_string) first_string = i + 1;
    }

    if (out) {
        out->brace = st.brace;
        out->paren = st.paren;
        out->bracket = st.bracket;
        out->ifdef = st.ifdef;
        out->endif = st.endif;
        out->in_block_comment = st.in_block_comment;
        out->in_string = st.in_string;
        out->bad = st.bad;
        out->tw_lines = tw;
        out->cr_lines = cr;
        out->tab_lines = tab;
        out->first_brace_line = first_brace;
        out->first_paren_line = first_paren;
        out->first_bracket_line = first_bracket;
        out->first_comment_line = first_comment;
        out->first_string_line = first_string;
    }

    int ok = (st.brace == 0 && st.paren == 0 && st.bracket == 0 &&
              st.ifdef == st.endif && !st.in_block_comment && !st.in_string && !st.bad);
    return ok ? 0 : 1;
}

int erdict_mode_syntax(const erdict_file_t *f, const erdict_opts_t *o) {
    erdict_syntax_result_t r;
    int ok = erdict_syntax_check(f, &r) == 0;

    int issues = 0;
    if (r.brace) issues++;
    if (r.paren) issues++;
    if (r.bracket) issues++;
    if (r.ifdef != r.endif) issues++;
    if (r.in_block_comment) issues++;
    if (r.in_string) issues++;
    if (r.bad) issues++;

    size_t blanks = 0;
    for (size_t i = 0; i < f->n_lines; i++)
        if (f->lines[i].len == 0) blanks++;

    const char *G = COL.green, *R = COL.red, *Y = COL.yellow, *C = COL.cyan;

    /* ---- brief mode: only failures, path:line: check ---- */
    if (o->brief) {
        int printed = 0;
        if (r.brace) {
            printf("%s:%zu: braces: net %+d\n",
                   f->path, r.first_brace_line ? r.first_brace_line : 1, r.brace);
            printed = 1;
        }
        if (r.paren) {
            printf("%s:%zu: parens: net %+d\n",
                   f->path, r.first_paren_line ? r.first_paren_line : 1, r.paren);
            printed = 1;
        }
        if (r.bracket) {
            printf("%s:%zu: brackets: net %+d\n",
                   f->path, r.first_bracket_line ? r.first_bracket_line : 1, r.bracket);
            printed = 1;
        }
        if (r.ifdef != r.endif) {
            printf("%s: ifdef: if %d, endif %d\n", f->path, r.ifdef, r.endif);
            printed = 1;
        }
        if (r.in_block_comment) {
            printf("%s:%zu: comment: unterminated\n",
                   f->path, r.first_comment_line ? r.first_comment_line : 1);
            printed = 1;
        }
        if (r.in_string) {
            printf("%s:%zu: string: unterminated\n",
                   f->path, r.first_string_line ? r.first_string_line : 1);
            printed = 1;
        }
        if (!printed) printf("%s: OK\n", f->path);
        return ok ? 0 : 1;
    }

    /* ---- full mode: sections, no rules, no line numbers ---- */
    printf("  %s%s%s\n\n", C, f->path, COL.reset);

    printf("  %sstructure%s\n", Y, COL.reset);
    printf("    braces      %s%-6s%s (net %+d)\n",
           r.brace==0 ? G : R, r.brace==0 ? "OK" : "FAIL", COL.reset, r.brace);
    printf("    parens      %s%-6s%s (net %+d)\n",
           r.paren==0 ? G : R, r.paren==0 ? "OK" : "FAIL", COL.reset, r.paren);
    printf("    brackets    %s%-6s%s (net %+d)\n",
           r.bracket==0 ? G : R, r.bracket==0 ? "OK" : "FAIL", COL.reset, r.bracket);
    printf("    ifdef       %s%-6s%s (if %d, endif %d)\n",
           r.ifdef==r.endif ? G : R, r.ifdef==r.endif ? "OK" : "FAIL", COL.reset,
           r.ifdef, r.endif);
    printf("\n");

    printf("  %stext%s\n", Y, COL.reset);
    printf("    comments    %s%-6s%s\n",
           r.in_block_comment ? R : G,
           r.in_block_comment ? "FAIL" : "OK", COL.reset);
    printf("    strings     %s%-6s%s\n",
           r.in_string ? R : G,
           r.in_string ? "FAIL" : "OK", COL.reset);
    printf("\n");

    printf("  %swhitespace%s\n", Y, COL.reset);
    /* hygiene: cyan if zero, cyan if nonzero — never red (not a syntax error) */
    printf("    trailing    %s%zu lines%s\n", C, r.tw_lines, COL.reset);
    printf("    tabs        %s%zu lines%s\n", C, r.tab_lines, COL.reset);
    printf("    CR          %s%zu lines%s\n", C, r.cr_lines, COL.reset);
    printf("\n");

    printf("  %s%s%s · %s%d issues%s · %s%zu lines%s · "
           "%s%zu tabs%s · %s%zu TW%s · %s%zu CR%s · %s%zu blank%s\n",
           ok ? G : R, ok ? "syntax OK" : "syntax FAIL", COL.reset,
           issues ? R : G, issues, COL.reset,
           C, f->n_lines, COL.reset,
           C, r.tab_lines, COL.reset,
           C, r.tw_lines,  COL.reset,
           C, r.cr_lines,  COL.reset,
           C, blanks, COL.reset);

    return ok ? 0 : 1;
}
