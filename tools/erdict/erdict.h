/** erdict.h — shared types. */

#ifndef CUBE_TOOLS_ERDICT_H
#define CUBE_TOOLS_ERDICT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define ERDICT_VERSION "2.1"

typedef struct {
    char    *p;
    size_t   len;
    size_t   raw_len;
    size_t   line_no;
    int      lead_sp;
    int      lead_tab;
    int      trail;
    int      cr;
    int      ws_ok;
} erdict_line_t;

typedef struct {
    char          *buf;
    size_t         buf_len;
    erdict_line_t *lines;
    size_t         n_lines;
    int            crlf;
    const char    *path;
} erdict_file_t;

typedef struct {
    int         color;
    int         hints;
    int         brief;
    int         count_only;
    int         json;
    int         icase;
    int         rebuild;
    int         apply;
    int         yes;
    int         force;
    int         no_cc_check;
    int         ask;
    int         quiet;
    int         quiet_zero;
    int         recurse;
    const char *mode;
    const char *pattern;
    size_t      r_start;
    size_t      r_end;
    const char *range_str;
    const char *file;
    const char *add_import_val;
    const char *patch_import_val;
    const char **incs;
    const char **includes_from;
    size_t       n_includes_from;
    const char **cached_incs;
    size_t       n_cached_incs;
    size_t      n_incs;
    const char **files;
    size_t      n_files;
    const char *expect_hash;
    const char *from_make;    /* directory containing the Makefile */
    const char *from_file;    /* path to read replacement from (--from-file) */
} erdict_opts_t;

typedef struct {
    const char *reset;
    const char *bold;
    const char *dim;
    const char *cyan;
    const char *dim_cyan;
    const char *yellow;
    const char *red;
    const char *green;
} erdict_colors_t;

extern erdict_colors_t COL;

void  *erdict_xmalloc(size_t n);
void  *erdict_xrealloc(void *p, size_t n);
char  *erdict_xstrdup(const char *s);
char  *erdict_xstrndup(const char *s, size_t n);
int    erdict_endswith(const char *s, const char *suffix);
int    erdict_startswith(const char *s, const char *pfx);
char  *erdict_read_all_fd(int fd, size_t *out_len);

int   erdict_file_load(const char *path, erdict_file_t *out);
void  erdict_file_free(erdict_file_t *f);
const erdict_line_t *erdict_line_at(const erdict_file_t *f, size_t line_no_1);

void  erdict_ws_classify(const erdict_file_t *f, erdict_line_t *l);

typedef struct erdict_pattern erdict_pattern_t;
erdict_pattern_t *erdict_pattern_substring(const char *needle, int icase);
erdict_pattern_t *erdict_pattern_regex(const char *re);
erdict_pattern_t *erdict_pattern_regex_icase(const char *re, int icase);
void            erdict_pattern_free(erdict_pattern_t *p);
size_t          erdict_pattern_find(const erdict_pattern_t *p,
                                    const char *line, size_t len);

void  erdict_colors_set(int mode, int is_tty);
void  erdict_ws_annot(char *out, size_t cap, const erdict_line_t *l);
size_t erdict_col_of_match(const char *line, size_t len, size_t match_off);
void  erdict_print_line_detail(FILE *fp, const erdict_line_t *l, size_t match_off,
                               int show_match_col);
void  erdict_print_line_plain(FILE *fp, const erdict_line_t *l);

void  erdict_err(const char *fmt, ...);
void  erdict_warn(const char *fmt, ...);

int erdict_walk(const char *root, const char *const *suffixes,
                int (*cb)(const char *path, void *ud), void *ud);

int erdict_mode_section(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_subst(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_search_multi(const erdict_opts_t *o);

typedef struct {
    int brace, paren, bracket;
    int ifdef, endif;
    int in_block_comment;
    int in_string;
    int bad;
    size_t tw_lines, cr_lines, tab_lines;
    size_t first_brace_line, first_paren_line, first_bracket_line;
    size_t first_comment_line, first_string_line;
} erdict_syntax_result_t;

int erdict_syntax_check(const erdict_file_t *f, erdict_syntax_result_t *out);

int erdict_find_matching_brace(const erdict_file_t *f,
                               size_t start_line_1, size_t start_col_0,
                               size_t *end_line_1, size_t *end_col_0);

int erdict_mode_history(const char *file);
int erdict_mode_revert(const char *file, size_t index, int force);
int erdict_mode_revert_last(const char *file, int force);
int erdict_journal_pop(const char *file);
int erdict_journal_append(const char *file,
                          const char *old_content, size_t old_len,
                          const char *new_content, size_t new_len,
                          const char *action);


int erdict_scan_includes(const char *root, const char ***out, size_t *out_n);
/* FNV-1a 64-bit hash of lines [s..e] (0-based, inclusive). Returns hex string
 * in out_buf (must be at least 17 bytes). Deterministic across runs. */
int  erdict_parse_range(const erdict_file_t *f, const erdict_opts_t *o,
                        size_t *out_start, size_t *out_end);
void erdict_hash_range(const erdict_file_t *f, size_t s, size_t e, char out_buf[17]);
/* Query make -n for the target and extract -I flags. Returns 0 on success,
 * -1 if make failed or produced no -I flags. Writes space-separated list
 * (or empty) to out_buf; out_len must be >= 2048. */
int  erdict_make_incs(const char *makefile_dir, const char *target,
                      char *out_buf, size_t out_len);
/* Find a .c under root that #includes basename(header). Writes path into
 * out (>= 1024 bytes). Returns 0 on found, -1 if none. Used to make the
 * cc -fsyntax-only gate work for .h files (a header alone is not a TU). */
int  erdict_find_includer(const char *header_path, const char *root,
                          char *out_path, size_t out_len);
int erdict_check_external(const char *path, const char *cc, const char *cstd,
                          const char **incs, size_t n_incs);
int erdict_mode_check(const erdict_file_t *f, const erdict_opts_t *o);

int erdict_mode_lint(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_tree(const erdict_opts_t *o);
int erdict_mode_syntax(const erdict_file_t *f, const erdict_opts_t *o);

int erdict_mode_callers(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_callees(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_signature(const erdict_file_t *f, const erdict_opts_t *o);

int erdict_mode_patch_import(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_add_import(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_sort_imports(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_add_func(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_add_decl(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_rename_func(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_rename_tree(const erdict_opts_t *o);
#endif
