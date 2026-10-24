/** sear.h — shared types for sear: search + analyze + patch for C source. */

#ifndef CUBE_TOOLS_SEAR_H
#define CUBE_TOOLS_SEAR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SEAR_VERSION "0.1"

/* ---- one line of a file ---- */
typedef struct {
    char    *p;        /* points into file buffer, NUL-terminated at end */
    size_t   len;      /* length excluding NUL, excluding trailing '\n' and '\r' */
    size_t   raw_len;  /* length as read, including any '\n'/'\r' */
    size_t   line_no;  /* 1-based */
    /* whitespace classification (computed lazily) */
    int      lead_sp;  /* count of leading spaces */
    int      lead_tab; /* count of leading tabs */
    int      trail;    /* 1 if trailing whitespace */
    int      cr;       /* 1 if line ended with \r */
    int      ws_ok;    /* 1 once classification is computed */
} sear_line_t;

/* ---- whole file ---- */
typedef struct {
    char          *buf;      /* owned */
    size_t         buf_len;
    sear_line_t   *lines;    /* owned */
    size_t         n_lines;
    int            crlf;     /* file used CRLF anywhere */
    const char    *path;
} sear_file_t;

/* ---- options ---- */
typedef struct {
    int         color;
    int         hints;
    int         brief;
    int         count_only;
    int         json;
    int         icase;
    int         apply;
    int         quiet;
    int         recurse;        /* -r: walk dirs */
    const char *mode;
    const char *pattern;        /* for search, --section, --subst */
    size_t      r_start;
    size_t      r_end;
    const char *range_str;
    const char *file;
    const char **files;         /* array of input files */
    size_t      n_files;
} sear_opts_t;

/* ---- colors (as strings, empty if disabled) ---- */
typedef struct {
    const char *reset;
    const char *bold;
    const char *dim;
    const char *cyan;
    const char *dim_cyan;
    const char *yellow;
    const char *red;
    const char *green;
} sear_colors_t;

extern sear_colors_t COL;

/* ---- strutil ---- */
void  *sear_xmalloc(size_t n);
void  *sear_xrealloc(void *p, size_t n);
char  *sear_xstrdup(const char *s);
char  *sear_xstrndup(const char *s, size_t n);
int    sear_endswith(const char *s, const char *suffix);
int    sear_startswith(const char *s, const char *pfx);
char  *sear_read_all_fd(int fd, size_t *out_len);

/* ---- io ---- */
int   sear_file_load(const char *path, sear_file_t *out);
void  sear_file_free(sear_file_t *f);
const sear_line_t *sear_line_at(const sear_file_t *f, size_t line_no_1);

/* ---- whitespace analysis ---- */
void  sear_ws_classify(const sear_file_t *f, sear_line_t *l);

/* ---- pattern ---- */
typedef struct sear_pattern sear_pattern_t;
sear_pattern_t *sear_pattern_substring(const char *needle, int icase);
sear_pattern_t *sear_pattern_regex(const char *re);
void            sear_pattern_free(sear_pattern_t *p);
/* Returns match start byte offset within [line, line+len), or SIZE_MAX. */
size_t          sear_pattern_find(const sear_pattern_t *p,
                                  const char *line, size_t len);

/* ---- output ---- */
void  sear_colors_set(int enable, int is_tty);
void  sear_ws_annot(char *out, size_t cap, const sear_line_t *l);
/* column (1-based char index) of first match. */
size_t sear_col_of_match(const char *line, size_t len, size_t match_off);
void  sear_print_line_detail(FILE *fp, const sear_line_t *l, size_t match_off,
                             int show_match_col);
void  sear_print_line_plain(FILE *fp, const sear_line_t *l);

/* ---- output helpers ---- */
void  sear_err(const char *fmt, ...);
void  sear_warn(const char *fmt, ...);

/* ---- directory walk ---- */
/* Call cb for each regular file with one of the given suffixes.
 * Returns 0 on success. `suffixes` is a NULL-terminated array. */
int sear_walk(const char *root, const char *const *suffixes,
              int (*cb)(const char *path, void *ud), void *ud);

/* ---- mode: section ---- */
int sear_mode_section(const sear_file_t *f, const sear_opts_t *o);

/* ---- mode: subst ---- */
int sear_mode_subst(const sear_file_t *f, const sear_opts_t *o);

/* ---- mode dispatch ---- */
int sear_mode_search_multi(const sear_opts_t *o);

#endif
