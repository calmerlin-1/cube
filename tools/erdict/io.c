/** io.c — load a file into memory and split into lines.
 *
 * Line model:
 *   - buf holds the whole file with a trailing NUL
 *   - every line is NUL-terminated in place, so l->p is a valid C string
 *   - l->len excludes the trailing '\n' and any '\r' before it
 *   - l->raw_len is the number of bytes as read, including terminator(s)
 *   - l->line_no is 1-based
 *   - CRLF tracking is set on the file if any line ended with \r\n
 */

#include "erdict.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int erdict_file_load(const char *path, erdict_file_t *out) {
    memset(out, 0, sizeof(*out));
    out->path = path;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "erdict: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    size_t n = 0;
    char *buf = erdict_read_all_fd(fd, &n);
    close(fd);
    if (!buf) {
        fprintf(stderr, "erdict: cannot read %s\n", path);
        return -1;
    }
    out->buf = buf;
    out->buf_len = n;

    /* Count lines: n+1 upper bound, one extra for a final line without \n */
    size_t cap = 64;
    size_t count = 0;
    erdict_line_t *lines = erdict_xmalloc(cap * sizeof(*lines));

    size_t i = 0;
    while (i < n) {
        size_t start = i;
        /* find line end (either \n or EOF) */
        while (i < n && buf[i] != '\n') i++;
        size_t raw = i - start;
        if (i < n) raw += 1;   /* include the \n in raw_len */

        int had_cr = 0;
        size_t len = i - start;
        if (len > 0 && buf[start + len - 1] == '\r') {
            had_cr = 1;
            len--;
            buf[start + len] = 0;   /* NUL where \r was, before \n */
            if (i < n) buf[i - 1] = 0; /* also clear the \n slot */
        } else {
            if (i < n) buf[i] = 0;    /* NUL where \n was */
        }
        if (had_cr) out->crlf = 1;

        if (count == cap) {
            cap *= 2;
            lines = erdict_xrealloc(lines, cap * sizeof(*lines));
        }
        erdict_line_t *l = &lines[count];
        memset(l, 0, sizeof(*l));
        l->p       = buf + start;
        l->len     = len;
        l->raw_len = raw;
        l->line_no = count + 1;
        l->cr      = had_cr;
        count++;

        if (i < n) i++;  /* skip \n */
    }

    /* If file ends with a newline, don't add an empty final line. But if the
     * file is empty (n==0), still create one empty line so tools have something. */
    if (n == 0 && count == 0) {
        lines = erdict_xrealloc(lines, sizeof(*lines));
        memset(&lines[0], 0, sizeof(lines[0]));
        lines[0].p       = buf;
        lines[0].len     = 0;
        lines[0].raw_len = 0;
        lines[0].line_no = 1;
        count = 1;
    }

    out->lines = lines;
    out->n_lines = count;
    return 0;
}

void erdict_file_free(erdict_file_t *f) {
    if (!f) return;
    free(f->buf);
    free(f->lines);
    memset(f, 0, sizeof(*f));
}

const erdict_line_t *erdict_line_at(const erdict_file_t *f, size_t line_no_1) {
    if (!f || line_no_1 < 1 || line_no_1 > f->n_lines) return NULL;
    return &f->lines[line_no_1 - 1];
}
