/** journal.c — write-ahead log, history, revert. ERDICTJ2 format. */

#include "erdict.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define JOURNAL_MAGIC_V1 "ERDICTJ1"
#define JOURNAL_MAGIC_V2 "ERDICTJ2"

static char *journal_path(const char *file) {
    size_t n = strlen(file);
    char *p = erdict_xmalloc(n + 32);
    snprintf(p, n + 32, "%s.erdict-journal", file);
    return p;
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    rewind(fp);
    char *buf = erdict_xmalloc((size_t)sz + 1);
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = 0;
    if (out_len) *out_len = got;
    return buf;
}

static int write_file(const char *path, const char *data, size_t n) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t w = fwrite(data, 1, n, fp);
    fclose(fp);
    return w == n ? 0 : -1;
}

typedef struct {
    size_t  index;
    char    ts[32];
    char    action[128];
    char   *old_content;
    size_t  old_len;
    char   *new_content;
    size_t  new_len;
} journal_entry_t;

static void free_entries(journal_entry_t *e, size_t n) {
    for (size_t i = 0; i < n; i++) {
        free(e[i].old_content);
        free(e[i].new_content);
    }
    free(e);
}

/* ---------- writing (V2) ---------- */

int erdict_journal_append(const char *file,
                          const char *old_content, size_t old_len,
                          const char *new_content, size_t new_len,
                          const char *action)
{
    char *jp = journal_path(file);
    FILE *fp = fopen(jp, "ab");
    if (!fp) {
        erdict_err("cannot open journal %s: %s", jp, strerror(errno));
        free(jp);
        return -1;
    }

    if (ftell(fp) == 0) fprintf(fp, "%s\n", JOURNAL_MAGIC_V2);

    time_t now = time(NULL);
    struct tm tm; localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%S", &tm);

    fprintf(fp, "ENTRY %s %zu %zu\n", ts, old_len, new_len);
    fprintf(fp, "ACTION %s\n", action ? action : "-");
    fprintf(fp, "OLD\n");
    fwrite(old_content, 1, old_len, fp);
    fprintf(fp, "\nEND-OLD\n");
    fprintf(fp, "NEW\n");
    fwrite(new_content, 1, new_len, fp);
    fprintf(fp, "\nEND-NEW\n");

    fclose(fp);
    free(jp);
    return 0;
}

/* ---------- reading (V1 + V2) ---------- */

static int parse_v2(const char *buf, size_t len, journal_entry_t **out, size_t *out_n) {
    journal_entry_t *e = NULL;
    size_t n = 0, cap = 0;
    size_t i = strlen(JOURNAL_MAGIC_V2);
    while (i < len && (buf[i] == '\n' || buf[i] == '\r')) i++;

    while (i < len) {
        if (strncmp(buf + i, "ENTRY ", 6) != 0) break;
        i += 6;
        char ts[32];
        size_t old_len = 0, new_len = 0;
        int consumed = 0;
        if (sscanf(buf + i, "%31s %zu %zu%n", ts, &old_len, &new_len, &consumed) != 3) break;
        i += (size_t)consumed;
        while (i < len && (buf[i] == '\n' || buf[i] == '\r')) i++;

        char action[128] = "-";
        if (i + 7 <= len && strncmp(buf + i, "ACTION ", 7) == 0) {
            i += 7;
            size_t a = 0;
            while (i < len && buf[i] != '\n' && a < sizeof action - 1) action[a++] = buf[i++];
            action[a] = 0;
            while (i < len && (buf[i] == '\n' || buf[i] == '\r')) i++;
        }

        if (i + 4 > len || strncmp(buf + i, "OLD\n", 4) != 0) break;
        i += 4;
        if (i + old_len > len) break;
        char *oldc = erdict_xmalloc(old_len + 1);
        memcpy(oldc, buf + i, old_len);
        oldc[old_len] = 0;
        i += old_len;
        while (i < len && buf[i] == '\n') i++;
        if (i + 8 > len || strncmp(buf + i, "END-OLD\n", 8) != 0) { free(oldc); break; }
        i += 8;

        if (i + 4 > len || strncmp(buf + i, "NEW\n", 4) != 0) { free(oldc); break; }
        i += 4;
        if (i + new_len > len) { free(oldc); break; }
        char *newc = erdict_xmalloc(new_len + 1);
        memcpy(newc, buf + i, new_len);
        newc[new_len] = 0;
        i += new_len;
        while (i < len && buf[i] == '\n') i++;
        if (i + 8 > len || strncmp(buf + i, "END-NEW\n", 8) != 0) { free(oldc); free(newc); break; }
        i += 8;

        if (n == cap) { cap = cap ? cap * 2 : 8; e = erdict_xrealloc(e, cap * sizeof *e); }
        e[n].index = n + 1;
        snprintf(e[n].ts, sizeof e[n].ts, "%s", ts);
        snprintf(e[n].action, sizeof e[n].action, "%s", action);
        e[n].old_content = oldc;
        e[n].old_len = old_len;
        e[n].new_content = newc;
        e[n].new_len = new_len;
        n++;
    }
    *out = e;
    *out_n = n;
    return 0;
}

static int parse_v1(const char *buf, size_t len, journal_entry_t **out, size_t *out_n) {
    journal_entry_t *e = NULL;
    size_t n = 0, cap = 0;
    size_t i = strlen(JOURNAL_MAGIC_V1);
    while (i < len && buf[i] == '\n') i++;

    while (i < len) {
        if (strncmp(buf + i, "ENTRY ", 6) != 0) break;
        i += 6;
        char ts[32], action[64];
        size_t old_len = 0, new_len = 0;
        int consumed = 0;
        if (sscanf(buf + i, "%31s %63s %zu %zu%n", ts, action, &old_len, &new_len, &consumed) != 4)
            break;
        i += (size_t)consumed;
        while (i < len && buf[i] == '\n') i++;

        if (i + old_len > len) break;
        char *oldc = erdict_xmalloc(old_len + 1);
        memcpy(oldc, buf + i, old_len);
        oldc[old_len] = 0;
        i += old_len;

        if (i < len && buf[i] == '\n') i++;
        if (i + 7 <= len && strncmp(buf + i, "--OLD--", 7) == 0) i += 7;
        if (i < len && buf[i] == '\n') i++;

        if (i + new_len > len) { free(oldc); break; }
        char *newc = erdict_xmalloc(new_len + 1);
        memcpy(newc, buf + i, new_len);
        newc[new_len] = 0;
        i += new_len;

        if (i < len && buf[i] == '\n') i++;
        if (i + 7 <= len && strncmp(buf + i, "--NEW--", 7) == 0) i += 7;
        if (i < len && buf[i] == '\n') i++;

        if (n == cap) { cap = cap ? cap * 2 : 8; e = erdict_xrealloc(e, cap * sizeof *e); }
        e[n].index = n + 1;
        snprintf(e[n].ts, sizeof e[n].ts, "%s", ts);
        snprintf(e[n].action, sizeof e[n].action, "%s", action);
        e[n].old_content = oldc;
        e[n].old_len = old_len;
        e[n].new_content = newc;
        e[n].new_len = new_len;
        n++;
    }
    *out = e;
    *out_n = n;
    return 0;
}

static int parse_journal(const char *buf, size_t len, journal_entry_t **out, size_t *out_n) {
    if (len >= strlen(JOURNAL_MAGIC_V2) &&
        strncmp(buf, JOURNAL_MAGIC_V2, strlen(JOURNAL_MAGIC_V2)) == 0)
        return parse_v2(buf, len, out, out_n);
    if (len >= strlen(JOURNAL_MAGIC_V1) &&
        strncmp(buf, JOURNAL_MAGIC_V1, strlen(JOURNAL_MAGIC_V1)) == 0)
        return parse_v1(buf, len, out, out_n);
    return -1;
}

static int rewrite_v2(const char *jp, journal_entry_t *e, size_t keep) {
    FILE *jf = fopen(jp, "wb");
    if (!jf) return -1;
    fprintf(jf, "%s\n", JOURNAL_MAGIC_V2);
    for (size_t i = 0; i < keep; i++) {
        fprintf(jf, "ENTRY %s %zu %zu\n", e[i].ts, e[i].old_len, e[i].new_len);
        fprintf(jf, "ACTION %s\n", e[i].action);
        fprintf(jf, "OLD\n");
        fwrite(e[i].old_content, 1, e[i].old_len, jf);
        fprintf(jf, "\nEND-OLD\n");
        fprintf(jf, "NEW\n");
        fwrite(e[i].new_content, 1, e[i].new_len, jf);
        fprintf(jf, "\nEND-NEW\n");
    }
    fclose(jf);
    return 0;
}

int erdict_mode_history(const char *file) {
    char *jp = journal_path(file);
    size_t len = 0;
    char *buf = read_file(jp, &len);
    if (!buf) { erdict_err("no journal for %s", file); free(jp); return 1; }
    journal_entry_t *e = NULL;
    size_t n = 0;
    if (parse_journal(buf, len, &e, &n) != 0) {
        erdict_err("corrupt journal %s", jp);
        free(buf); free(jp); return 2;
    }
    /* header valid but body unparseable → corrupt, not empty */
    size_t magic_len = strlen(JOURNAL_MAGIC_V2);
    if (n == 0 && len > magic_len + 1) {
        erdict_err("corrupt journal %s (header OK, body unparseable)", jp);
        free_entries(e, n); free(buf); free(jp); return 2;
    }
    printf("  %s%s%s\n", COL.bold, file, COL.reset);
    if (n == 0) printf("  %s(no entries)%s\n", COL.dim, COL.reset);
    for (size_t i = 0; i < n; i++) {
        printf("  %s#%-3zu%s %s%-24s%s %-32s %s%zu → %zu bytes%s\n",
               COL.cyan, e[i].index, COL.reset,
               COL.dim, e[i].ts, COL.reset,
               e[i].action,
               COL.yellow, e[i].old_len, e[i].new_len, COL.reset);
    }
    free_entries(e, n);
    free(buf);
    free(jp);
    return 0;
}

static int revert_to(const char *file, size_t target_index, int force) {
    char *jp = journal_path(file);
    size_t len = 0;
    char *buf = read_file(jp, &len);
    if (!buf) { erdict_err("no journal for %s", file); free(jp); return 1; }

    journal_entry_t *e = NULL;
    size_t n = 0;
    if (parse_journal(buf, len, &e, &n) != 0) {
        erdict_err("corrupt journal %s", jp);
        free(buf); free(jp); return 2;
    }
    if (target_index < 1 || target_index > n) {
        erdict_err("entry #%zu out of range (1..%zu)", target_index, n);
        free_entries(e, n); free(buf); free(jp); return 2;
    }

    size_t cur_len = 0;
    char *cur = read_file(file, &cur_len);
    if (!cur) {
        erdict_err("cannot read %s", file);
        free_entries(e, n); free(buf); free(jp); return 2;
    }

    for (size_t i = n; i >= target_index && i > 0; i--) {
        journal_entry_t *en = &e[i - 1];
        if (!force && (cur_len != en->new_len || memcmp(cur, en->new_content, cur_len) != 0)) {
            erdict_err("file changed since entry #%zu; use --force to revert anyway", en->index);
            free(cur); free_entries(e, n); free(buf); free(jp); return 1;
        }
        free(cur);
        cur_len = en->old_len;
        cur = erdict_xmalloc(cur_len + 1);
        memcpy(cur, en->old_content, cur_len);
        cur[cur_len] = 0;
    }

    if (write_file(file, cur, cur_len) != 0) {
        erdict_err("cannot write %s", file);
        free(cur); free_entries(e, n); free(buf); free(jp); return 2;
    }

    rewrite_v2(jp, e, target_index - 1);

    printf("  reverted %s to entry %s#%zu%s (%zu bytes)\n",
           file, COL.cyan, target_index, COL.reset, cur_len);

    free(cur);
    free_entries(e, n);
    free(buf);
    free(jp);
    return 0;
}


/* Remove the last journal entry. Used to roll back when a write fails
 * after the journal was written (transactional apply). */
int erdict_journal_pop(const char *file) {
    char *jp = journal_path(file);
    size_t len = 0;
    char *buf = read_file(jp, &len);
    if (!buf) { free(jp); return -1; }
    journal_entry_t *e = NULL;
    size_t n = 0;
    if (parse_journal(buf, len, &e, &n) != 0 || n == 0) {
        free(buf); free(jp); return -1;
    }
    size_t keep = n - 1;
    int rc = rewrite_v2(jp, e, keep);
    free_entries(e, n);
    free(buf);
    free(jp);
    return rc;
}

int erdict_mode_revert(const char *file, size_t index, int force) {
    return revert_to(file, index, force);
}

int erdict_mode_revert_last(const char *file, int force) {
    char *jp = journal_path(file);
    size_t len = 0;
    char *buf = read_file(jp, &len);
    if (!buf) { erdict_err("no journal for %s", file); free(jp); return 1; }
    journal_entry_t *e = NULL;
    size_t n = 0;
    if (parse_journal(buf, len, &e, &n) != 0) {
        erdict_err("corrupt journal %s", jp);
        free(buf); free(jp); return 2;
    }
    free_entries(e, n);
    free(buf);
    free(jp);
    if (n == 0) { erdict_err("journal is empty"); return 1; }
    return revert_to(file, n, force);
}
