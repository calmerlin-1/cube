/** walk.c — recursive directory walk, filtered by file suffix. */

#include "erdict.h"
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

static int has_suffix(const char *name, const char *const *suffixes) {
    for (int i = 0; suffixes[i]; i++)
        if (erdict_endswith(name, suffixes[i])) return 1;
    return 0;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* collect all entries first, sort, then recurse — gives stable order */
static int walk_recursive(const char *root, const char *const *suffixes,
                          int (*cb)(const char *, void *), void *ud)
{
    DIR *d = opendir(root);
    if (!d) return -1;

    size_t cap = 64, n = 0;
    char **names = erdict_xmalloc(cap * sizeof(*names));

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (n == cap) { cap *= 2; names = erdict_xrealloc(names, cap * sizeof(*names)); }
        names[n++] = erdict_xstrdup(e->d_name);
    }
    closedir(d);

    qsort(names, n, sizeof(*names), cmp_str);

    int rc = 0;
    for (size_t i = 0; i < n && rc == 0; i++) {
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", root, names[i]);

        struct stat st;
        if (stat(full, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (walk_recursive(full, suffixes, cb, ud) != 0) rc = -1;
        } else if (S_ISREG(st.st_mode) && has_suffix(names[i], suffixes)) {
            if (cb(full, ud) != 0) rc = -1;
        }
    }

    for (size_t i = 0; i < n; i++) free(names[i]);
    free(names);
    return rc;
}

int erdict_walk(const char *root, const char *const *suffixes,
              int (*cb)(const char *, void *), void *ud)
{
    struct stat st;
    if (stat(root, &st) == 0 && S_ISREG(st.st_mode)) {
        /* a plain file — call directly */
        return cb(root, ud);
    }
    return walk_recursive(root, suffixes, cb, ud);
}
