/** loader.c — runtime profile definitions loaded from a config file.
 *
 * Format (INI-like, comments start with '#' or ';'):
 *   [profile-name]
 *   display = Chrome 132 on Linux
 *   user_agent = Mozilla/5.0 ...
 *   tls_min = 1.2
 *   tls_max = 1.3
 *   alpn = h2,http/1.1
 *   ciphers = 0x1301, 0x1302, 0x1303
 *   ciphers12 = 0xcca9, 0xcca8
 *   groups = 0x001d, 0x0017
 *   sigalgs = 0x0403, 0x0503
 *   extensions = 0, 23, 65281
 *   grease = 1
 *
 * Adding a browser release is a data change, not a C change.
 */

#include "crisptls_fingerprint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define LOADED_MAX 32
#define LIST_MAX   128

typedef struct {
    crisptls_profile_t p;
    int      used;
    char     name[64];
    char     display[128];
    char     ua[256];
    char     alpn[64];
    uint16_t ciphers[LIST_MAX];
    uint16_t ciphers_12[LIST_MAX];
    uint16_t groups[LIST_MAX];
    uint16_t sigalgs[LIST_MAX];
    uint16_t extensions[LIST_MAX];
} loaded_profile_t;

static loaded_profile_t g_loaded[LOADED_MAX];
static int g_nloaded;
static const char *g_names[LOADED_MAX + 1];
static int g_names_dirty = 1;

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

static int parse_list(const char *v, uint16_t *out, int cap) {
    int n = 0;
    while (*v && n < cap - 1) {
        while (*v && (isspace((unsigned char)*v) || *v == ',' || *v == ';')) v++;
        if (!*v) break;
        char *end = NULL;
        unsigned long x = strtoul(v, &end, 0);
        if (end == v) break;
        out[n++] = (uint16_t)x;
        v = end;
    }
    out[n] = 0;
    return n;
}

static int parse_tls_ver(const char *v) {
    if (strstr(v, "1.3") || strstr(v, "13")) return CRISPTLS_VERSION_TLS13;
    if (strstr(v, "1.2") || strstr(v, "12")) return CRISPTLS_VERSION_TLS12;
    return CRISPTLS_VERSION_TLS13;
}

static void finalize(loaded_profile_t *lp) {
    if (!lp || !lp->name[0]) return;
    lp->p.name = lp->name;
    lp->p.display = lp->display[0] ? lp->display : lp->name;
    lp->p.user_agent_hint = lp->ua[0] ? lp->ua : "cube/1.0";
    if (!lp->p.tls_max) lp->p.tls_max = CRISPTLS_VERSION_TLS13;
    if (!lp->p.tls_min) lp->p.tls_min = CRISPTLS_VERSION_TLS12;
    if (!lp->p.alpn) lp->p.alpn = lp->alpn[0] ? lp->alpn : "h2,http/1.1";
    if (!lp->p.ciphers) lp->p.ciphers = lp->ciphers;
    if (!lp->p.ciphers_12) lp->p.ciphers_12 = lp->ciphers_12;
    if (!lp->p.groups) lp->p.groups = lp->groups;
    if (!lp->p.sigalgs) lp->p.sigalgs = lp->sigalgs;
    if (!lp->p.extensions) lp->p.extensions = lp->extensions;
    lp->used = 1;
    g_names_dirty = 1;
}

int crisptls_profile_load_file(const char *path) {
    if (!path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    loaded_profile_t *cur = NULL;
    int added = 0;

    while (fgets(line, sizeof line, f)) {
        char *s = trim(line);
        if (!*s || *s == '#' || *s == ';') continue;
        if (*s == '[') {
            if (cur) { finalize(cur); if (cur->used) added++; }
            char *end = strchr(s, ']');
            if (!end) { cur = NULL; continue; }
            *end = 0;
            s = trim(s + 1);
            if (!*s) { cur = NULL; continue; }
            int slot = -1;
            for (int i = 0; i < g_nloaded; i++)
                if (!strcmp(g_loaded[i].name, s)) { slot = i; break; }
            if (slot < 0) {
                if (g_nloaded >= LOADED_MAX) { cur = NULL; continue; }
                slot = g_nloaded++;
            }
            cur = &g_loaded[slot];
            memset(cur, 0, sizeof(*cur));
            snprintf(cur->name, sizeof cur->name, "%s", s);
            continue;
        }
        if (!cur) continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = 0;
        char *key = trim(s);
        char *val = trim(eq + 1);
        if (!strcmp(key, "display"))            snprintf(cur->display, sizeof cur->display, "%s", val);
        else if (!strcmp(key, "user_agent") || !strcmp(key, "user-agent"))
                                                 snprintf(cur->ua, sizeof cur->ua, "%s", val);
        else if (!strcmp(key, "alpn"))          snprintf(cur->alpn, sizeof cur->alpn, "%s", val);
        else if (!strcmp(key, "tls_min"))       cur->p.tls_min = parse_tls_ver(val);
        else if (!strcmp(key, "tls_max"))       cur->p.tls_max = parse_tls_ver(val);
        else if (!strcmp(key, "ciphers"))       parse_list(val, cur->ciphers, LIST_MAX);
        else if (!strcmp(key, "ciphers12") || !strcmp(key, "ciphers_12"))
                                                 parse_list(val, cur->ciphers_12, LIST_MAX);
        else if (!strcmp(key, "groups"))        parse_list(val, cur->groups, LIST_MAX);
        else if (!strcmp(key, "sigalgs"))       parse_list(val, cur->sigalgs, LIST_MAX);
        else if (!strcmp(key, "extensions"))    parse_list(val, cur->extensions, LIST_MAX);
        else if (!strcmp(key, "grease"))        cur->p.send_grease = atoi(val) != 0;
    }
    if (cur) { finalize(cur); if (cur->used) added++; }
    fclose(f);
    return added;
}

const crisptls_profile_t *crisptls_profile_find_loaded(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < g_nloaded; i++)
        if (g_loaded[i].used && !strcmp(g_loaded[i].name, name))
            return &g_loaded[i].p;
    return NULL;
}

const char *const *crisptls_profile_loaded_names(void) {
    if (g_names_dirty) {
        int n = 0;
        for (int i = 0; i < g_nloaded && n < LOADED_MAX; i++)
            if (g_loaded[i].used) g_names[n++] = g_loaded[i].name;
        g_names[n] = NULL;
        g_names_dirty = 0;
    }
    return g_names;
}
