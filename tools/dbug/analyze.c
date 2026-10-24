/** analyze.c — static analysis with step-style nesting + per-fn summary. */

#include "dbug.h"
#include "symbols.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_DEPTH 4

int dbug_is_keyword(const char *name, size_t len) {
    static const char *KW[] = {
        "if","else","for","while","do","switch","case","default","break",
        "continue","return","goto","sizeof","typedef","struct","union","enum",
        "static","extern","const","volatile","inline","void","int","char","long",
        "short","float","double","signed","unsigned","_Bool","auto","register",
        "restrict","_Complex", NULL };
    for (int i = 0; KW[i]; i++)
        if (strlen(KW[i]) == len && !strncmp(name, KW[i], len)) return 1;
    return 0;
}
int dbug_is_ident(int c) {
    return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_';
}
int dbug_is_risky(const char *name) {
    static const char *R[] = {
        "strcpy","strcat","sprintf","vsprintf","gets",
        "memcpy","memmove","memset",
        "malloc","calloc","realloc","free",
        "scanf","fscanf","sscanf",
        "system","popen","execl","execv","execvp", NULL };
    for (int i = 0; R[i]; i++) if (!strcmp(R[i], name)) return 1;
    return 0;
}

size_t dbug_body_end(const sear_file_t *f, size_t start) {
    int depth = 0, opened = 0;
    for (size_t i = start; i < f->n_lines; i++) {
        const sear_line_t *l = &f->lines[i];
        for (size_t k = 0; k < l->len; k++) {
            if (l->p[k] == '{') { depth++; opened = 1; }
            else if (l->p[k] == '}') {
                depth--;
                if (opened && depth == 0) return i;
            }
        }
    }
    return SIZE_MAX;
}

/* A function has a body iff we see '{' on the same line or within 3 lines. */
static int has_body_nearby(const sear_file_t *f, size_t start) {
    for (size_t i = start; i < f->n_lines && i < start + 4; i++) {
        const sear_line_t *l = &f->lines[i];
        for (size_t k = 0; k < l->len; k++) {
            if (l->p[k] == '{') return 1;
            if (l->p[k] == ';') return 0;
        }
    }
    return 0;
}

/* ---- import lookup ---- */
static int try_path(const char *dir, const char *name, char *out, size_t sz) {
    if (!dir || !*dir) return 0;
    int n = snprintf(out, sz, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sz) return 0;
    return access(out, R_OK) == 0;
}
static int find_import(const char *raw, size_t raw_len, const char *src,
                       char *out, size_t outsz)
{
    if (raw_len < 3) return 0;
    int angled = (raw[0] == '<');
    if (raw[0] != '<' && raw[0] != '"') return 0;
    if (raw[raw_len-1] != (angled ? '>' : '"')) return 0;
    char name[512];
    size_t nl = raw_len - 2;
    if (nl >= sizeof(name)) return 0;
    memcpy(name, raw + 1, nl); name[nl] = 0;
    if (!angled) {
        char dir[1024];
        const char *slash = strrchr(src, '/');
        if (slash) {
            size_t dl = (size_t)(slash - src);
            if (dl < sizeof(dir)) {
                memcpy(dir, src, dl); dir[dl] = 0;
                if (try_path(dir, name, out, outsz)) return 1;
            }
        }
    }
    static const char *INCS[] = {
        "/usr/include", "/usr/local/include", NULL };
    for (int i = 0; INCS[i]; i++)
        if (try_path(INCS[i], name, out, outsz)) return 1;
    return 0;
}

/* ---- per-function summary ---- */
static void describe_calls(const sear_file_t *f, size_t start, size_t end,
                           char *out, size_t outsz)
{
    int reads=0, writes=0, allocs=0, frees=0, files=0, strs=0, execs=0, mems=0;
    for (size_t i = start; i <= end && i < f->n_lines; i++) {
        const sear_line_t *L = &f->lines[i];
        size_t j = 0;
        while (j < L->len) {
            if (!dbug_is_ident(L->p[j])) { j++; continue; }
            size_t s = j;
            while (j < L->len && dbug_is_ident(L->p[j])) j++;
            size_t nl = j - s;
            if (!nl || nl > 63 || j >= L->len || L->p[j] != '(') continue;
            char name[64]; memcpy(name, L->p + s, nl); name[nl] = 0;
            if (dbug_is_keyword(name, nl)) continue;
            if (strstr(name,"read")||strstr(name,"scanf")||strstr(name,"fgets")) reads++;
            else if (strstr(name,"write")||strstr(name,"printf")||strstr(name,"puts")||strstr(name,"putc")) writes++;
            else if (strstr(name,"malloc")||strstr(name,"calloc")||strstr(name,"realloc")) allocs++;
            else if (!strcmp(name,"free")) frees++;
            else if (strstr(name,"open")||strstr(name,"close")||strstr(name,"fopen")||strstr(name,"fclose")) files++;
            else if (strstr(name,"strcpy")||strstr(name,"strcat")||strstr(name,"strlen")||strstr(name,"strcmp")) strs++;
            else if (strstr(name,"system")||strstr(name,"exec")||strstr(name,"popen")) execs++;
            else if (strstr(name,"memcpy")||strstr(name,"memset")||strstr(name,"memmove")) mems++;
        }
    }
    size_t w = 0;
    #define APPEND(s) do { if (w) w += (size_t)snprintf(out+w,outsz-w,", "); \
        w += (size_t)snprintf(out+w,outsz-w,"%s",s); } while (0)
    if (allocs) APPEND("allocates");
    if (frees)  APPEND("frees");
    if (reads)  APPEND("reads");
    if (writes) APPEND("writes");
    if (files)  APPEND("file-io");
    if (strs)   APPEND("string ops");
    if (mems)   APPEND("memory ops");
    if (execs)  APPEND("execs");
    if (!w)     snprintf(out, outsz, "no external calls");
    #undef APPEND
}

/* ---- nested step printer ---- */

typedef struct { const char *name; size_t start, end; } fn_t;

/* find index of fn by name, or -1 */
static int find_fn(const fn_t *arr, int n, const char *name) {
    for (int i = 0; i < n; i++) if (!strcmp(arr[i].name, name)) return i;
    return -1;
}

static int on_stack(const int *stack, int sp, int idx) {
    for (int i = 0; i < sp; i++) if (stack[i] == idx) return 1;
    return 0;
}

static void print_body(const sear_file_t *f, size_t start, size_t end,
                       const fn_t *fns, int nfns, int indent, int depth,
                       int *stack, int sp)
{
    int brace = 1;
    for (size_t i = start + 1; i <= end && i < f->n_lines; i++) {
        const sear_line_t *l = &f->lines[i];
        size_t t = 0;
        while (t < l->len && (l->p[t]==' '||l->p[t]=='\t')) t++;
        if (t == l->len) continue;
        if (l->p[t]=='/' && (l->p[t+1]=='/'||l->p[t+1]=='*')) continue;

        int dedent = (l->p[t]=='}');
        int cur = brace - (dedent?1:0); if (cur<0) cur=0;

        printf("        ");
        for (int d = 0; d < indent + cur; d++) fputs("  ", stdout);
        printf("%sL%-4zu%s ", COL.dim, l->line_no, COL.reset);

        /* print line, coloring calls, detecting in-file fns */
        int nested = -1;
        size_t j = 0;
        while (j < l->len) {
            if (!dbug_is_ident(l->p[j])) { putchar(l->p[j]); j++; continue; }
            size_t s = j;
            while (j < l->len && dbug_is_ident(l->p[j])) j++;
            size_t nl = j - s;
            char name[128];
            size_t cn = nl < sizeof(name)-1 ? nl : sizeof(name)-1;
            memcpy(name, l->p + s, cn); name[cn] = 0;
            int is_call = (j < l->len && l->p[j]=='(') &&
                          !dbug_is_keyword(name, nl);
            if (is_call) {
                int idx = find_fn(fns, nfns, name);
                if (idx >= 0 && !on_stack(stack, sp, idx) && depth < MAX_DEPTH) {
                    nested = idx;
                    printf("%s%s%s%s", COL.bold, COL.green, name, COL.reset);
                } else if (dbug_is_risky(name)) {
                    printf("%s%s%s", COL.red, name, COL.reset);
                } else {
                    printf("%s%s%s", COL.cyan, name, COL.reset);
                }
            } else {
                fwrite(l->p + s, 1, nl, stdout);
            }
        }
        putchar('\n');

        if (nested >= 0) {
            printf("        ");
            for (int d = 0; d < indent + cur + 1; d++) fputs("  ", stdout);
            printf("%s>>> %s%s\n", COL.dim, fns[nested].name, COL.reset);
            int ns[64]; memcpy(ns, stack, sizeof(int)*sp);
            if (sp < 64) ns[sp] = nested;
            print_body(f, fns[nested].start, fns[nested].end,
                       fns, nfns, indent + cur + 2, depth + 1,
                       ns, sp + 1 < 64 ? sp + 1 : 64);
        }

        for (size_t m = 0; m < l->len; m++) {
            if (l->p[m]=='{') brace++;
            else if (l->p[m]=='}') brace--;
        }
        if (brace<0) brace=0;
    }
}

int dbug_static(const dbug_opts_t *o) {
    sear_file_t f;
    if (sear_file_load(o->file, &f) != 0) return 2;
    sear_sym_t *syms = NULL;
    size_t n = 0;
    if (sear_symbols_scan(&f, &syms, &n) != 0) { sear_file_free(&f); return 2; }

    printf("  %s%s%s\n", COL.bold, o->file, COL.reset);

    int imp_ok=0, imp_bad=0, fn_ok=0, fn_bad=0;
    (void)fn_ok;



    printf("\n  %simports%s\n", COL.cyan, COL.reset);
    for (size_t i = 0; i < n; i++) {
        if (syms[i].kind != SEAR_SYM_IMPORT) continue;
        char path[1200];
        if (find_import(syms[i].name, strlen(syms[i].name), o->file,
                        path, sizeof(path))) {
            printf("    %sOK  %s%s  %s-> %s%s\n",
                   COL.green, COL.reset, syms[i].name, COL.dim, path, COL.reset);
            imp_ok++;
        } else {
            printf("    %sFAIL %s%s\n", COL.red, COL.reset, syms[i].name);
            imp_bad++;
        }
    }
    if (!imp_ok && !imp_bad) printf("    %s(none)%s\n", COL.dim, COL.reset);

    /* build fn index */
    fn_t fns[128]; int nfns = 0;
    for (size_t i = 0; i < n && nfns < 128; i++) {
        if (syms[i].kind != SEAR_SYM_FUNC) continue;
        size_t start = syms[i].line_no - 1;
        if (!has_body_nearby(&f, start)) continue;
        size_t end = dbug_body_end(&f, start);
        if (end == SIZE_MAX) continue;
        fns[nfns].name = syms[i].name;
        fns[nfns].start = start;
        fns[nfns].end = end;
        nfns++;
    }

    printf("\n  %sfunctions%s\n", COL.cyan, COL.reset);
    for (int i = 0; i < nfns; i++) {
        char what[256];
        describe_calls(&f, fns[i].start, fns[i].end, what, sizeof(what));
        printf("\n    %s%s%s  L%zu-%zu  (%zu lines)\n",
               COL.bold, fns[i].name, COL.reset,
               fns[i].start + 1, fns[i].end + 1,
               fns[i].end - fns[i].start + 1);
        printf("      %swhat:%s %s\n", COL.dim, COL.reset, what);
        int stk[64]; int sp = 0;
        stk[sp++] = i;
        print_body(&f, fns[i].start, fns[i].end, fns, nfns, 0, 0, stk, sp);
        fn_ok++;
    }

    printf("\n  %s%zu imports: %d OK, %d FAIL%s\n",
           COL.bold, (size_t)(imp_ok+imp_bad), imp_ok, imp_bad, COL.reset);
    printf("  %s%d functions%s\n", COL.bold, nfns, COL.reset);

    free(syms);
    sear_file_free(&f);
    return (imp_bad + fn_bad) ? 1 : 0;
}
