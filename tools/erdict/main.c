/** main.c — arg parse + dispatch. */
#include "erdict.h"
#include "symbols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int erdict_mode_search   (const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_range    (const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_structure(const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_syntax   (const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_stats    (const erdict_file_t *f, const erdict_opts_t *o);
int erdict_mode_patch    (const erdict_file_t *f, const erdict_opts_t *o);
int erdict_parse_range   (const erdict_file_t *f, const erdict_opts_t *o,
                        size_t *s, size_t *e);

static void usage(void) {
    const char *B = COL.bold, *R = COL.reset, *C = COL.cyan,
               *D = COL.dim,  *Y = COL.yellow;

    printf("  %susage:%s %serdict%s <file|dir> <cmd> [args]\n\n", D, R, B, R);

    printf("  %ssearch:%s\n", C, R);
    printf("    erdict <file> <text>                    %ssubstring search%s\n", D, R);
    printf("    erdict <file> /regex/                   %sregex search%s\n", D, R);
    printf("    erdict <file> <text> --icase            %scase-insensitive%s\n", D, R);
    printf("    erdict <file> <text> --brief            %sone line per match%s\n", D, R);
    printf("    erdict <file> <text> --count            %scount only%s\n", D, R);
    printf("    erdict <file> <text> --json             %sJSON output%s\n", D, R);

    printf("\n  %srange:%s\n", C, R);
    printf("    erdict <file> 10,20                     %slines 10-20%s\n", D, R);
    printf("    erdict <file> 10+5                      %slines 10-15%s\n", D, R);
    printf("    erdict <file> 5                          %ssingle line%s\n", D, R);
    printf("    erdict <file> /s/,/e/                   %sbetween pattern matches%s\n", D, R);

    printf("\n  %sstructure:%s\n", C, R);
    printf("    erdict <file> --funcs [pat]             %sfunction definitions%s\n", D, R);
    printf("    erdict <file> --structs                 "
           "%sstruct/enum/union/typedef%s\n", D, R);
    printf("    erdict <file> --macros                  %s#define entries%s\n", D, R);
    printf("    erdict <file> --imports                 %s#include lines%s\n", D, R);
    printf("    erdict <file> --globals                 %sfile-scope variables%s\n", D, R);
    printf("    erdict <file> --list                    %severything above%s\n", D, R);
    printf("    erdict <file> --section <name>          %sfunction body%s\n", D, R);
    printf("    erdict <file> --signature <name>        "
           "%sdefinition line only%s\n", D, R);

    printf("\n  %squeries:%s\n", C, R);
    printf("    erdict <file> --callers <sym>           "
           "%swhere <sym> is referenced%s\n", D, R);
    printf("    erdict <file> --callees <func>          %swhat <func> calls%s\n", D, R);

    printf("\n  %sanalysis:%s\n", C, R);
    printf("    erdict <file> --syntax [-r dir]         %sstructural check%s\n", D, R);
    printf("    erdict <file> --check [-r dir]          "
           "%ssyntax + cc -fsyntax-only%s\n", D, R);
    printf("    erdict <file> --lint [-r dir]           "
           "%strailing ws, tabs, CR, long lines%s\n", D, R);
    printf("    erdict <file> --stat                    %sfile summary%s\n", D, R);

    printf("\n  %spatch (dry-run by default; --apply to write):%s\n", C, R);
    printf("    erdict <file> <start>,<end> --patch     %sreplace range (stdin)%s\n", D, R);
    printf("    erdict <file> <start>       --insert    "
           "%sinsert before line (stdin)%s\n", D, R);
    printf("    erdict <file> <start>       --insert-after "
           "%sinsert after line%s\n", D, R);
    printf("    erdict <file> <start>,<end> --delete    %sdelete range%s\n", D, R);
    printf("    erdict <file>               --append    %sappend to end (stdin)%s\n", D, R);
    printf("    erdict <file>               --prepend   %sprepend to start (stdin)%s\n", D, R);
    printf("    erdict <file> --patch-func <name>       "
           "%sreplace function body (stdin)%s\n", D, R);
    printf("    erdict <file> --add-func <name>         "
           "%sappend new function body (stdin)%s\n", D, R);
    printf("    erdict <file> --add-decl '<text>'       "
           "%sinsert line before final #endif%s\n", D, R);
    printf("    erdict <file> --rename-func <old>:<new> %srename in one file%s\n", D, R);
    printf("    erdict <dir>  --rename-func <old>:<new> -r "
           "%srename across tree (atomic)%s\n", D, R);
    printf("    erdict <file> --subst /pat/             "
           "%sreplace matching lines (stdin)%s\n", D, R);

    printf("\n  %simports:%s\n", C, R);
    printf("    erdict <file> --add-import='<h>'        "
           "%sinsert #include if absent%s\n", D, R);
    printf("    erdict <file> --patch-import='<a>:<b>'  %sreplace one #include%s\n", D, R);
    printf("    erdict <file> --sort-imports            %ssort the #include block%s\n", D, R);

    printf("\n  %sjournal:%s\n", C, R);
    printf("    erdict <file> --history                 %slist journal entries%s\n", D, R);
    printf("    erdict <file> --revert <n>              %srevert to entry n%s\n", D, R);
    printf("    erdict <file> --revert-last             "
           "%sundo the last journaled change%s\n", D, R);

    printf("\n  %scommon:%s\n", C, R);
    printf("    %s--rebuild%s        after --apply, run make -j4 in cwd\n", B, R);
    printf("    %s--expect-hash=<h>%s verify range hash before --patch\n", B, R);
    printf("    %s--from-make=<dir>%s extract -I flags via make -n\n", B, R);
    printf("    %s--apply%s          commit changes (patch modes) + journal\n", B, R);
    printf("    %s--ask%s            prompt y/N on --apply\n", B, R);
    printf("    %s--yes%s            with --ask, skip the prompt\n", B, R);
    printf("    %s--force%s          bypass gates (syntax, cc), force revert, allow >50%% delete\n", B, R);
    printf("    %s--from-file=<p>%s  read replacement content from file instead of stdin\n", B, R);
    printf("    %s--color=MODE%s     auto (default) | always | never\n", B, R);
    printf("    %s--no-color%s       alias for --color=never\n", B, R);
    printf("    %s-r%s               recurse directories "
           "(search/syntax/check/lint)\n", B, R);
    printf("    %s-I<dir>%s         include dir for --check (repeatable)\n", B, R);
    printf("    %s--includes-from=<dir>%s  "
           "auto-discover -I dirs under <dir>\n", B, R);
    printf("    %s--quiet%s          suppress summary\n", B, R);
    printf("    %s--version%s        print version\n", B, R);
    printf("    %s--help%s           this message\n", B, R);

    printf("\n  %snote:%s --section and --patch-func are line-granular;\n"
           "        minified C (everything on one line) is not supported.\n",
           Y, R);
}

static const char *MODE_FLAGS[] = {
    "--funcs", "--structs", "--macros", "--imports", "--globals", "--list",
    "--syntax", "--stat", "--check", "--lint",
    "--patch", "--insert", "--insert-after", "--delete", "--append", "--prepend",
    "--subst", "--section", "--patch-func",
    "--history", "--revert", "--revert-last",
    "--callers", "--callees", "--signature",
    "--sort-imports",
    "--add-func", "--add-decl", "--rename-func",
    NULL
};

int main(int argc, char **argv) {
    erdict_opts_t o;
    memset(&o, 0, sizeof(o));
    o.color = 1;
    o.hints = 1;

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "--color=", 8)) {
            const char *v = argv[i] + 8;
            if      (!strcmp(v, "always")) o.color = 2;
            else if (!strcmp(v, "never"))  o.color = 0;
            else if (!strcmp(v, "auto"))   o.color = 1;
        } else if (!strcmp(argv[i], "--no-color")) {
            o.color = 0;
        }
    }
    erdict_colors_set(o.color, isatty(1));

    if (argc < 2) { usage(); return 2; }

    const char *files[256];
    size_t n_files = 0;
    const char *incs[64];
    size_t n_incs = 0;
    const char *inc_from[16];
    size_t n_inc_from = 0;
    const char *positional = NULL;
    const char *mode = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        else if (!strcmp(a, "--version") || !strcmp(a, "-V")) {
            printf("erdict %s\n", ERDICT_VERSION);
            return 0;
        }
        else if (!strcmp(a, "--rebuild"))   o.rebuild = 1;
        else if (!strncmp(a, "--expect-hash=", 14)) o.expect_hash = a + 14;
        else if (!strcmp(a, "--expect-hash")) {
            if (i + 1 < argc) o.expect_hash = argv[++i];
        }
        else if (!strncmp(a, "--from-make=", 12)) {
            o.from_make = a + 12;
        }
        else if (!strcmp(a, "--from-make")) {
            o.from_make = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : ".";
        }
        else if (!strncmp(a, "--from-file=", 12)) {
            o.from_file = a + 12;
        }
        else if (!strcmp(a, "--from-file")) {
            if (i + 1 < argc) o.from_file = argv[++i];
        }
        else if (!strcmp(a, "--apply"))     o.apply = 1;
        else if (!strcmp(a, "--ask"))       o.ask = 1;
        else if (!strcmp(a, "--yes"))       o.yes = 1;
        else if (!strcmp(a, "--force"))     o.force = 1;
        else if (!strcmp(a, "--no-cc-check")) o.no_cc_check = 1;
        else if (!strcmp(a, "--no-color"))  o.color = 0;
        else if (!strncmp(a, "--color=", 8)) {
            const char *v = a + 8;
            if      (!strcmp(v, "always")) o.color = 2;
            else if (!strcmp(v, "auto"))   o.color = 1;
            else if (!strcmp(v, "never"))  o.color = 0;
            else { fprintf(stderr, "erdict: bad --color value '%s'\n", v); return 2; }
        }
        else if (!strcmp(a, "--brief"))     o.brief = 1;
        else if (!strcmp(a, "--count"))     o.count_only = 1;
        else if (!strcmp(a, "--json"))      o.json = 1;
        else if (!strcmp(a, "--icase"))     o.icase = 1;
        else if (!strcmp(a, "--quiet"))     o.quiet = 1;
        else if (!strcmp(a, "-r"))          o.recurse = 1;
        else if (!strncmp(a, "--includes-from=", 16)) {
            if (n_inc_from < 16) inc_from[n_inc_from++] = a + 16;
        }
        else if (!strcmp(a, "--includes-from")) {
            if (i + 1 < argc && n_inc_from < 16) inc_from[n_inc_from++] = argv[++i];
        }
        else if (!strncmp(a, "-I", 2) && a[2]) {
            if (n_incs < 64) incs[n_incs++] = a + 2;
        }
        else if (!strcmp(a, "-I")) {
            if (i + 1 < argc && n_incs < 64) incs[n_incs++] = argv[++i];
        }
        else if (!strncmp(a, "--add-import=", 13)) {
            o.add_import_val = a + 13;
            mode = "add-import";
        }
        else if (!strncmp(a, "--patch-import=", 15)) {
            o.patch_import_val = a + 15;
            mode = "patch-import";
        }
        else if (a[0] == '-' && a[1] == '-') {
            int known = 0;
            for (int k = 0; MODE_FLAGS[k]; k++)
                if (!strcmp(a, MODE_FLAGS[k])) { known = 1; mode = a + 2; break; }
            if (!known) { fprintf(stderr, "erdict: unknown option %s\n", a); return 2; }
        } else {
            size_t alen = strlen(a);
            int is_regex_like = (alen >= 2 && a[0] == '/' && a[alen-1] == '/');
            int looks_like_file =
                !is_regex_like &&
                (erdict_endswith(a, ".c") ||
                 erdict_endswith(a, ".h") ||
                 (a[0] != '/' && a[0] != '-' && strchr(a, '.') != NULL) ||
                 a[0] == '/' || a[0] == '.');
            if (looks_like_file && n_files < 256) {
                files[n_files++] = a;
            } else if (!positional) {
                positional = a;
            } else {
                if (n_files < 256) files[n_files++] = positional;
                positional = a;
            }
        }
    }

    if (o.recurse && positional && n_files == 0) {
        files[n_files++] = positional;
        positional = NULL;
    }
    if (n_files == 0 && !positional) { usage(); return 2; }
    if (n_files == 0 && !mode) { usage(); return 2; }

    erdict_colors_set(o.color, isatty(1));
    o.incs = incs;
    o.n_incs = n_incs;
    o.includes_from = inc_from;
    o.n_includes_from = n_inc_from;
    if (getenv("ERDICT_DEBUG_ARGS")) {
        fprintf(stderr, "  files=%zu mode=%s recurse=%d includes_from=%zu\n",
                n_files, mode ? mode : "(null)", o.recurse, o.n_includes_from);
        for (size_t ii = 0; ii < o.n_includes_from; ii++)
            fprintf(stderr, "    inc_from[%zu]=%s\n", ii, o.includes_from[ii]);
        for (size_t di = 0; di < n_files; di++)
            fprintf(stderr, "    file[%zu]=%s\n", di, files[di]);
    }
    o.files = files;
    o.n_files = n_files;
    o.mode = mode;
    o.pattern = positional;
    o.file = n_files ? files[0] : NULL;

    /* If first arg is a directory, enable recurse automatically */
    if (o.file) {
        struct stat st;
        if (stat(o.file, &st) == 0 && S_ISDIR(st.st_mode)) {
            o.recurse = 1;
        }
    }

    int rc = 0;

    if (mode) {
        if (!strcmp(mode, "history")) {
            if (n_files == 0) { usage(); return 2; }
            rc = erdict_mode_history(files[0]);
        }
        else if (!strcmp(mode, "revert")) {
            if (n_files == 0) { usage(); return 2; }
            size_t idx = positional ? (size_t)atoi(positional) : 0;
            rc = erdict_mode_revert(files[0], idx, o.force);
        }
        else if (!strcmp(mode, "revert-last")) {
            if (n_files == 0) { usage(); return 2; }
            rc = erdict_mode_revert_last(files[0], o.force);
        }
        else if (!strcmp(mode, "check")) {
            if (n_files == 0) { usage(); return 2; }
            if (o.recurse) rc = erdict_mode_tree(&o);
            else {
                erdict_file_t f;
                if (erdict_file_load(files[0], &f) != 0) return 2;
                o.file = files[0];
                rc = erdict_mode_check(&f, &o);
                erdict_file_free(&f);
            }
        }
        else if (!strcmp(mode, "lint")) {
            if (n_files == 0) { usage(); return 2; }
            if (o.recurse) rc = erdict_mode_tree(&o);
            else {
                erdict_file_t f;
                if (erdict_file_load(files[0], &f) != 0) return 2;
                rc = erdict_mode_lint(&f, &o);
                erdict_file_free(&f);
            }
        }
        else if (!strcmp(mode, "syntax")) {
            if (n_files == 0) { usage(); return 2; }
            if (o.recurse) rc = erdict_mode_tree(&o);
            else {
                erdict_file_t f;
                if (erdict_file_load(files[0], &f) != 0) return 2;
                rc = erdict_mode_syntax(&f, &o);
                erdict_file_free(&f);
            }
        }
        else if (!strcmp(mode, "callers")) {
            if (n_files == 0) { usage(); return 2; }
            if (o.recurse) rc = erdict_mode_tree(&o);
            else {
                erdict_file_t f;
                if (erdict_file_load(files[0], &f) != 0) return 2;
                rc = erdict_mode_callers(&f, &o);
                erdict_file_free(&f);
            }
        }
        else if (!strcmp(mode, "callees")) {
            if (n_files == 0) { usage(); return 2; }
            if (o.recurse) rc = erdict_mode_tree(&o);
            else {
                erdict_file_t f;
                if (erdict_file_load(files[0], &f) != 0) return 2;
                rc = erdict_mode_callees(&f, &o);
                erdict_file_free(&f);
            }
        }
        else if (!strcmp(mode, "signature")) {
            if (n_files == 0) { usage(); return 2; }
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            rc = erdict_mode_signature(&f, &o);
            erdict_file_free(&f);
        }
        else if (!strcmp(mode, "patch-import")) {
            if (n_files == 0) { usage(); return 2; }
            if (!o.patch_import_val) {
                erdict_err("--patch-import=<old>:<new> is required");
                return 2;
            }
            char *pair = erdict_xstrdup(o.patch_import_val);
            char *colon = strchr(pair, ':');
            if (!colon) {
                erdict_err("--patch-import=<old>:<new> needs a ':' separator");
                free(pair); return 2;
            }
            *colon = 0;
            o.pattern = pair;
            o.file = colon + 1;
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) { free(pair); return 2; }
            rc = erdict_mode_patch_import(&f, &o);
            erdict_file_free(&f);
            free(pair);
        }
        else if (!strcmp(mode, "add-import")) {
            if (n_files == 0) { usage(); return 2; }
            if (!o.add_import_val) {
                erdict_err("--add-import=<header> is required");
                return 2;
            }
            o.pattern = o.add_import_val;
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            rc = erdict_mode_add_import(&f, &o);
            erdict_file_free(&f);
        }
        else if (!strcmp(mode, "sort-imports")) {
            if (n_files == 0) { usage(); return 2; }
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            rc = erdict_mode_sort_imports(&f, &o);
            erdict_file_free(&f);
        }
        else if (!strcmp(mode, "add-func")) {
            if (n_files == 0) { usage(); return 2; }
            o.pattern = positional;
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            rc = erdict_mode_add_func(&f, &o);
            erdict_file_free(&f);
        }
        else if (!strcmp(mode, "add-decl")) {
            if (n_files == 0) { usage(); return 2; }
            o.pattern = positional;
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            rc = erdict_mode_add_decl(&f, &o);
            erdict_file_free(&f);
        }
        else if (!strcmp(mode, "rename-func")) {
            if (n_files == 0) { usage(); return 2; }
            o.pattern = positional;
            if (o.recurse) rc = erdict_mode_rename_tree(&o);
            else {
                erdict_file_t f;
                if (erdict_file_load(files[0], &f) != 0) return 2;
                rc = erdict_mode_rename_func(&f, &o);
                erdict_file_free(&f);
            }
        }
        else if (!strcmp(mode, "patch-func")) {
            if (n_files == 0) { usage(); return 2; }
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            rc = erdict_mode_patch(&f, &o);
            erdict_file_free(&f);
        }
        else if (!strcmp(mode, "section")) {
            if (n_files == 0) { usage(); return 2; }
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            rc = erdict_mode_section(&f, &o);
            erdict_file_free(&f);
        }
        else if (!strcmp(mode, "subst")) {
            for (size_t i = 0; i < o.n_files; i++) {
                erdict_file_t f;
                if (erdict_file_load(files[i], &f) != 0) continue;
                int r = erdict_mode_subst(&f, &o);
                if (r != 0 && rc == 0) rc = r;
                erdict_file_free(&f);
            }
        }
        else if (n_files > 1) {
            erdict_err("multi-file only supported for --subst, --syntax, --check, --lint, search");
            rc = 2;
        }
        else {
            if (n_files == 0) { usage(); return 2; }
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;

            if (!strcmp(mode, "funcs")   ||
                !strcmp(mode, "structs") ||
                !strcmp(mode, "macros")  ||
                !strcmp(mode, "imports") ||
                !strcmp(mode, "globals") ||
                !strcmp(mode, "list"))
            {
                rc = erdict_mode_structure(&f, &o);
            }
            else if (!strcmp(mode, "stat"))     rc = erdict_mode_stats(&f, &o);
            else if (!strcmp(mode, "patch") ||
                     !strcmp(mode, "insert") ||
                     !strcmp(mode, "insert-after") ||
                     !strcmp(mode, "delete") ||
                     !strcmp(mode, "append") ||
                     !strcmp(mode, "prepend"))
            {
                o.range_str = positional;
                if (o.range_str && strcmp(mode, "append") && strcmp(mode, "prepend")) {
                    if (erdict_parse_range(&f, &o, &o.r_start, &o.r_end) != 0) {
                        erdict_err("bad range: %s", o.range_str);
                        erdict_file_free(&f);
                        return 2;
                    }
                }
                rc = erdict_mode_patch(&f, &o);
            }
            else {
                erdict_err("unknown mode: --%s", mode);
                rc = 2;
            }
            erdict_file_free(&f);
        }
    }
    else if (positional) {
        int is_numeric_range = (positional[0] >= '0' && positional[0] <= '9');
        int is_pattern_range = (positional[0] == '/' && strlen(positional) > 2
                                && strchr(positional, ','));

        if (is_numeric_range || is_pattern_range) {
            if (n_files == 0) { usage(); return 2; }
            erdict_file_t f;
            if (erdict_file_load(files[0], &f) != 0) return 2;
            o.range_str = positional;
            rc = erdict_mode_range(&f, &o);
            erdict_file_free(&f);
        } else {
            rc = erdict_mode_search_multi(&o);
        }
    }

    return rc;
}
