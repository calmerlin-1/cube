/** main.c — arg parse + dispatch. */

#include "sear.h"
#include "symbols.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* implemented in each mode file */
int sear_mode_search   (const sear_file_t *f, const sear_opts_t *o);
int sear_mode_range    (const sear_file_t *f, const sear_opts_t *o);
int sear_mode_structure(const sear_file_t *f, const sear_opts_t *o);
int sear_mode_syntax   (const sear_file_t *f, const sear_opts_t *o);
int sear_mode_stats    (const sear_file_t *f, const sear_opts_t *o);
int sear_mode_patch    (const sear_file_t *f, const sear_opts_t *o);
int sear_parse_range   (const sear_file_t *f, const sear_opts_t *o,
                        size_t *s, size_t *e);

static void usage(void) {
    fputs(
"usage: sear <file> <cmd> [args]\n"
"\n"
"search:\n"
"  sear <file> <text>            substring search\n"
"  sear <file> /regex/           regex search\n"
"  sear <file> <text> --icase    case-insensitive\n"
"  sear <file> <text> --brief    one line per match\n"
"  sear <file> <text> --count    count only\n"
"  sear <file> <text> --json     JSON output\n"
"\n"
"range:\n"
"  sear <file> 10,20             print lines 10-20\n"
"  sear <file> 10+5              lines 10-15\n"
"  sear <file> /s/,/e/           between two pattern matches\n"
"\n"
"structure:\n"
"  sear <file> --funcs [pat]     function definitions\n"
"  sear <file> --structs         struct/enum/union/typedef\n"
"  sear <file> --macros          #define entries\n"
"  sear <file> --imports         #include lines\n"
"  sear <file> --globals         file-scope variables\n"
"  sear <file> --list            everything above\n"
"\n"
"analysis:\n"
"  sear <file> --syntax          brace/paren/comment/string check\n"
"  sear <file> --stat            file summary\n"
"\n"
"patch (dry-run by default; --apply to write):\n"
"  sear <file> <start>,<end> --patch         replace range (stdin)\n"
"  sear <file> <start>       --insert        insert before line (stdin)\n"
"  sear <file> <start>       --insert-after  insert after line (stdin)\n"
"  sear <file> <start>,<end> --delete        delete range\n"
"  sear <file>               --append        append to end (stdin)\n"
"  sear <file>               --prepend       prepend to start (stdin)\n"
"\n"
"common:\n"
"  --apply          commit changes (patch modes)\n"
"  --no-color       disable color\n"
"  --quiet          suppress summary\n"
"  --help           this message\n"
        , stderr);
}

/* Recognized mode flags. */
static const char *MODE_FLAGS[] = {
    "--funcs", "--structs", "--macros", "--imports", "--globals", "--list",
    "--syntax", "--stat",
    "--patch", "--insert", "--insert-after", "--delete", "--append", "--prepend",
    "--subst", "--section",
    NULL
};

int main(int argc, char **argv) {
    sear_opts_t o;
    memset(&o, 0, sizeof(o));
    o.color = 1;
    o.hints = 1;

    if (argc < 2) { usage(); return 2; }

    /* Collect files + one positional + one mode flag. */
    const char *files[256];
    size_t n_files = 0;
    const char *positional = NULL;
    const char *mode = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        else if (!strcmp(a, "--apply"))     o.apply = 1;
        else if (!strcmp(a, "--no-color"))  o.color = 0;
        else if (!strcmp(a, "--brief"))     o.brief = 1;
        else if (!strcmp(a, "--count"))     o.count_only = 1;
        else if (!strcmp(a, "--json"))      o.json = 1;
        else if (!strcmp(a, "--icase"))     o.icase = 1;
        else if (!strcmp(a, "--quiet"))     o.quiet = 1;
        else if (!strcmp(a, "-r"))          o.recurse = 1;
        else if (a[0] == '-' && a[1] == '-') {
            int known = 0;
            for (int k = 0; MODE_FLAGS[k]; k++)
                if (!strcmp(a, MODE_FLAGS[k])) { known = 1; mode = a + 2; break; }
            if (!known) { fprintf(stderr, "sear: unknown option %s\n", a); return 2; }
        } else if (!positional) {
            /* ambiguous: could be a file or the pattern.
             * If it looks like a file (exists, or has known suffix, or is a dir)
             * and we haven't seen a pattern yet, treat as file. */
            int looks_like_file =
                sear_endswith(a, ".c") ||
                sear_endswith(a, ".h") ||
                (a[0] != '/' && a[0] != '-' && strchr(a, '.') != NULL);
            /* if it's the last arg and no other files, treat as pattern */
            if (looks_like_file && (mode != NULL || n_files > 0 || i + 1 < argc)) {

                if (n_files < 256) files[n_files++] = a;
                continue;
            }
            positional = a;
        } else if (n_files < 256) {
            files[n_files++] = a;
        }
    }

    if (n_files == 0 && !positional) { usage(); return 2; }
    if (n_files == 0 && !mode) { usage(); return 2; }

    sear_colors_set(o.color, isatty(1));
    o.files = files;
    o.n_files = n_files;
    o.mode = mode;
    o.pattern = positional;
    o.file = n_files ? files[0] : NULL;

    int rc = 0;

    /* Multi-file paths: -r, or 2+ files on cmdline. */
    int multi = (o.recurse || n_files > 1);

    if (mode) {
        if (!strcmp(mode, "section")) {
            /* single file required */
            if (n_files == 0) { usage(); return 2; }
            sear_file_t f;
            if (sear_file_load(files[0], &f) != 0) return 2;
            rc = sear_mode_section(&f, &o);
            sear_file_free(&f);
        }
        else if (!strcmp(mode, "subst")) {
            /* multi-file allowed */
            for (size_t i = 0; i < o.n_files; i++) {
                sear_file_t f;
                if (sear_file_load(files[i], &f) != 0) continue;
                int r = sear_mode_subst(&f, &o);
                if (r != 0 && rc == 0) rc = r;
                sear_file_free(&f);
            }
        }
        else if (multi) {
            sear_err("multi-file only supported for --subst and search");
            rc = 2;
        }
        else {
            /* single-file modes: structure, syntax, stat, patch modes */
            if (n_files == 0) { usage(); return 2; }
            sear_file_t f;
            if (sear_file_load(files[0], &f) != 0) return 2;

            if (!strcmp(mode, "funcs")   ||
                !strcmp(mode, "structs") ||
                !strcmp(mode, "macros")  ||
                !strcmp(mode, "imports") ||
                !strcmp(mode, "globals") ||
                !strcmp(mode, "list"))
            {
                rc = sear_mode_structure(&f, &o);
            }
            else if (!strcmp(mode, "syntax"))   rc = sear_mode_syntax(&f, &o);
            else if (!strcmp(mode, "stat"))     rc = sear_mode_stats(&f, &o);
            else if (!strcmp(mode, "patch") ||
                     !strcmp(mode, "insert") ||
                     !strcmp(mode, "insert-after") ||
                     !strcmp(mode, "delete") ||
                     !strcmp(mode, "append") ||
                     !strcmp(mode, "prepend"))
            {
                o.range_str = positional;
                if (o.range_str && strcmp(mode, "append") && strcmp(mode, "prepend")) {
                    if (sear_parse_range(&f, &o, &o.r_start, &o.r_end) != 0) {
                        sear_err("bad range: %s", o.range_str);
                        sear_file_free(&f);
                        return 2;
                    }
                }
                rc = sear_mode_patch(&f, &o);
            }
            else {
                sear_err("unknown mode: --%s", mode);
                rc = 2;
            }
            sear_file_free(&f);
        }
    }
    else if (positional) {
        /* range vs search */
        int looks_like_range =
            (positional[0] >= '0' && positional[0] <= '9') ||
            (positional[0] == '/' && strlen(positional) > 1 &&
             (strchr(positional, ',') || strlen(positional) > 2));

        if (looks_like_range && positional[0] >= '0' && positional[0] <= '9') {
            if (n_files == 0) { usage(); return 2; }
            sear_file_t f;
            if (sear_file_load(files[0], &f) != 0) return 2;
            o.range_str = positional;
            rc = sear_mode_range(&f, &o);
            sear_file_free(&f);
        } else {
            rc = sear_mode_search_multi(&o);
        }
    }

    return rc;
}
