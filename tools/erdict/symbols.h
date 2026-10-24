/** symbols.h — C symbol scanner. */
#ifndef CUBE_TOOLS_ERDICT_SYMBOLS_H
#define CUBE_TOOLS_ERDICT_SYMBOLS_H
#include "erdict.h"

typedef enum {
    ERDICT_SYM_FUNC,
    ERDICT_SYM_STRUCT,
    ERDICT_SYM_MACRO,
    ERDICT_SYM_IMPORT,
    ERDICT_SYM_GLOBAL,
} erdict_sym_kind_t;

typedef struct {
    erdict_sym_kind_t kind;
    size_t          line_no;
    char           *name;    /* owned */
} erdict_sym_t;

int erdict_symbols_scan(const erdict_file_t *f, erdict_sym_t **out, size_t *out_n);

#endif
