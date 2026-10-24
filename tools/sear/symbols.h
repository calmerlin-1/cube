/** symbols.h — C symbol scanner. */
#ifndef CUBE_TOOLS_SEAR_SYMBOLS_H
#define CUBE_TOOLS_SEAR_SYMBOLS_H
#include "sear.h"

typedef enum {
    SEAR_SYM_FUNC,
    SEAR_SYM_STRUCT,
    SEAR_SYM_MACRO,
    SEAR_SYM_IMPORT,
    SEAR_SYM_GLOBAL,
} sear_sym_kind_t;

typedef struct {
    sear_sym_kind_t kind;
    size_t          line_no;
    char           *name;    /* owned */
} sear_sym_t;

int sear_symbols_scan(const sear_file_t *f, sear_sym_t **out, size_t *out_n);

#endif
