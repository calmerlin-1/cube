/* flywheel/include/parser.h
 *
 * Parser API. Input: JavaScript source text. Output: AST + error list.
 *
 * Philosophy:
 *   - Never crashes. Every failure is recorded as a ParseError with position.
 *   - Collects ALL errors in one pass, not just the first.
 *   - Returns a partial AST even on errors, so the caller can inspect what parsed.
 *   - Parser never touches stdout, never calls exit(), never aborts.
 *
 * Usage:
 *   ParseResult r = parser_parse("var x = 1;", "<input>");
 *   if (r.nerrors == 0) { ...use r.program... }
 *   else { for each error, print code + line + col + msg }
 *   parser_free_result(&r);
 */

#ifndef FLYWHEEL_PARSER_H
#define FLYWHEEL_PARSER_H

#include "lexer.h"
#include "ast.h"

/* ------------------------------------------------------------------ */
/* Error codes                                                        */
/* ------------------------------------------------------------------ */
typedef enum {
    PARSE_OK = 0,

    /* lexer-surfaced */
    PARSE_ERR_LEXER,
    PARSE_ERR_UNEXPECTED_TOKEN,
    PARSE_ERR_EXPECTED_TOKEN,
    PARSE_ERR_UNEXPECTED_EOF,

    /* expression errors */
    PARSE_ERR_INVALID_ASSIGNMENT,
    PARSE_ERR_INVALID_ARROW,
    PARSE_ERR_INVALID_SPREAD,
    PARSE_ERR_INVALID_TERNARY,
    PARSE_ERR_INVALID_TAGGED_TEMPLATE,

    /* statement errors */
    PARSE_ERR_INVALID_DECLARATION,
    PARSE_ERR_INVALID_STATEMENT,
    PARSE_ERR_INVALID_FOR,
    PARSE_ERR_INVALID_RETURN,
    PARSE_ERR_INVALID_BREAK,
    PARSE_ERR_INVALID_CONTINUE,
    PARSE_ERR_INVALID_THROW,
    PARSE_ERR_INVALID_TRY,

    /* function / class */
    PARSE_ERR_INVALID_PARAMS,
    PARSE_ERR_DUPLICATE_PARAM,
    PARSE_ERR_DUPLICATE_PROTO,
    PARSE_ERR_INVALID_CLASS,
    PARSE_ERR_INVALID_METHOD,
    PARSE_ERR_CTOR_CANNOT_BE_ASYNC,
    PARSE_ERR_CTOR_CANNOT_BE_GEN,

    /* patterns */
    PARSE_ERR_INVALID_DESTRUCTURING,
    PARSE_ERR_REST_MUST_BE_LAST,
    PARSE_ERR_REST_CANNOT_HAVE_DEFAULT,
    PARSE_ERR_INVALID_PATTERN,

    /* modules */
    PARSE_ERR_INVALID_MODULE,
    PARSE_ERR_IMPORT_IN_SCRIPT,

    /* reserved / strict */
    PARSE_ERR_RESERVED_WORD,
    PARSE_ERR_STRICT_VIOLATION,

    /* limits */
    PARSE_ERR_TOO_MANY_ERRORS,
    PARSE_ERR_INTERNAL
} ParseErrorCode;

/* ------------------------------------------------------------------ */
/* One error                                                          */
/* ------------------------------------------------------------------ */
typedef struct {
    ParseErrorCode code;
    const char    *msg;         /* static string, do not free */
    int            line;        /* 1-based */
    int            column;      /* 1-based */
    const char    *filename;    /* borrowed from parser_parse argument */
} ParseError;

/* ------------------------------------------------------------------ */
/* Result                                                             */
/* ------------------------------------------------------------------ */
typedef struct {
    Node       *program;        /* NODE_PROGRAM, or NULL on catastrophic failure */
    ParseError *errors;         /* malloc'd array of errors */
    int         nerrors;        /* number of errors recorded */
    int         capacity;       /* internal — do not touch */
    int         fatal;          /* 1 if too many errors — parsing stopped */
    int         owns_arena;     /* 1 = caller must call ast_free_arena();
                                   0 = arena owned by cache, do not free */
} ParseResult;

/* ------------------------------------------------------------------ */
/* API                                                                */
/* ------------------------------------------------------------------ */

/* Parse `source` as an ECMAScript Script (not Module).
 * `filename` is used only for error messages — may be NULL.
 * Always returns a result; never crashes; never exits. */
ParseResult parser_parse(const char *source, const char *filename);
ParseResult parser_parse_nocache(const char *source, const char *filename);

/* Internal — used by src/cache.c. Does not consult or populate the cache. */
ParseResult parser_parse_uncached(const char *source, const char *filename);
ParseResult parser_parse_no_swap(const char *source, const char *filename);
ParseResult parser_parse_module_no_swap(const char *source, const char *filename);
ParseResult parser_parse_module_uncached(const char *source, const char *filename);

/* Same, but parse as a Module (import/export allowed, top-level await allowed). */
ParseResult parser_parse_module(const char *source, const char *filename);

/* Free everything in a ParseResult. Safe to call twice on the same struct. */
void parser_free_result(ParseResult *r);

/* Human-readable name for an error code (for tests, logging, etc). */
const char *parser_error_code_name(ParseErrorCode c);

/* Number of errors in the result. */
int parser_error_count(const ParseResult *r);

/* Convenience: print all errors to stdout, one per line, with position. */
void parser_print_errors(const ParseResult *r);

#endif /* FLYWHEEL_PARSER_H */
