/* flywheel/include/lexer.h
 *
 * Token types, Token struct, Lexer state, and public lexer API.
 * This is the ONLY header the parser and tests need to include.
 *
 * Design notes:
 *   - No assumption about what's "correct" JS. The lexer recognizes shapes.
 *   - Errors are values, not aborts. Every error carries line + column + message.
 *   - Every token carries the byte range in the source it came from.
 *   - Keywords, operators, punctuation are looked up in tables (data, not code).
 *   - Unicode identifiers work: any byte >= 0x80 is treated as letter-like.
 *   - Regex vs division is resolved by remembering the previous token.
 */

#ifndef FLYWHEEL_LEXER_H
#define FLYWHEEL_LEXER_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Token kinds                                                         */
/* ------------------------------------------------------------------ */
typedef enum {
    /* meta */
    TOK_EOF = 0,
    TOK_ERROR,

    /* literals */
    TOK_NUMBER,
    TOK_BIGINT,
    TOK_STRING,
    TOK_TEMPLATE_HEAD,     /* `text${   */
    TOK_TEMPLATE_MIDDLE,   /* }text${   */
    TOK_TEMPLATE_TAIL,     /* }text`    */
    TOK_TEMPLATE_NO_SUB,   /* `text`    */
    TOK_REGEX,

    /* identifiers and reserved */
    TOK_IDENT,
    TOK_KEYWORD,           /* generic keyword marker; specific via .keyword */

    /* punctuation */
    TOK_LPAREN, TOK_RPAREN,
    TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET,
    TOK_SEMICOLON, TOK_COMMA,
    TOK_DOT, TOK_ELLIPSIS,
    TOK_COLON, TOK_QUESTION,
    TOK_ARROW,             /* => */
    TOK_OPTIONAL_CHAIN,    /* ?. */

    /* assignment operators */
    TOK_EQ,                /* =  */
    TOK_PLUS_EQ, TOK_MINUS_EQ, TOK_STAR_EQ, TOK_SLASH_EQ, TOK_PERCENT_EQ,
    TOK_POW_EQ,            /* **= */
    TOK_LSHIFT_EQ, TOK_RSHIFT_EQ, TOK_URSHIFT_EQ,
    TOK_AMP_EQ, TOK_PIPE_EQ, TOK_CARET_EQ,
    TOK_AND_AND_EQ, TOK_OR_OR_EQ, TOK_NULLISH_EQ, /* &&= ||= ??= */

    /* arithmetic */
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT, TOK_POW,
    TOK_PLUS_PLUS, TOK_MINUS_MINUS,

    /* bitwise */
    TOK_AMP, TOK_PIPE, TOK_CARET, TOK_TILDE,
    TOK_LSHIFT, TOK_RSHIFT, TOK_URSHIFT,

    /* comparison */
    TOK_EQEQ, TOK_NEQ,             /* ==  !=  */
    TOK_STRICT_EQ, TOK_STRICT_NEQ, /* === !== */
    TOK_LT, TOK_GT, TOK_LE, TOK_GE,

    /* logical */
    TOK_AND_AND, TOK_OR_OR, TOK_BANG, TOK_NULLISH, /* ?? */

} TokKind;

/* Which keyword this token is, when kind == TOK_KEYWORD. */
typedef enum {
    KW_NONE = 0,
    KW_VAR, KW_LET, KW_CONST,
    KW_FUNCTION, KW_RETURN,
    KW_IF, KW_ELSE,
    KW_FOR, KW_WHILE, KW_DO,
    KW_BREAK, KW_CONTINUE,
    KW_SWITCH, KW_CASE, KW_DEFAULT,
    KW_TRY, KW_CATCH, KW_FINALLY, KW_THROW,
    KW_NEW, KW_DELETE, KW_TYPEOF, KW_INSTANCEOF, KW_IN, KW_VOID,
    KW_THIS, KW_SUPER,
    KW_NULL, KW_TRUE, KW_FALSE, KW_UNDEFINED,
    KW_CLASS, KW_EXTENDS, KW_STATIC, KW_GET, KW_SET,
    KW_IMPORT, KW_EXPORT, KW_FROM, KW_AS,
    KW_ASYNC, KW_AWAIT, KW_YIELD,
    KW_OF,
    KW_DEBUGGER, KW_WITH,
} KeywordKind;

/* ------------------------------------------------------------------ */
/* Token                                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    TokKind  kind;
    KeywordKind keyword;   /* valid iff kind == TOK_KEYWORD */
    const char *start;     /* pointer into source (not NUL-terminated) */
    int      length;       /* byte length of the token text */
    int      line;         /* 1-based */
    int      column;       /* 1-based */
    double   number;       /* valid iff kind == TOK_NUMBER */
    int      preceded_by_newline;   /* 1 if whitespace before this token
                                       contained a line terminator */
} Token;

/* ------------------------------------------------------------------ */
/* Lexer                                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *source;    /* whole input, NUL-terminated by caller */
    const char *current;   /* cursor */
    int         line;
    int         column;

    /* previous significant token — needed for regex/div disambiguation */
    TokKind     prev_kind;

    /* proper template state — stack of open backtick templates */
    int         template_depth;         /* how many backtick templates are open */
    int         template_in_sub[32];    /* per-level: 1 if inside ${...} of that template */
    int         expect_template_segment;/* transient — set right after a } that closes a sub */

    /* error state — lexer never aborts, records and continues */
    int         has_error;
    char        error_msg[256];
    int         error_line;
    int         error_column;
} Lexer;

/* ------------------------------------------------------------------ */
/* API                                                                */
/* ------------------------------------------------------------------ */

/* Initialize lexer over a source string. */
void  lexer_init(Lexer *lx, const char *source);

/* Produce the next token. Always succeeds (may return TOK_ERROR). */
Token lexer_next(Lexer *lx);

/* Lex the entire source into a malloc'd array. Caller frees with free().
 * *out_count is set to the number of tokens (INCLUDING the final EOF).
 * On error, tokens up to and including the error token are returned,
 * and the array ends with an EOF token so callers can stop cleanly. */
Token *lexer_all(Lexer *lx, int *out_count);

/* Human-readable token name — used by tests and error messages. */
const char *token_kind_name(TokKind k);

/* Keyword lookup: returns KW_NONE if not a keyword. */
KeywordKind keyword_lookup(const char *word, int length);

#endif /* FLYWHEEL_LEXER_H */
