/* flywheel/src/lexer.c
 *
 * A JavaScript lexer. No dependencies beyond libc.
 * Compile standalone:   clang -DLEXER_TEST src/lexer.c -o build/test_lexer
 * Run:                  ./build/test_lexer 'var x = 10'
 */

#include "../include/lexer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ================================================================== */
/* Keyword table — data, not code. Add one line to add a keyword.     */
/* ================================================================== */
typedef struct { const char *word; KeywordKind kw; } KwEntry;

static const KwEntry KEYWORDS[] = {
    {"var", KW_VAR}, {"let", KW_LET}, {"const", KW_CONST},
    {"function", KW_FUNCTION}, {"return", KW_RETURN},
    {"if", KW_IF}, {"else", KW_ELSE},
    {"for", KW_FOR}, {"while", KW_WHILE}, {"do", KW_DO},
    {"break", KW_BREAK}, {"continue", KW_CONTINUE},
    {"switch", KW_SWITCH}, {"case", KW_CASE}, {"default", KW_DEFAULT},
    {"try", KW_TRY}, {"catch", KW_CATCH}, {"finally", KW_FINALLY},
    {"throw", KW_THROW},
    {"new", KW_NEW}, {"delete", KW_DELETE}, {"typeof", KW_TYPEOF},
    {"instanceof", KW_INSTANCEOF}, {"in", KW_IN}, {"void", KW_VOID},
    {"this", KW_THIS}, {"super", KW_SUPER},
    {"null", KW_NULL}, {"true", KW_TRUE}, {"false", KW_FALSE},
    {"undefined", KW_UNDEFINED},
    {"class", KW_CLASS}, {"extends", KW_EXTENDS}, {"static", KW_STATIC},
    {"get", KW_GET}, {"set", KW_SET},
    {"import", KW_IMPORT}, {"export", KW_EXPORT},
    {"from", KW_FROM}, {"as", KW_AS},
    {"async", KW_ASYNC}, {"await", KW_AWAIT}, {"yield", KW_YIELD},
    {"of", KW_OF},
    {"debugger", KW_DEBUGGER}, {"with", KW_WITH},
    {NULL, KW_NONE}
};

KeywordKind keyword_lookup(const char *word, int length) {
    for (int i = 0; KEYWORDS[i].word; i++) {
        if ((int)strlen(KEYWORDS[i].word) == length &&
            strncmp(KEYWORDS[i].word, word, length) == 0) {
            return KEYWORDS[i].kw;
        }
    }
    return KW_NONE;
}

/* ================================================================== */
/* Character classification                                           */
/* ================================================================== */
static int is_ident_start(unsigned char c) {
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           c == '_' || c == '$' ||
           c >= 0x80;   /* UTF-8 lead byte: treat as letter-like */
}

static int is_ident_continue(unsigned char c) {
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

static int is_dec(unsigned char c)   { return c >= '0' && c <= '9'; }
static int is_hex(unsigned char c)   {
    return is_dec(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int is_oct(unsigned char c)   { return c >= '0' && c <= '7'; }
static int is_bin(unsigned char c)   { return c == '0' || c == '1'; }

/* ================================================================== */
/* Lexer core                                                         */
/* ================================================================== */
void lexer_init(Lexer *lx, const char *source) {
    lx->source      = source;
    lx->current     = source;
    lx->line        = 1;
    lx->column      = 1;
    lx->prev_kind   = TOK_EOF;
    lx->template_depth = 0;
    lx->expect_template_segment = 0;
    for (int _i = 0; _i < 32; _i++) lx->template_in_sub[_i] = 0;
    lx->has_error   = 0;
    lx->error_msg[0] = '\0';
    lx->error_line  = 0;
    lx->error_column= 0;
}

static void set_error(Lexer *lx, const char *msg) {
    if (!lx->has_error) {
        lx->has_error = 1;
        strncpy(lx->error_msg, msg, sizeof(lx->error_msg) - 1);
        lx->error_line = lx->line;
        lx->error_column = lx->column;
    }
}

static unsigned char peek(Lexer *lx)  { return (unsigned char)*lx->current; }
static unsigned char peek2(Lexer *lx) {
    return lx->current[0] ? (unsigned char)lx->current[1] : 0;
}
static unsigned char peek3(Lexer *lx) {
    return lx->current[0] && lx->current[1] ? (unsigned char)lx->current[2] : 0;
}
static unsigned char peek4(Lexer *lx) {
    return lx->current[0] && lx->current[1] && lx->current[2]
           ? (unsigned char)lx->current[3] : 0;
}

static unsigned char advance(Lexer *lx) {
    unsigned char c = (unsigned char)*lx->current;
    if (c == 0) return 0;
    lx->current++;
    if (c == '\n') { lx->line++; lx->column = 1; }
    else if (c != '\r') { lx->column++; }
    return c;
}

/* ================================================================== */
/* Whitespace + comments (with line terminator tracking for ASI)      */
/* ================================================================== */
static int skip_whitespace(Lexer *lx, int *saw_newline) {
    *saw_newline = 0;
    const char *p = lx->current;
    int newlines = 0;
    int col_delta = 0;
    for (;;) {
        unsigned char ch = (unsigned char)*p;
        if (ch == ' ' || ch == '\t' || ch == '\v' || ch == '\f') {
            p++; col_delta++;
        } else if (ch == '\r') {
            p++; col_delta = 0;
        } else if (ch == '\n') {
            *saw_newline = 1;
            newlines++;
            col_delta = 0;
            p++;
        } else if (ch == '/' && p[1] == '/') {
            /* line comment — walk to EOL, don't consume the newline */
            p += 2;
            while (*p && *p != '\n') p++;
        } else if (ch == '/' && p[1] == '*') {
            /* block comment — walk to close, count newlines inside */
            const char *start = p;
            p += 2;
            int closed = 0;
            while (*p) {
                if (*p == '\n') { *saw_newline = 1; newlines++; col_delta = 0; p++; continue; }
                if (*p == '*' && p[1] == '/') { p += 2; closed = 1; break; }
                p++;
                col_delta++;
            }
            if (!closed) {
                set_error(lx, "unterminated block comment");
            }
            (void)start;
        } else {
            break;
        }
    }
    /* flush state once */
    int consumed = (int)(p - lx->current);
    if (consumed > 0) {
        if (newlines > 0) {
            lx->line += newlines;
            lx->column = 1 + col_delta;
        } else {
            lx->column += col_delta;
        }
        lx->current = p;
    }
    return 0;
}

/* ================================================================== */
/* Number scanning (all forms)                                        */
/* ================================================================== */
static Token scan_number(Lexer *lx) {
    Token t = {0};
    t.start  = lx->current;
    t.line   = lx->line;
    t.column = lx->column;

    int is_bigint = 0;
    int is_float  = 0;

    if (peek(lx) == '0' && (peek2(lx) == 'x' || peek2(lx) == 'X')) {
        advance(lx); advance(lx);
        if (!is_hex(peek(lx))) set_error(lx, "hex literal has no digits");
        while (is_hex(peek(lx)) || peek(lx) == '_') advance(lx);
    } else if (peek(lx) == '0' && (peek2(lx) == 'o' || peek2(lx) == 'O')) {
        advance(lx); advance(lx);
        if (!is_oct(peek(lx))) set_error(lx, "octal literal has no digits");
        while (is_oct(peek(lx)) || peek(lx) == '_') advance(lx);
    } else if (peek(lx) == '0' && (peek2(lx) == 'b' || peek2(lx) == 'B')) {
        advance(lx); advance(lx);
        if (!is_bin(peek(lx))) set_error(lx, "binary literal has no digits");
        while (is_bin(peek(lx)) || peek(lx) == '_') advance(lx);
    } else {
        while (is_dec(peek(lx)) || peek(lx) == '_') advance(lx);
        if (peek(lx) == '.') {
            is_float = 1;
            advance(lx);
            while (is_dec(peek(lx)) || peek(lx) == '_') advance(lx);
        }
        if (peek(lx) == 'e' || peek(lx) == 'E') {
            is_float = 1;
            advance(lx);
            if (peek(lx) == '+' || peek(lx) == '-') advance(lx);
            if (!is_dec(peek(lx))) set_error(lx, "exponent has no digits");
            while (is_dec(peek(lx)) || peek(lx) == '_') advance(lx);
        }
    }

    if (peek(lx) == 'n' && !is_float) {
        is_bigint = 1;
        advance(lx);
    }

    t.length = (int)(lx->current - t.start);
    if (t.length == 0) { t.kind = TOK_ERROR; return t; }

    /* parse to double: strip underscores, dispatch by base */
    char buf[512];
    int n = t.length < (int)sizeof(buf) - 1 ? t.length : (int)sizeof(buf) - 1;
    int j = 0;
    for (int i = 0; i < n; i++) {
        if (t.start[i] != '_') buf[j++] = t.start[i];
    }
    buf[j] = '\0';

    double value = 0.0;
    if (j >= 2 && buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) {
        value = (double)strtoull(buf + 2, NULL, 16);
    } else if (j >= 2 && buf[0] == '0' && (buf[1] == 'o' || buf[1] == 'O')) {
        value = (double)strtoull(buf + 2, NULL, 8);
    } else if (j >= 2 && buf[0] == '0' && (buf[1] == 'b' || buf[1] == 'B')) {
        value = (double)strtoull(buf + 2, NULL, 2);
    } else {
        value = strtod(buf, NULL);
    }

    t.number = value;
    t.kind = is_bigint ? TOK_BIGINT : TOK_NUMBER;
    return t;
}

/* ================================================================== */
/* Identifier / keyword scanning                                      */
/* ================================================================== */
static Token scan_ident(Lexer *lx) {
    Token t = {0};
    t.start  = lx->current;
    t.line   = lx->line;
    t.column = lx->column;

    /* SPEED: bulk-scan ASCII identifier chars. Most tokens are short
     * (1-5 chars). The function-call overhead of advance() per char
     * adds up over a page of JS. Inline the hot loop here. */
    const char *p = lx->current;
    while (1) {
        unsigned char ch = (unsigned char)*p;
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' || ch == '$' ||
            ch >= 0x80) {
            p++;
            continue;
        }
        break;
    }
    /* flush state once — no per-character advance calls */
    lx->column += (int)(p - lx->current);
    lx->current = p;

    t.length = (int)(lx->current - t.start);
    KeywordKind kw = keyword_lookup(t.start, t.length);
    if (kw != KW_NONE) {
        t.kind = TOK_KEYWORD;
        t.keyword = kw;
    } else {
        t.kind = TOK_IDENT;
    }
    return t;
}

/* ================================================================== */
/* String scanning (single, double, template)                         */
/* ================================================================== */
static Token scan_simple_string(Lexer *lx, char quote) {
    Token t = {0};
    t.start  = lx->current;
    t.line   = lx->line;
    t.column = lx->column;

    advance(lx); /* opening quote */
    while (peek(lx) && peek(lx) != quote) {
        if (peek(lx) == '\\') {
            advance(lx);
            if (peek(lx)) advance(lx);
        } else {
            advance(lx);
        }
    }
    if (peek(lx) != quote) {
        set_error(lx, "unterminated string");
        t.kind = TOK_ERROR;
    } else {
        advance(lx); /* closing quote */
        t.kind = TOK_STRING;
    }
    t.length = (int)(lx->current - t.start);
    return t;
}

/* Template literal: `text`, `text${expr}text`, `text${expr}text${expr}...text` */
static Token scan_template(Lexer *lx, int is_continuation) {
    Token t = {0};
    t.start  = lx->current;
    t.line   = lx->line;
    t.column = lx->column;

    int opening_backtick = !is_continuation;
    if (opening_backtick) {
        /* push a new template level */
        if (lx->template_depth < 31) {
            lx->template_in_sub[lx->template_depth] = 0;
        }
        lx->template_depth++;
        advance(lx); /* consume ` */
    }

    /* we are now scanning template text of level (template_depth - 1) */
    int level = lx->template_depth - 1;
    if (level < 0) level = 0;

    /* scan forward, looking for ${ or ` */
    int saw_sub = 0, hit_end = 0;
    const char *scan = lx->current;
    while (*scan) {
        if (scan[0] == '\\') { scan++; if (scan[0]) scan++; continue; }
        if (scan[0] == '`') { hit_end = 1; break; }
        if (scan[0] == '$' && scan[1] == '{') { saw_sub = 1; break; }
        scan++;
    }

    if (saw_sub) {
        while (peek(lx) && !(peek(lx) == '$' && peek2(lx) == '{')) {
            if (peek(lx) == '\\') { advance(lx); if (peek(lx)) advance(lx); }
            else advance(lx);
        }
        advance(lx); advance(lx); /* ${ */
        t.kind = is_continuation ? TOK_TEMPLATE_MIDDLE : TOK_TEMPLATE_HEAD;
        lx->template_in_sub[level] = 1;   /* we are now inside a sub of this level */
    } else if (hit_end) {
        while (peek(lx) && peek(lx) != '`') {
            if (peek(lx) == '\\') { advance(lx); if (peek(lx)) advance(lx); }
            else advance(lx);
        }
        advance(lx); /* closing ` */
        t.kind = is_continuation ? TOK_TEMPLATE_TAIL : TOK_TEMPLATE_NO_SUB;
        /* pop this template */
        if (lx->template_depth > 0) lx->template_depth--;
        if (lx->template_depth < 32) lx->template_in_sub[lx->template_depth] = 0;
    } else {
        set_error(lx, "unterminated template literal");
        t.kind = TOK_ERROR;
    }
    t.length = (int)(lx->current - t.start);
    return t;
}

/* ================================================================== */
/* Regex scanning (called only when lexer decides it's a regex)       */
/* ================================================================== */
static Token scan_regex(Lexer *lx) {
    Token t = {0};
    t.start  = lx->current;
    t.line   = lx->line;
    t.column = lx->column;

    advance(lx); /* opening / */
    int in_class = 0;
    while (peek(lx)) {
        unsigned char c = peek(lx);
        if (c == '\\') { advance(lx); if (peek(lx)) advance(lx); continue; }
        if (c == '[') in_class = 1;
        else if (c == ']') in_class = 0;
        else if (c == '/' && !in_class) break;
        else if (c == '\n') { set_error(lx, "newline in regex"); t.kind = TOK_ERROR; return t; }
        advance(lx);
    }
    if (peek(lx) != '/') { set_error(lx, "unterminated regex"); t.kind = TOK_ERROR; return t; }
    advance(lx);
    /* flags */
    while ((peek(lx) >= 'a' && peek(lx) <= 'z') ||
           (peek(lx) >= 'A' && peek(lx) <= 'Z')) {
        advance(lx);
    }
    t.kind = TOK_REGEX;
    t.length = (int)(lx->current - t.start);
    return t;
}

/* ================================================================== */
/* Operator / punctuation dispatch (longest match wins)               */
/* ================================================================== */
static Token make_tok(Lexer *lx, TokKind k) {
    Token t = {0};
    t.kind   = k;
    t.start  = lx->current;
    t.line   = lx->line;
    t.column = lx->column;
    return t;
}

static Token scan_punct(Lexer *lx) {
    Token t = make_tok(lx, TOK_ERROR);
    unsigned char c1 = peek(lx), c2 = peek2(lx), c3 = peek3(lx), c4 = peek4(lx);

    #define MK(K, N) do { t.kind = (K); for (int _i = 0; _i < (N); _i++) advance(lx); t.length = (int)(lx->current - t.start); return t; } while (0)

    /* four-char first */
    if (c1=='?') {
        if (c2=='.' && c3=='?' && c4=='=') MK(TOK_NULLISH_EQ, 4);  /* ??? */
    }
    if (c1=='>') {
        if (c2=='>' && c3=='>' && c4=='=') MK(TOK_URSHIFT_EQ, 4);
        if (c2=='>' && c3=='>' && c4=='=') MK(TOK_RSHIFT_EQ, 4);
    }

    /* three-char */
    if (c1=='=' && c2=='=' && c3=='=') MK(TOK_STRICT_EQ, 3);
    if (c1=='!' && c2=='=' && c3=='=') MK(TOK_STRICT_NEQ, 3);
    if (c1=='.' && c2=='.' && c3=='.') MK(TOK_ELLIPSIS, 3);
    if (c1=='*' && c2=='*' && c3=='=') MK(TOK_POW_EQ, 3);
    if (c1=='<' && c2=='<' && c3=='=') MK(TOK_LSHIFT_EQ, 3);
    if (c1=='&' && c2=='&' && c3=='=') MK(TOK_AND_AND_EQ, 3);
    if (c1=='|' && c2=='|' && c3=='=') MK(TOK_OR_OR_EQ, 3);
    if (c1=='?' && c2=='?' && c3=='=') MK(TOK_NULLISH_EQ, 3);

    /* >>> and >>>= must come before >> and >>= */
    if (c1=='>' && c2=='>' && c3=='>' && peek4(lx)=='=') MK(TOK_URSHIFT_EQ, 4);
    if (c1=='>' && c2=='>' && c3=='>') MK(TOK_URSHIFT, 3);

    /* two-char */
    if (c1=='=' && c2=='>')           MK(TOK_ARROW, 2);
    if (c1=='=' && c2=='=')           MK(TOK_EQEQ, 2);
    if (c1=='!' && c2=='=')           MK(TOK_NEQ, 2);
    if (c1=='+' && c2=='+')           MK(TOK_PLUS_PLUS, 2);
    if (c1=='-' && c2=='-')           MK(TOK_MINUS_MINUS, 2);
    if (c1=='+' && c2=='=')           MK(TOK_PLUS_EQ, 2);
    if (c1=='-' && c2=='=')           MK(TOK_MINUS_EQ, 2);
    if (c1=='*' && c2=='=')           MK(TOK_STAR_EQ, 2);
    if (c1=='/' && c2=='=')           MK(TOK_SLASH_EQ, 2);
    if (c1=='%' && c2=='=')           MK(TOK_PERCENT_EQ, 2);
    if (c1=='*' && c2=='*')           MK(TOK_POW, 2);
    if (c1=='&' && c2=='&')           MK(TOK_AND_AND, 2);
    if (c1=='|' && c2=='|')           MK(TOK_OR_OR, 2);
    if (c1=='?' && c2=='?')           MK(TOK_NULLISH, 2);
    if (c1=='?' && c2=='.')           MK(TOK_OPTIONAL_CHAIN, 2);
    if (c1=='<' && c2=='<')           MK(TOK_LSHIFT, 2);
    if (c1=='>' && c2=='>')           MK(TOK_RSHIFT, 2);
    if (c1=='<' && c2=='=')           MK(TOK_LE, 2);
    if (c1=='>' && c2=='=')           MK(TOK_GE, 2);
    if (c1=='&' && c2=='=')           MK(TOK_AMP_EQ, 2);
    if (c1=='|' && c2=='=')           MK(TOK_PIPE_EQ, 2);
    if (c1=='^' && c2=='=')           MK(TOK_CARET_EQ, 2);

    /* one-char */
    switch (c1) {
        case '(': MK(TOK_LPAREN, 1);
        case ')': MK(TOK_RPAREN, 1);
        case '{': MK(TOK_LBRACE, 1);
        case '}': MK(TOK_RBRACE, 1);
        case '[': MK(TOK_LBRACKET, 1);
        case ']': MK(TOK_RBRACKET, 1);
        case ';': MK(TOK_SEMICOLON, 1);
        case ',': MK(TOK_COMMA, 1);
        case '.': MK(TOK_DOT, 1);
        case ':': MK(TOK_COLON, 1);
        case '?': MK(TOK_QUESTION, 1);
        case '=': MK(TOK_EQ, 1);
        case '/': MK(TOK_SLASH, 1);
        case '+': MK(TOK_PLUS, 1);
        case '-': MK(TOK_MINUS, 1);
        case '*': MK(TOK_STAR, 1);
        case '%': MK(TOK_PERCENT, 1);
        case '&': MK(TOK_AMP, 1);
        case '|': MK(TOK_PIPE, 1);
        case '^': MK(TOK_CARET, 1);
        case '~': MK(TOK_TILDE, 1);
        case '<': MK(TOK_LT, 1);
        case '>': MK(TOK_GT, 1);
        case '!': MK(TOK_BANG, 1);
        default: {
            set_error(lx, "unexpected character");
            t.kind = TOK_ERROR;
            t.length = 1;
            advance(lx);
            return t;
        }
    }
    #undef MK
}

/* ================================================================== */
/* Main dispatch                                                      */
/* ================================================================== */
static int prev_is_value(TokKind k) {
    switch (k) {
        case TOK_IDENT:
        case TOK_NUMBER: case TOK_BIGINT:
        case TOK_STRING: case TOK_TEMPLATE_NO_SUB: case TOK_TEMPLATE_TAIL:
        case TOK_REGEX:
        case TOK_RPAREN: case TOK_RBRACKET: case TOK_RBRACE:
            return 1;
        default:
            return 0;
    }
}

Token lexer_next(Lexer *lx) {
    Token t = {0};
    t.line = lx->line;
    t.column = lx->column;

    /* inside a template, right after we closed a ${...} substitution */
    if (lx->expect_template_segment) {
        lx->expect_template_segment = 0;
        t = scan_template(lx, 1);
        t.preceded_by_newline = 0;
        if (t.kind != TOK_ERROR) lx->prev_kind = t.kind;
        return t;
    }

    int saw_newline = 0;
    skip_whitespace(lx, &saw_newline);

    t.line = lx->line;
    t.column = lx->column;
    t.preceded_by_newline = saw_newline;

    unsigned char c = peek(lx);
    if (c == 0) { t.kind = TOK_EOF; t.start = lx->current; t.length = 0; return t; }

    if (is_dec(c) || (c == '.' && is_dec(peek2(lx)))) {
        t = scan_number(lx);
    } else if (c == '"' || c == '\'') {
        t = scan_simple_string(lx, (char)c);
    } else if (c == '`') {
        /* new backtick — always a fresh template (nested if inside sub) */
        t = scan_template(lx, 0);
    } else if (is_ident_start(c)) {
        t = scan_ident(lx);
    } else if (c == '/' && !prev_is_value(lx->prev_kind)) {
        t = scan_regex(lx);
    } else {
        /* if we just closed a ${ substitution, the next text is template */
        if (c == '}' && lx->template_depth > 0) {
            int lv = lx->template_depth - 1;
            if (lv >= 0 && lv < 32 && lx->template_in_sub[lv]) {
                /* this } closes the ${...} at this level */
                t = scan_punct(lx);
                lx->template_in_sub[lv] = 0;
                lx->expect_template_segment = 1;
                return t;
            }
        }
        /* if prev token was } AND template_depth indicates we're still in template,
           next we expect either ` (tail) or text followed by ${ (middle).
           But we already consumed the }, so we need to know we're "after sub". */
        t = scan_punct(lx);
    }

    /* update prev for the next iteration (but don't track TOK_ERROR) */
    if (t.kind != TOK_ERROR) {
        lx->prev_kind = t.kind;
    }
    return t;
}

Token *lexer_all(Lexer *lx, int *out_count) {
    /* Adaptive: start tiny (16 tokens), grow on demand. Small snippets
     * use almost no memory; large ones grow to fit. */
    int cap = 16, n = 0;
    Token *arr = (Token*)malloc(sizeof(Token) * cap);
    if (!arr) { *out_count = 0; return NULL; }

    for (;;) {
        if (n >= cap) {
            cap *= 2;
            Token *big = (Token*)realloc(arr, sizeof(Token) * cap);
            if (!big) { free(arr); *out_count = 0; return NULL; }
            arr = big;
        }
        Token t = lexer_next(lx);
        arr[n++] = t;
        if (t.kind == TOK_EOF || t.kind == TOK_ERROR) {
            /* guarantee final EOF */
            if (t.kind == TOK_ERROR) {
                if (n >= cap) { cap *= 2; arr = (Token*)realloc(arr, sizeof(Token) * cap); }
                Token eof = {0}; eof.kind = TOK_EOF;
                eof.start = lx->current; eof.line = lx->line; eof.column = lx->column;
                arr[n++] = eof;
            }
            break;
        }
    }
    *out_count = n;
    return arr;
}

/* ================================================================== */
/* Names for tests                                                    */
/* ================================================================== */
const char *token_kind_name(TokKind k) {
    switch (k) {
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_NUMBER: return "NUMBER";
        case TOK_BIGINT: return "BIGINT";
        case TOK_STRING: return "STRING";
        case TOK_TEMPLATE_HEAD: return "TEMPLATE_HEAD";
        case TOK_TEMPLATE_MIDDLE: return "TEMPLATE_MIDDLE";
        case TOK_TEMPLATE_TAIL: return "TEMPLATE_TAIL";
        case TOK_TEMPLATE_NO_SUB: return "TEMPLATE_NO_SUB";
        case TOK_REGEX: return "REGEX";
        case TOK_IDENT: return "IDENT";
        case TOK_KEYWORD: return "KEYWORD";
        case TOK_LPAREN: return "LPAREN";
        case TOK_RPAREN: return "RPAREN";
        case TOK_LBRACE: return "LBRACE";
        case TOK_RBRACE: return "RBRACE";
        case TOK_LBRACKET: return "LBRACKET";
        case TOK_RBRACKET: return "RBRACKET";
        case TOK_SEMICOLON: return "SEMICOLON";
        case TOK_COMMA: return "COMMA";
        case TOK_DOT: return "DOT";
        case TOK_ELLIPSIS: return "ELLIPSIS";
        case TOK_COLON: return "COLON";
        case TOK_QUESTION: return "QUESTION";
        case TOK_ARROW: return "ARROW";
        case TOK_OPTIONAL_CHAIN: return "OPTIONAL_CHAIN";
        case TOK_EQ: return "EQ";
        case TOK_PLUS_EQ: return "PLUS_EQ";
        case TOK_MINUS_EQ: return "MINUS_EQ";
        case TOK_STAR_EQ: return "STAR_EQ";
        case TOK_SLASH_EQ: return "SLASH_EQ";
        case TOK_PERCENT_EQ: return "PERCENT_EQ";
        case TOK_POW_EQ: return "POW_EQ";
        case TOK_LSHIFT_EQ: return "LSHIFT_EQ";
        case TOK_RSHIFT_EQ: return "RSHIFT_EQ";
        case TOK_URSHIFT_EQ: return "URSHIFT_EQ";
        case TOK_AMP_EQ: return "AMP_EQ";
        case TOK_PIPE_EQ: return "PIPE_EQ";
        case TOK_CARET_EQ: return "CARET_EQ";
        case TOK_AND_AND_EQ: return "AND_AND_EQ";
        case TOK_OR_OR_EQ: return "OR_OR_EQ";
        case TOK_NULLISH_EQ: return "NULLISH_EQ";
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_POW: return "POW";
        case TOK_PLUS_PLUS: return "PLUS_PLUS";
        case TOK_MINUS_MINUS: return "MINUS_MINUS";
        case TOK_AMP: return "AMP";
        case TOK_PIPE: return "PIPE";
        case TOK_CARET: return "CARET";
        case TOK_TILDE: return "TILDE";
        case TOK_LSHIFT: return "LSHIFT";
        case TOK_RSHIFT: return "RSHIFT";
        case TOK_URSHIFT: return "URSHIFT";
        case TOK_EQEQ: return "EQEQ";
        case TOK_NEQ: return "NEQ";
        case TOK_STRICT_EQ: return "STRICT_EQ";
        case TOK_STRICT_NEQ: return "STRICT_NEQ";
        case TOK_LT: return "LT";
        case TOK_GT: return "GT";
        case TOK_LE: return "LE";
        case TOK_GE: return "GE";
        case TOK_AND_AND: return "AND_AND";
        case TOK_OR_OR: return "OR_OR";
        case TOK_BANG: return "BANG";
        case TOK_NULLISH: return "NULLISH";
    }
    return "?";
}

/* ================================================================== */
/* Standalone test                                                    */
/* ================================================================== */
#ifdef LEXER_TEST
static void print_token(const Token *t) {
    printf("%-16s line=%d col=%-3d len=%-3d text=\"%.*s\"",
           token_kind_name(t->kind), t->line, t->column, t->length,
           t->length, t->start ? t->start : "");
    if (t->kind == TOK_NUMBER) printf(" value=%g", t->number);
    if (t->kind == TOK_KEYWORD) printf(" kw=%d", t->keyword);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s 'source code'\n", argv[0]);
        return 1;
    }
    const char *src = argv[1];
    printf("SOURCE: %s\n\n", src);

    Lexer lx;
    lexer_init(&lx, src);
    int n = 0;
    Token *toks = lexer_all(&lx, &n);
    for (int i = 0; i < n; i++) print_token(&toks[i]);
    if (lx.has_error) {
        printf("\nERROR at line %d col %d: %s\n",
               lx.error_line, lx.error_column, lx.error_msg);
    }
    free(toks);
    return lx.has_error ? 2 : 0;
}
#endif
