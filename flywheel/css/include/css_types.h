/** css_types.h — CSS AST. Zero-copy slices into source. Arena allocated. */

#ifndef FLYWHEEL_CSS_TYPES_H
#define FLYWHEEL_CSS_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* ---- Token kinds ---- */
typedef enum {
    CSST_EOF = 0,
    CSST_IDENT,          /* "color", "div" */
    CSST_FUNCTION,       /* "rgb(" — paren NOT consumed */
    CSST_AT_KEYWORD,     /* "@media" — "@" consumed, name included */
    CSST_HASH,           /* "#id" — "#" consumed */
    CSST_STRING,         /* "..." or '...' — content only, no quotes */
    CSST_BAD_STRING,
    CSST_URL,            /* url(...) — content only */
    CSST_NUMBER,         /* "42", "3.14" */
    CSST_PERCENTAGE,     /* "42%" — number part only */
    CSST_DIMENSION,      /* "42px" — value in .number, unit in .unit */
    CSST_WHITESPACE,
    CSST_CDO,            /* <!-- */
    CSST_CDC,            /* --> */
    CSST_COLON,          /* : */
    CSST_SEMICOLON,      /* ; */
    CSST_COMMA,          /* , */
    CSST_LBRACKET,       /* [ */
    CSST_RBRACKET,       /* ] */
    CSST_LPAREN,         /* ( */
    CSST_RPAREN,         /* ) */
    CSST_LBRACE,         /* { */
    CSST_RBRACE,         /* } */
    CSST_DELIM,          /* anything else, e.g. . > + ~ * / */
    CSST__MAX
} css_tok_kind_t;

typedef struct {
    css_tok_kind_t kind;
    const char    *start;
    int            length;
    /* Numeric tokens */
    double         number;
    /* Dimension tokens: unit is a slice after the number */
    const char    *unit;
    int            unit_len;
} css_token_t;

/* ---- Selector parts ---- */
typedef enum {
    SEL_ELEMENT,      /* div, span, * */
    SEL_CLASS,        /* .foo */
    SEL_ID,           /* #bar */
    SEL_ATTR,         /* [href] [href="x"] [href^="x"] [href$="x"] [href*="x"] */
    SEL_PSEUDO_CLASS, /* :hover, :first-child, :not(...) */
    SEL_PSEUDO_ELEM,  /* ::before */
    SEL_UNIVERSAL,    /* * */
} css_selector_part_kind_t;

typedef struct {
    css_selector_part_kind_t kind;
    /* The main name — for ELEMENT: "div"; CLASS: "foo"; ID: "bar";
     * PSEUDO: "hover"; ATTR: "href". */
    const char *name;
    int         name_len;
    /* For ATTR: operator string ("", "=", "^=", "$=", "*=", "~=", "|=") */
    const char *attr_op;
    int         attr_op_len;
    /* For ATTR: value (may be quoted; slice excludes quotes) */
    const char *attr_value;
    int         attr_value_len;
    /* For PSEUDO_CLASS with arguments: :not(...), :nth-child(2n+1).
     * Recursively a selector list. NULL for simple pseudo-classes. */
    struct css_selector_list *inner;
    /* For :nth-child(2n+1) — store raw argument text */
    const char *arg_text;
    int         arg_len;
} css_selector_part_t;

/* A combinator between parts: ' ' (descendant), '>', '+', '~'. */
typedef enum {
    COMB_NONE = 0,
    COMB_DESCENDANT,
    COMB_CHILD,
    COMB_ADJACENT,
    COMB_SIBLING,
} css_combinator_t;

typedef struct {
    css_selector_part_t *parts;
    css_combinator_t    *combinators;   /* length = n_parts - 1 */
    int                  n_parts;
    int                  cap_parts;
    /* Computed specificity: (a, b, c) — id, class/attr/pseudo, element */
    uint32_t             spec_a;
    uint32_t             spec_b;
    uint32_t             spec_c;
} css_selector_t;

typedef struct css_selector_list {
    css_selector_t *items;
    int             n;
    int             cap;
} css_selector_list_t;

/* ---- Value representation ---- */
typedef enum {
    CSSV_UNKNOWN = 0,
    CSSV_NUMBER,
    CSSV_LENGTH,
    CSSV_PERCENT,
    CSSV_COLOR_HEX,
    CSSV_STRING,
    CSSV_URL,
    CSSV_KEYWORD,
    CSSV_FUNCTION,
} css_value_kind_t;

typedef struct {
    css_value_kind_t kind;
    const char *text;
    int         text_len;
    double      number;
    const char *unit;
    int         unit_len;
    uint32_t    rgb;
    const char *fn_name;
    int         fn_name_len;
    const char *fn_args;
    int         fn_args_len;
} css_value_t;

/* ---- Declaration ---- */
typedef struct {
    const char *prop;
    int         prop_len;
    const char *value;
    int         value_len;
    int         important;      /* 1 if !important */
    /* Structured value — filled at parse time so the cascade doesn't
     * have to re-parse text. Pointer to css_value_t, or NULL. */
    void       *parsed;
} css_decl_t;

/* ---- Rule ---- */
typedef enum {
    RULE_STYLE = 0,      /* selector { decls } */
    RULE_AT_MEDIA,       /* @media ... { ... } */
    RULE_AT_IMPORT,      /* @import "..." ; */
    RULE_AT_SUPPORTS,    /* @supports (...) { ... } */
    RULE_AT_FONT_FACE,   /* @font-face { ... } */
    RULE_AT_KEYFRAMES,   /* @keyframes name { ... } */
    RULE_AT_UNKNOWN,     /* any other @rule, kept raw */
} css_rule_kind_t;

typedef struct css_rule {
    css_rule_kind_t kind;
    /* For RULE_STYLE */
    css_selector_list_t selectors;
    css_decl_t         *decls;
    int                 n_decls;
    int                 cap_decls;
    /* For @-rules */
    const char         *at_name;      /* "media", "import", "supports" */
    int                 at_name_len;
    const char         *at_prelude;   /* raw text between @name and { or ; */
    int                 at_prelude_len;
    /* Nested rules (for @media, @supports) */
    struct css_rule    *nested;
    int                 n_nested;
    int                 cap_nested;
} css_rule_t;


/** Token cache entry — keyed by FNV-1a hash of source. */
typedef struct {
    uint64_t hash;
    size_t   length;
    int      valid;
    css_token_t *tokens;
    int      n_tokens;
} css_tok_cache_entry_t;

/** Stylesheet cache entry. */
typedef struct {
    uint64_t hash;
    size_t   length;
    int      valid;
    void    *stylesheet;   /* css_stylesheet_t * */
} css_sheet_cache_entry_t;

/** Selector intern table entry. */
typedef struct {
    const char *text;
    int         text_len;
    int         valid;
    void       *parsed;    /* css_selector_t * */
} css_sel_intern_entry_t;

/* ---- Stylesheet ---- */
typedef struct {
    css_rule_t *rules;
    int         n_rules;
    int         cap_rules;
    /* Arena backing everything. Free once. */
    void       *arena;
} css_stylesheet_t;

#endif
