/** html_types.h — HTML AST. Zero-copy slices into source. Arena allocated. */

#ifndef FLYWHEEL_HTML_TYPES_H
#define FLYWHEEL_HTML_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* ---- Token kinds ---- */
typedef enum {
    HTMLT_EOF = 0,
    HTMLT_TEXT,            /* text between tags */
    HTMLT_START_TAG,       /* <div ...> */
    HTMLT_END_TAG,         /* </div> */
    HTMLT_SELF_CLOSING,    /* <br/> */
    HTMLT_COMMENT,         /* <!-- ... --> */
    HTMLT_DOCTYPE,         /* <!DOCTYPE ...> */
    HTMLT_CDATA,           /* <![CDATA[...]]> */
    HTMLT_ERROR
} html_tok_kind_t;

typedef struct {
    html_tok_kind_t kind;
    const char *start;     /* slice into source */
    int         length;
    int         line;      /* 1-based */
    int         column;
    /* For START_TAG / END_TAG / SELF_CLOSING: tag name slice. */
    const char *tag;
    int         tag_len;
} html_token_t;

/* ---- Attribute ---- */
typedef struct {
    const char *name;      int name_len;
    const char *value;     int value_len;   /* NULL if valueless */
    uint8_t     has_value;
    uint8_t     _pad[3];
} html_attr_t;

/* ---- Node ---- */
typedef enum {
    HTML_NODE_ELEMENT = 0,
    HTML_NODE_TEXT,
    HTML_NODE_COMMENT,
    HTML_NODE_DOCTYPE,
    HTML_NODE_ROOT,
} html_node_kind_t;

typedef struct html_node {
    html_node_kind_t kind;
    const char      *tag;      int tag_len;    /* ELEMENT only */
    html_attr_t     *attrs;    int attr_count; /* ELEMENT only */
    const char      *text;     int text_len;   /* TEXT/COMMENT/DOCTYPE only */
    uint8_t          self_closing;
    uint8_t          _pad[7];
    struct html_node *parent;
    struct html_node *first_child;
    struct html_node *last_child;
    struct html_node *next_sibling;
} html_node_t;

/* ---- Document ---- */
typedef struct {
    html_node_t *root;      /* synthetic root; children are top-level nodes */
    int          n_nodes;
    void        *arena;     /* owned; free with html_free() */
} html_document_t;

#endif
