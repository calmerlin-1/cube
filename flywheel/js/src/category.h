/** category.h — execution category classification.
 * Every AST node carries a category. Executors are chosen per category. */

#ifndef FLYWHEEL_CATEGORY_H
#define FLYWHEEL_CATEGORY_H

#include <stdint.h>

typedef enum {
    CAT_UNCLASSIFIED = 0,
    CAT_COLD_ONESHOT,
    CAT_HOT_NUMERIC,
    CAT_HOT_LOOP,
    CAT_MONO_CALL,
    CAT_LOOKUP_BOUND,
    CAT_POLY,
    CAT_DYNAMIC,
    CAT__MAX
} category_t;

typedef struct {
    uint32_t   count;
    uint32_t   same_shape_run;
    uint32_t   same_type_run;
    uint64_t   total_time_ns;
    uint64_t   self_time_ns;
    uint8_t    last_kind_byte;
    uint8_t    _pad[3];
    category_t category;
} cat_state_t;

/** Global flag — when 0, no observation is done. Set to 1 to enable. */
extern int g_cat_enabled;

/** Get or create the classification state for a node. */
cat_state_t *cat_get(const void *node);

/** Assign a category based on observed counters. */
void cat_classify(cat_state_t *s);

/** Dump the current category distribution. */
void cat_dump(void);

/** Reset all observation state. */
void cat_reset(void);

/** Human-readable category name. */
const char *cat_name(category_t c);

#endif
