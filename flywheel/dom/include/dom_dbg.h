/** dom_dbg.h — fail-loudly helpers.
 *
 * Every failure prints: file:line in function(): what went wrong.
 * Every function uses DOM_CHECK_* at entry so nothing fails silently.
 */

#ifndef FLYWHEEL_DOM_DBG_H
#define FLYWHEEL_DOM_DBG_H

#include <stdio.h>

#define DOM_FAIL(fmt, ...) do { \
    fprintf(stderr, "[DOM_FAIL] %s:%d in %s(): " fmt "\n", \
            __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
} while (0)

/* Returns -1 on failure — use in int-returning functions. */
#define DOM_CHECK(cond, fmt, ...) do { \
    if (!(cond)) { DOM_FAIL(fmt, ##__VA_ARGS__); return -1; } \
} while (0)

/* Returns void on failure. */
#define DOM_CHECK_VOID(cond, fmt, ...) do { \
    if (!(cond)) { DOM_FAIL(fmt, ##__VA_ARGS__); return; } \
} while (0)

/* Returns NULL on failure — use in pointer-returning functions. */
#define DOM_CHECK_NULL(ptr, what) do { \
    if (!(ptr)) { DOM_FAIL("%s is NULL", what); return NULL; } \
} while (0)

/* Always trace — no silent pass. */
#define DOM_TRACE(fmt, ...) do { \
    fprintf(stderr, "[DOM] %s:%d in %s(): " fmt "\n", \
            __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
} while (0)

#endif /* FLYWHEEL_DOM_DBG_H */
