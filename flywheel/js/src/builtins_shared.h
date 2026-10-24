/** builtins_shared.h — process-wide native prototypes.
 * Built once. Shared by every Interp. Never freed. */

#ifndef FLYWHEEL_BUILTINS_SHARED_H
#define FLYWHEEL_BUILTINS_SHARED_H

#include "../include/object.h"

/** Build all shared native objects. Safe to call multiple times — idempotent. */
void builtins_shared_init(void);

/** Accessors. Each returns the process-wide singleton or NULL. */
Object *builtins_shared_console(void);
Object *builtins_shared_math(void);
Object *builtins_shared_json(void);
Object *builtins_shared_string_proto(void);
Object *builtins_shared_array_proto(void);

/** Free everything. Only call at process exit. */
void builtins_shared_shutdown(void);

#endif
