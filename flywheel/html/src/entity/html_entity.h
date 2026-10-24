/** html_entity.h — HTML named + numeric entity decoding. */

#ifndef FLY_HTML_ENTITY_H
#define FLY_HTML_ENTITY_H

#include <stddef.h>

/** Decode HTML entities in-place into out. Returns bytes written. */
int html_entity_decode(const char *in, int in_len, char *out, size_t cap);

#endif
