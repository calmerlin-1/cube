/** dns_pin.h — per-domain upstream preference. Bounded LRU hashmap. */

#ifndef FLYWHEEL_DNS_PIN_H
#define FLYWHEEL_DNS_PIN_H

#include <stddef.h>
#include <stdint.h>

typedef struct dns_pin_store dns_pin_store_t;

dns_pin_store_t *dns_pin_new(size_t max_entries);
void             dns_pin_free(dns_pin_store_t *s);

/** Record that upstream_idx was fastest for (name, type). */
void dns_pin_set(dns_pin_store_t *s, const char *name, uint16_t type, size_t upstream_idx);

/** Return pinned upstream index for (name, type), or SIZE_MAX if none. */
size_t dns_pin_get(dns_pin_store_t *s, const char *name, uint16_t type);

/** Clear all pins. */
void dns_pin_clear(dns_pin_store_t *s);

/** Stats. */
size_t dns_pin_count(dns_pin_store_t *s);

#endif
