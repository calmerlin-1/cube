/** registry.c — profile lookup by name. */

#include "crisptls_fingerprint.h"
#include "crisptls_policy.h"
#include <string.h>

/** Declared in chrome.c, firefox.c, etc. */
extern const crisptls_profile_t CRISPTLS_PROFILE_CHROME_120;
extern const crisptls_profile_t CRISPTLS_PROFILE_FIREFOX_121;
extern const crisptls_profile_t CRISPTLS_PROFILE_CURL_8;

static const crisptls_profile_t *REGISTRY[] = {
    &CRISPTLS_PROFILE_CHROME_120,
    &CRISPTLS_PROFILE_FIREFOX_121,
    &CRISPTLS_PROFILE_CURL_8,
    NULL
};

const crisptls_profile_t *crisptls_profile_lookup(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; REGISTRY[i]; i++) {
        if (!strcmp(REGISTRY[i]->name, name)) return REGISTRY[i];
    }
    return NULL;
}

const char *const *crisptls_policy_profile_names(void) {
    static const char *names[] = { "chrome-120", "firefox-121", "curl-8", NULL };
    return names;
}
