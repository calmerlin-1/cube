/** registry.c — profile lookup by name. */

#include "crisptls_fingerprint.h"
#include "crisptls_policy.h"
#include <string.h>

/** Declared in chrome.c, firefox.c, etc. */
extern const crisptls_profile_t CRISPTLS_PROFILE_CHROME_120;
extern const crisptls_profile_t CRISPTLS_PROFILE_FIREFOX_121;
extern const crisptls_profile_t CRISPTLS_PROFILE_CURL_8;
extern const crisptls_profile_t CRISPTLS_PROFILE_CHROME_131;
extern const crisptls_profile_t CRISPTLS_PROFILE_FIREFOX_133;
extern const crisptls_profile_t CRISPTLS_PROFILE_EDGE_120;
extern const crisptls_profile_t CRISPTLS_PROFILE_SAFARI_17;

static const crisptls_profile_t *REGISTRY[] = {
    &CRISPTLS_PROFILE_CHROME_120,
    &CRISPTLS_PROFILE_FIREFOX_121,
    &CRISPTLS_PROFILE_CURL_8,
    &CRISPTLS_PROFILE_CHROME_131,
    &CRISPTLS_PROFILE_FIREFOX_133,
    &CRISPTLS_PROFILE_EDGE_120,
    &CRISPTLS_PROFILE_SAFARI_17,
    NULL
};

const crisptls_profile_t *crisptls_profile_lookup(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; REGISTRY[i]; i++) {
        if (!strcmp(REGISTRY[i]->name, name)) return REGISTRY[i];
    }
    /* Runtime profiles from a config file extend the built-in registry. */
    return crisptls_profile_find_loaded(name);
}

const char *const *crisptls_policy_profile_names(void) {
    static const char *names[64];
    static int init = 0;
    if (!init) {
        int n = 0;
        static const char *builtin[] = {
            "chrome-120", "firefox-121", "curl-8",
            "chrome-131", "firefox-133", "edge-120", "safari-17"
        };
        for (size_t i = 0; i < sizeof(builtin) / sizeof(builtin[0]) && n < 63; i++)
            names[n++] = builtin[i];
        const char *const *loaded = crisptls_profile_loaded_names();
        for (int i = 0; loaded && loaded[i] && n < 63; i++)
            names[n++] = loaded[i];
        names[n] = NULL;
        init = 1;
    }
    return names;
}
