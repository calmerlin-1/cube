/** proxy.h — outbound proxy configuration and tunnel establishment. */
#ifndef CUBE_NET_PROXY_H
#define CUBE_NET_PROXY_H

#include <stddef.h>

typedef enum {
    PROXY_NONE = 0,
    PROXY_HTTP,
    PROXY_SOCKS5,
    PROXY_SOCKS5H
} proxy_type_t;

typedef struct {
    proxy_type_t   type;
    char           host[256];
    unsigned short port;
    char           user[128];
    char           pass[128];
    char           no_proxy[1024];
} proxy_config_t;

/* Parse "http://user:pass@host:port", "socks5://host:1080", "socks5h://...". */
int  proxy_parse(proxy_config_t *p, const char *url);

/* Set bypass list (comma/space separated; "*" bypasses everything). */
void proxy_set_no_proxy(proxy_config_t *p, const char *list);

/* 1 = connect directly, 0 = use proxy. */
int  proxy_bypass(const proxy_config_t *p, const char *host);

/* Establish a tunnel over an already-connected proxy fd. Returns 0 on success. */
int  proxy_tunnel(const proxy_config_t *p, int fd,
                  const char *host, unsigned short port,
                  unsigned int timeout_ms, char *err, size_t cap);

#endif
