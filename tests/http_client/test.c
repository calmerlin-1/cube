/** test.c — smoke test for http_client. */

#include "http_client.h"
#include "http_status.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    http_client_t c;
    http_client_init(&c);
    http_headers_set(&c.default_headers, "User-Agent", "cube-http-client/0.1");

    http_response_t r;
    int rc = http_client_get(&c, "1.1.1.1", 80, "/", &r);
    if (rc != 0) {
        fprintf(stderr, "get failed: %d\n", rc);
        http_client_free(&c);
        return 1;
    }

    printf("status : %d %s\n", r.status_code, r.reason ? r.reason : "");
    const char *srv = http_headers_get(&r.headers, "Server");
    if (srv) printf("server : %s\n", srv);
    printf("body   : %zu bytes\n", r.body_len);

    /* exercise chunked / Content-Length path */
    rc = http_client_get(&c, "1.1.1.1", 80, "/cdn-cgi/trace", &r);
    if (rc == 0) {
        printf("trace  : %d %s\n", r.status_code, http_status_str(r.status_code));
        printf("body   : %zu bytes\n", r.body_len);
        http_response_free(&r);
    }

    http_response_free(&r);
    http_client_free(&c);
    return 0;
}
