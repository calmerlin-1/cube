#include <stdio.h>
#include <string.h>
#include "url_parser.h"
int main(void) {
    const char *cases[] = {
        "https://[::1]/",
        "https://[2001:DB8::1]/",
        "https://[2001:0DB8:0000:0000:0000:0000:0000:0001]/",
        "https://[FE80::1]/",
        "https://[0:0:0:0:0:0:0:1]/",
        "https://[2001:db8:0:0:1:0:0:1]/",
        "https://[::ffff:192.0.2.1]/",
        NULL
    };
    for (int i = 0; cases[i]; i++) {
        char buf[8192]; size_t n = 0; url_view v;
        url_err e = url_parse_whatwg_stable(cases[i], strlen(cases[i]),
                                             buf, sizeof buf, &n, &v);
        if (e != URL_OK) {
            printf("%-52s  ERR %s\n", cases[i], url_err_name(e));
            continue;
        }
        printf("%-52s  host='%.*s'\n", cases[i], (int)v.host_len, v.host);
    }
    return 0;
}
