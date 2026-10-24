/* url_schemes.c — scheme -> port + flags. One sorted table, binary search. */

#include "url_schemes.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

/* Return lowercase of c. */
static unsigned char to_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

/* Compare slice vs literal, case-insensitive. Returns -1/0/1. */
static int cmp_ci(const char *a, size_t al, const char *b) {
    size_t bl = strlen(b);
    size_t n = al < bl ? al : bl;
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = to_lower((unsigned char)a[i]);
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb) return ca < cb ? -1 : 1;
    }
    if (al < bl) return -1;
    if (al > bl) return 1;
    return 0;
}

/* Built-in table. MUST be sorted by scheme name (ASCII). */
typedef struct { const char *scheme; unsigned short port; unsigned char flags; } row;

static const row BUILTIN[] = {
    {"about",          0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"afp",            548,   SCHEME_HAS_PORT},
    {"amqp",           5672,  SCHEME_HAS_PORT},
    {"amqps",          5671,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"arangodb",       8529,  SCHEME_HAS_PORT},
    {"bitcoin",        8333,  SCHEME_HAS_PORT},
    {"bittorrent",     6881,  SCHEME_HAS_PORT},
    {"blob",           0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"cassandra",      9042,  SCHEME_HAS_PORT},
    {"chrome",         0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"cifs",           445,   SCHEME_HAS_PORT},
    {"clickhouse",     9000,  SCHEME_HAS_PORT},
    {"cockroachdb",    26257, SCHEME_HAS_PORT},
    {"collectd",       25826, SCHEME_HAS_PORT},
    {"consul",         8500,  SCHEME_HAS_PORT},
    {"couchdb",        5984,  SCHEME_HAS_PORT},
    {"dash",           80,    SCHEME_HAS_PORT},
    {"data",           0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"dav",            80,    SCHEME_HAS_PORT},
    {"dhcp",           67,    SCHEME_HAS_PORT},
    {"dhcpv6",         547,   SCHEME_HAS_PORT},
    {"dht",            6881,  SCHEME_HAS_PORT},
    {"dns",            53,    SCHEME_HAS_PORT},
    {"dns-over-tls",   853,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"docker",         2375,  SCHEME_HAS_PORT},
    {"docker-tls",     2376,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"doh",            443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"edonkey",        4662,  SCHEME_HAS_PORT},
    {"elasticsearch",  9200,  SCHEME_HAS_PORT},
    {"etcd",           2379,  SCHEME_HAS_PORT},
    {"ethereum",       30303, SCHEME_HAS_PORT},
    {"file",           0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"finger",         79,    SCHEME_HAS_PORT},
    {"ftp",            21,    SCHEME_HAS_PORT},
    {"ftp-data",       20,    SCHEME_HAS_PORT},
    {"ftps",           990,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"ftps-data",      989,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"gemini",         1965,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"git",            9418,  SCHEME_HAS_PORT},
    {"gnutella",       6346,  SCHEME_HAS_PORT},
    {"gopher",         70,    SCHEME_HAS_PORT},
    {"grafana",        3000,  SCHEME_HAS_PORT},
    {"gre",            47,    SCHEME_HAS_PORT},
    {"hls",            80,    SCHEME_HAS_PORT},
    {"http",           80,    SCHEME_HAS_PORT},
    {"http-alt",       8080,  SCHEME_HAS_PORT},
    {"https",          443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"https-alt",      8443,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"imap",           143,   SCHEME_HAS_PORT},
    {"imaps",          993,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"influxdb",       8086,  SCHEME_HAS_PORT},
    {"ipfs",           4001,  SCHEME_HAS_PORT},
    {"ipfs-api",       5001,  SCHEME_HAS_PORT},
    {"ipfs-gateway",   8080,  SCHEME_HAS_PORT},
    {"ipns",           0,     SCHEME_NO_HOST},
    {"ipsec",          500,   SCHEME_HAS_PORT},
    {"ipsec-nat-t",    4500,  SCHEME_HAS_PORT},
    {"irc",            194,   SCHEME_HAS_PORT},
    {"ircs",           6697,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"iscsi",          3260,  SCHEME_HAS_PORT},
    {"javascript",     0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"kad",            4672,  SCHEME_HAS_PORT},
    {"kafka",          9092,  SCHEME_HAS_PORT},
    {"kerberos",       88,    SCHEME_HAS_PORT},
    {"kubelet",        10250, SCHEME_HAS_PORT},
    {"kubernetes",     6443,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"l2tp",           1701,  SCHEME_HAS_PORT},
    {"ldap",           389,   SCHEME_HAS_PORT},
    {"ldaps",          636,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"llmnr",          5355,  SCHEME_HAS_PORT},
    {"magnet",         0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"mailto",         0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"managesieve",    2000,  SCHEME_HAS_PORT},
    {"mariadb",        3306,  SCHEME_HAS_PORT},
    {"matrix",         8448,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"mdns",           5353,  SCHEME_HAS_PORT},
    {"memcached",      11211, SCHEME_HAS_PORT},
    {"mms",            1755,  SCHEME_HAS_PORT},
    {"mongodb",        27017, SCHEME_HAS_PORT},
    {"mqtt",           1883,  SCHEME_HAS_PORT},
    {"mqtts",          8883,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"mssql",          1433,  SCHEME_HAS_PORT},
    {"mysql",          3306,  SCHEME_HAS_PORT},
    {"nagios",         5666,  SCHEME_HAS_PORT},
    {"nbd",            10809, SCHEME_HAS_PORT},
    {"neo4j",          7687,  SCHEME_HAS_PORT},
    {"netbios-dgm",    138,   SCHEME_HAS_PORT},
    {"netbios-ns",     137,   SCHEME_HAS_PORT},
    {"netbios-ssn",    139,   SCHEME_HAS_PORT},
    {"nfs",            2049,  SCHEME_HAS_PORT},
    {"nomad",          4646,  SCHEME_HAS_PORT},
    {"ntp",            123,   SCHEME_HAS_PORT},
    {"openvpn",        1194,  SCHEME_HAS_PORT},
    {"oracle",         1521,  SCHEME_HAS_PORT},
    {"pop3",           110,   SCHEME_HAS_PORT},
    {"pop3s",          995,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"postgresql",     5432,  SCHEME_HAS_PORT},
    {"pptp",           1723,  SCHEME_HAS_PORT},
    {"prometheus",     9090,  SCHEME_HAS_PORT},
    {"rabbitmq",       5672,  SCHEME_HAS_PORT},
    {"radius",         1812,  SCHEME_HAS_PORT},
    {"radius-acct",    1813,  SCHEME_HAS_PORT},
    {"rdp",            3389,  SCHEME_HAS_PORT},
    {"redis",          6379,  SCHEME_HAS_PORT},
    {"rfb",            5900,  SCHEME_HAS_PORT},
    {"riak",           8087,  SCHEME_HAS_PORT},
    {"rlogin",         513,   SCHEME_HAS_PORT},
    {"rsh",            514,   SCHEME_HAS_PORT},
    {"rsync",          873,   SCHEME_HAS_PORT},
    {"rtmp",           1935,  SCHEME_HAS_PORT},
    {"rtmps",          443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"rtp",            5004,  SCHEME_HAS_PORT},
    {"rtsp",           554,   SCHEME_HAS_PORT},
    {"s3",             443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"scp",            22,    SCHEME_HAS_PORT | SCHEME_TLS},
    {"sftp",           22,    SCHEME_HAS_PORT | SCHEME_TLS},
    {"shadowsocks",    8388,  SCHEME_HAS_PORT},
    {"sieve",          4190,  SCHEME_HAS_PORT},
    {"sip",            5060,  SCHEME_HAS_PORT},
    {"sips",           5061,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"slack",          443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"smb",            445,   SCHEME_HAS_PORT},
    {"sms",            0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"smtp",           25,    SCHEME_HAS_PORT},
    {"smtps",          465,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"snmp",           161,   SCHEME_HAS_PORT},
    {"snmptrap",       162,   SCHEME_HAS_PORT},
    {"socks",          1080,  SCHEME_HAS_PORT},
    {"socks4",         1080,  SCHEME_HAS_PORT},
    {"socks5",         1080,  SCHEME_HAS_PORT},
    {"spotify",        443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"ssh",            22,    SCHEME_HAS_PORT | SCHEME_TLS},
    {"statsd",         8125,  SCHEME_HAS_PORT},
    {"steam",          27015, SCHEME_HAS_PORT},
    {"stomp",          61613, SCHEME_HAS_PORT},
    {"submission",     587,   SCHEME_HAS_PORT},
    {"svn",            3690,  SCHEME_HAS_PORT},
    {"swift",          8080,  SCHEME_HAS_PORT},
    {"syslog",         514,   SCHEME_HAS_PORT},
    {"tacacs",         49,    SCHEME_HAS_PORT},
    {"tel",            0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"telnet",         23,    SCHEME_HAS_PORT},
    {"tftp",           69,    SCHEME_HAS_PORT},
    {"tor",            9050,  SCHEME_HAS_PORT},
    {"tor-control",    9051,  SCHEME_HAS_PORT},
    {"tor-socks",      9050,  SCHEME_HAS_PORT},
    {"urn",            0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"vault",          8200,  SCHEME_HAS_PORT | SCHEME_TLS},
    {"view-source",    0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"vnc",            5900,  SCHEME_HAS_PORT},
    {"vscode",         0,     SCHEME_NO_HOST | SCHEME_OPAQUE},
    {"webdav",         80,    SCHEME_HAS_PORT},
    {"webdavs",        443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"whois",          43,    SCHEME_HAS_PORT},
    {"wireguard",      51820, SCHEME_HAS_PORT},
    {"ws",             80,    SCHEME_HAS_PORT},
    {"wss",            443,   SCHEME_HAS_PORT | SCHEME_TLS},
    {"x11",            6000,  SCHEME_HAS_PORT},
    {"xmpp",           5222,  SCHEME_HAS_PORT},
    {"zabbix",         10050, SCHEME_HAS_PORT},
    {"zeromq",         5555,  SCHEME_HAS_PORT},
    {"zoom",           443,   SCHEME_HAS_PORT | SCHEME_TLS},
};

#define BUILTIN_N (sizeof(BUILTIN) / sizeof(BUILTIN[0]))

/* Runtime table — loaded from conf. Overrides builtins on name clash. */
static row *g_extra = NULL;
static size_t g_extra_n = 0;
static size_t g_extra_cap = 0;

/* Parse one conf line: "scheme port flags". Returns 0 ok, -1 skip. */
static int parse_conf_line(char *line, row *out) {
    char *p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '\0' || *p == '#') return -1;

    char *name = p;
    while (*p && !isspace((unsigned char)*p)) p++;
    if (*p == '\0') return -1;
    *p++ = '\0';

    while (*p && isspace((unsigned char)*p)) p++;
    char *port_s = p;
    while (*p && !isspace((unsigned char)*p)) p++;
    if (*p) *p++ = '\0';

    while (*p && isspace((unsigned char)*p)) p++;
    char *flags_s = p;
    while (*p && *p != '\n' && *p != '\r') p++;
    *p = '\0';

    unsigned port = (unsigned)atoi(port_s);
    if (port > 65535) port = 0;

    unsigned char flags = 0;
    for (char *f = flags_s; *f; f++) {
        switch (*f) {
            case 'p': flags |= SCHEME_HAS_PORT; break;
            case 'h': flags |= SCHEME_NO_HOST;  break;
            case 'o': flags |= SCHEME_OPAQUE;   break;
            case 't': flags |= SCHEME_TLS;      break;
        }
    }
    if (port && !(flags & SCHEME_HAS_PORT)) flags |= SCHEME_HAS_PORT;

    out->scheme = strdup(name);
    if (!out->scheme) return -1;
    for (char *c = (char *)out->scheme; *c; c++) *c = (char)to_lower((unsigned char)*c);
    out->port = (unsigned short)port;
    out->flags = flags;
    return 0;
}

/* Load extra scheme definitions from a conf file. */
int url_schemes_load(const char *conf_path) {
    if (!conf_path) return -1;
    FILE *f = fopen(conf_path, "r");
    if (!f) return -1;

    url_schemes_unload();

    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        row r;
        if (parse_conf_line(line, &r) != 0) continue;
        if (g_extra_n == g_extra_cap) {
            size_t nc = g_extra_cap ? g_extra_cap * 2 : 32;
            row *nr = (row *)realloc(g_extra, nc * sizeof(row));
            if (!nr) { free((void *)r.scheme); break; }
            g_extra = nr;
            g_extra_cap = nc;
        }
        g_extra[g_extra_n++] = r;
        loaded++;
    }
    fclose(f);
    return loaded;
}

/* Drop runtime entries. */
void url_schemes_unload(void) {
    for (size_t i = 0; i < g_extra_n; i++) free((void *)g_extra[i].scheme);
    free(g_extra);
    g_extra = NULL;
    g_extra_n = 0;
    g_extra_cap = 0;
}

/* Linear search runtime table (small). Returns 1 if found. */
static int lookup_extra(const char *scheme, size_t len, scheme_info *out) {
    for (size_t i = 0; i < g_extra_n; i++) {
        if (cmp_ci(scheme, len, g_extra[i].scheme) == 0) {
            out->port = g_extra[i].port;
            out->flags = g_extra[i].flags;
            return 1;
        }
    }
    return 0;
}

/* Binary search builtin table. Returns 1 if found. */
static int lookup_builtin(const char *scheme, size_t len, scheme_info *out) {
    size_t lo = 0, hi = BUILTIN_N;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = cmp_ci(scheme, len, BUILTIN[mid].scheme);
        if (c == 0) {
            out->port = BUILTIN[mid].port;
            out->flags = BUILTIN[mid].flags;
            return 1;
        }
        if (c < 0) hi = mid; else lo = mid + 1;
    }
    return 0;
}

/* Look up scheme. Runtime overrides builtin. Returns 1 found, 0 not. */
int url_scheme_lookup(const char *scheme, size_t len, scheme_info *out) {
    if (!scheme || len == 0 || !out) return 0;
    if (lookup_extra(scheme, len, out)) return 1;
    return lookup_builtin(scheme, len, out);
}

unsigned short url_scheme_default_port(const char *scheme, size_t len) {
    scheme_info info;
    return url_scheme_lookup(scheme, len, &info) ? info.port : 0;
}

int url_scheme_allows_no_host(const char *scheme, size_t len) {
    scheme_info info;
    return url_scheme_lookup(scheme, len, &info) ? ((info.flags & SCHEME_NO_HOST) != 0) : 0;
}

int url_scheme_is_tls(const char *scheme, size_t len) {
    scheme_info info;
    return url_scheme_lookup(scheme, len, &info) ? ((info.flags & SCHEME_TLS) != 0) : 0;
}
