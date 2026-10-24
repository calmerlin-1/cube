/* dns_probe.c — query one name, print every field with timing and colors. */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "dns.h"
#include "dns_types.h"
#include "color.h"

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint16_t parse_type(const char *s) {
    if (!strcmp(s, "A"))      return DNS_TYPE_A;
    if (!strcmp(s, "AAAA"))   return DNS_TYPE_AAAA;
    if (!strcmp(s, "MX"))     return DNS_TYPE_MX;
    if (!strcmp(s, "TXT"))    return DNS_TYPE_TXT;
    if (!strcmp(s, "NS"))     return DNS_TYPE_NS;
    if (!strcmp(s, "CNAME"))  return DNS_TYPE_CNAME;
    if (!strcmp(s, "PTR"))    return DNS_TYPE_PTR;
    if (!strcmp(s, "SRV"))    return DNS_TYPE_SRV;
    if (!strcmp(s, "SOA"))    return DNS_TYPE_SOA;
    if (!strcmp(s, "CAA"))    return DNS_TYPE_CAA;
    if (!strcmp(s, "DNSKEY")) return DNS_TYPE_DNSKEY;
    if (!strcmp(s, "DS"))     return DNS_TYPE_DS;
    if (!strcmp(s, "RRSIG"))  return DNS_TYPE_RRSIG;
    if (!strcmp(s, "HTTPS"))  return DNS_TYPE_HTTPS;
    if (!strcmp(s, "SVCB"))   return DNS_TYPE_SVCB;
    if (!strcmp(s, "ANY"))    return DNS_TYPE_ANY;
    return 0;
}

static void print_flag_list(uint8_t f, FILE *out) {
    int any = 0;
    #define ADD(name, bit) do { \
        if (f & (1u << bit)) { fprintf(out, "%s%s", any ? " " : "", name); any = 1; } \
    } while (0)
    ADD("AA", 6);
    ADD("TC", 5);
    ADD("RD", 4);
    ADD("RA", 3);
    ADD("AD", 1);
    ADD("CD", 0);
    #undef ADD
    if (!any) fprintf(out, "-");
}

/* Return the color for a record type. */
static const char *type_color(uint16_t type) {
    if (!col_is_enabled()) return "";
    switch (type) {
        case DNS_TYPE_A:
        case DNS_TYPE_AAAA:   return col_green();
        case DNS_TYPE_CNAME:  return col_yellow();
        case DNS_TYPE_MX:
        case DNS_TYPE_NS:
        case DNS_TYPE_PTR:    return col_cyan();
        case DNS_TYPE_SRV:
        case DNS_TYPE_SOA:
        case DNS_TYPE_CAA:    return col_magenta();
        case DNS_TYPE_TXT:    return col_dim();
        case DNS_TYPE_DNSKEY:
        case DNS_TYPE_DS:
        case DNS_TYPE_RRSIG:  return col_bright_blue();
        case DNS_TYPE_HTTPS:
        case DNS_TYPE_SVCB:   return col_bright_cyan();
        default:              return "";
    }
}

/* Print the value of one record (everything after the type name). */
static void print_record_value(const dns_record_t *rec) {
    char buf[512];
    /* dns_record_format includes the qname; strip it for the value-only output */
    if (dns_record_format(rec, buf, sizeof(buf)) > 0) {
        /* find the second space (after qname and type) */
        const char *p = buf;
        int spaces = 0;
        while (*p && spaces < 2) { if (*p == ' ') spaces++; p++; }
        const char *c = type_color(rec->type);
        const char *r = col_is_enabled() ? col_reset() : "";
        printf("    %-7s %s%s%s\n",
               dns_type_name(rec->type), c, p ? p : buf, r);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: %s <name> [type]\n"
            "  types: A AAAA MX TXT NS CNAME PTR SRV SOA CAA\n"
            "         DNSKEY DS RRSIG HTTPS SVCB ANY\n"
            "  flags: --no-cache   skip cache lookup\n",
            argv[0]);
        return 1;
    }

    const char *name = argv[1];
    uint16_t qtype = DNS_TYPE_A;
    uint32_t flags = 0;

    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i], "--no-cache"))    { flags |= DNS_F_NO_CACHE;    continue; }
        else if (!strcmp(argv[i], "--fresh"))       { flags |= DNS_F_NO_CACHE;    continue; }
        else if (!strcmp(argv[i], "--tcp"))         { flags |= DNS_F_TCP_ONLY;    continue; }
        else if (!strcmp(argv[i], "--udp"))         { flags |= DNS_F_UDP_ONLY;    continue; }
        else if (!strcmp(argv[i], "--doh"))         { flags |= DNS_F_DOH_ONLY;    continue; }
        else if (!strcmp(argv[i], "--dot"))         { flags |= DNS_F_DOT_ONLY;    continue; }
        else if (!strcmp(argv[i], "--dnssec"))      { flags |= DNS_F_DNSSEC;      continue; }
        else if (!strcmp(argv[i], "--no-recurse"))  { flags |= DNS_F_NO_RECURSE;  continue; }
        uint16_t t = parse_type(argv[i]);
        if (t) qtype = t;
        else if (argv[i][0] != '-') { fprintf(stderr, "unknown type: %s\n", argv[i]); return 1; }
    }

    col_enable();

    uint64_t t0 = now_ns();
    dns_resolver_t *r = dns_resolver_new_default();
    uint64_t t1 = now_ns();
    if (!r) { fprintf(stderr, "cannot create resolver\n"); return 1; }

    printf("%s%s %s%s\n",
           col_bold(), name, dns_type_name(qtype), col_reset());
    printf("  %sstartup%s   %.1f ms\n", col_dim(), col_reset(), (t1 - t0) / 1e6);
    printf("  %supstreams%s %zu configured\n",
           col_dim(), col_reset(), dns_upstream_count(r));

    dns_answer_t ans;
    memset(&ans, 0, sizeof(ans));

    t0 = now_ns();
    int rc = dns_resolve(r, name, qtype, flags, &ans);
    t1 = now_ns();

    double wall_ms = (t1 - t0) / 1e6;

    if (rc != DNS_OK) {
        const char *ec = col_red();
        printf("  %sresult%s    %s%s (%d)%s\n",
               col_dim(), col_reset(), ec, dns_err_name(rc), rc, col_reset());
        printf("  %swall%s     %.3f ms\n", col_dim(), col_reset(), wall_ms);
        dns_resolver_free(r);
        return 2;
    }

    const char *wall_c = wall_ms < 100 ? col_green()
                      : wall_ms < 300 ? col_yellow()
                      : col_red();

    printf("  %sresult%s    %sok%s\n",
           col_dim(), col_reset(), col_green(), col_reset());
    printf("  %swall%s     %s%.3f ms%s",
           col_dim(), col_reset(), wall_c, wall_ms, col_reset());
    if (ans.elapsed_ns)
        printf("  %s(internal %.3f ms)%s",
               col_dim(), ans.elapsed_ns / 1e6, col_reset());
    printf("\n");

    /* status line: rcode + flags */
    printf("  %sstatus%s    %s%s%s",
           col_dim(), col_reset(),
           ans.rcode == 0 ? col_green() : col_yellow(),
           dns_rcode_name(ans.rcode), col_reset());
    if (ans.flags) {
        printf("  ");
        print_flag_list(ans.flags, stdout);
    }
    printf("\n");

    if (ans.count == 0) {
        printf("  %sanswers%s   (none)\n", col_dim(), col_reset());
    } else {
        printf("  %sanswers%s   %zu record%s\n",
               col_dim(), col_reset(), ans.count, ans.count == 1 ? "" : "s");
        for (size_t i = 0; i < ans.count; i++)
            print_record_value(&ans.records[i]);
    }

    dns_answer_free(&ans);

    /* second query — cache check */
    dns_answer_t ans2;
    memset(&ans2, 0, sizeof(ans2));
    t0 = now_ns();
    rc = dns_resolve(r, name, qtype, flags, &ans2);
    t1 = now_ns();

    if (rc == DNS_OK) {
        double cached_ms = (t1 - t0) / 1e6;
        printf("  %scached%s    %s%.4f ms%s",
               col_dim(), col_reset(),
               col_green(), cached_ms, col_reset());
        if (wall_ms > 0 && cached_ms > 0) {
            printf("  %s(%.0fx)%s",
                   col_dim(), wall_ms / cached_ms, col_reset());
        }
        printf("\n");
        dns_answer_free(&ans2);
    }

    /* transport + cache stats */
    {
        dns_stats_t st;
        dns_stats(r, &st);
        printf("  %stransport%s  udp=%llu tcp=%llu dot=%llu doh=%llu cached=%llu\n",
               col_dim(), col_reset(),
               (unsigned long long)st.queries_udp,
               (unsigned long long)st.queries_tcp,
               (unsigned long long)st.queries_dot,
               (unsigned long long)st.queries_doh,
               (unsigned long long)st.queries_cached);
    }

    return 0;
}
