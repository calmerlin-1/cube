/** dns_race.c — parallel racing resolver using non-blocking UDP sockets. */

#include "dns_upstream.h"
#include "dns_wire.h"
#include "../include/dns.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

/** One in-flight UDP query. */
typedef struct {
    int          fd;
    size_t       upstream_idx;
    uint16_t     id;
    uint64_t     sent_ns;
    int          active;
} race_slot_t;

#define RACE_MAX 16

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/** Set O_NONBLOCK on fd. Returns 0 ok, -1 error. */
static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/** Resolve host:port to sockaddr_storage. Returns 0 ok, -1 error. */
static int resolve_udp_target(const char *host, uint16_t port,
                              struct sockaddr_storage *out, socklen_t *out_len) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char pstr[8];
    snprintf(pstr, sizeof(pstr), "%u", port);
    if (getaddrinfo(host, pstr, &hints, &res) != 0) return -1;
    int ok = -1;
    for (struct addrinfo *r = res; r; r = r->ai_next) {
        if (r->ai_addrlen <= sizeof(*out)) {
            memcpy(out, r->ai_addr, r->ai_addrlen);
            *out_len = (socklen_t)r->ai_addrlen;
            ok = 0;
            break;
        }
    }
    freeaddrinfo(res);
    return ok;
}

/** Send the query to one upstream, non-blocking. Returns fd >= 0 or -1. */
static int launch_udp(const dns_upstream_t *u,
                      const uint8_t *query, size_t qlen) {
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    if (resolve_udp_target(u->addr, u->port, &ss, &slen) != 0) return -1;

    int fd = socket(ss.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (set_nonblock(fd) != 0) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&ss, slen) != 0) {
        close(fd);
        return -1;
    }
    ssize_t n = send(fd, query, qlen, 0);
    if (n != (ssize_t)qlen) { close(fd); return -1; }
    return fd;
}

/** Race N upstreams in parallel.
 * Returns:
 *   >0  response bytes written into resp
 *    0  all timed out
 *   -1  all failed
 * out_upstream_idx receives the winning index.
 * out_latency_ns receives winning round-trip time. */
/** Launch a specific upstream into a slot. Returns 0 ok, -1 skip. */
static int launch_slot(dns_upstream_pool_t *pool, size_t up_idx,
                       uint16_t query_id, const uint8_t *query, size_t qlen,
                       race_slot_t *slot) {
    const dns_upstream_t *u = &pool->items[up_idx];
    if (u->proto != UP_PROTO_UDP) return -1;
    int fd = launch_udp(u, query, qlen);
    if (fd < 0) return -1;
    slot->fd = fd;
    slot->upstream_idx = up_idx;
    slot->id = query_id;
    slot->sent_ns = now_ns();
    slot->active = 1;
    return 0;
}

/** Race with staged escalation.
 * Phase 1: 0..p1_ms       — top-1 only
 * Phase 2: p1_ms..p2_ms   — top-2..top-4
 * Phase 3: p2_ms..total   — remaining
 * Latecomer grace: after first response, keep polling for grace_ms
 *   and record latencies of losers that also respond. */
int dns_race_query_staged(dns_upstream_pool_t *pool,
                          size_t *upstream_indices, size_t n,
                          const uint8_t *query, size_t qlen,
                          uint8_t *resp, size_t resp_cap,
                          uint32_t p1_ms, uint32_t p2_ms, uint32_t total_ms,
                          uint32_t grace_ms,
                          size_t *out_upstream_idx,
                          uint64_t *out_latency_ns,
                          dns_race_stats_t *out_stats) {
    if (!pool || !upstream_indices || n == 0 || !query || !resp) return -1;
    if (n > RACE_MAX) n = RACE_MAX;

    race_slot_t slots[RACE_MAX];
    memset(slots, 0, sizeof(slots));

    uint16_t query_id = rd16(query);
    uint64_t start = now_ns();
    uint64_t winner_time = 0;
    int winner = -1;
    int winner_bytes = 0;

    /* phase 1: top-1 */
    launch_slot(pool, upstream_indices[0], query_id, query, qlen, &slots[0]);
    size_t launched = slots[0].active ? 1 : 0;

    size_t next_phase2 = 1;
    size_t next_phase3 = (n >= 4) ? 4 : n;
    int in_phase3 = 0;

    uint64_t last_response_ns = 0;
    int    grace_running = 0;

    for (;;) {
        uint64_t elapsed_ms = (now_ns() - start) / 1000000ull;
        uint64_t since_resp_ms = winner >= 0 ? (now_ns() - last_response_ns) / 1000000ull : 0;

        /* check termination */
        if (winner >= 0 && grace_running && since_resp_ms >= grace_ms) break;
        if (winner >= 0 && !grace_running) break;
        if (elapsed_ms >= total_ms) break;
        if (winner < 0 && launched == 0) break;

        /* escalate */
        if (winner < 0 && !in_phase3 && elapsed_ms >= p2_ms && next_phase2 < next_phase3) {
            for (size_t i = next_phase2; i < next_phase3 && i < n; i++) {
                if (slots[i].active) continue;
                if (launch_slot(pool, upstream_indices[i], query_id, query, qlen, &slots[i]) == 0)
                    launched++;
            }
            next_phase2 = next_phase3;
        }
        if (winner < 0 && !in_phase3 && elapsed_ms >= p2_ms * 2 && next_phase3 < n) {
            for (size_t i = next_phase3; i < n; i++) {
                if (slots[i].active) continue;
                if (launch_slot(pool, upstream_indices[i], query_id, query, qlen, &slots[i]) == 0)
                    launched++;
            }
            in_phase3 = 1;
        }

        /* poll active slots */
        struct pollfd pfds[RACE_MAX];
        int   map[RACE_MAX];
        int   np = 0;
        for (int i = 0; i < RACE_MAX; i++) {
            if (slots[i].active) {
                pfds[np].fd = slots[i].fd;
                pfds[np].events = POLLIN;
                map[np] = i;
                np++;
            }
        }
        if (np == 0) break;

        int timeout;
        if (winner < 0) {
            /* next escalation boundary or total */
            uint64_t next = p2_ms;
            if (elapsed_ms >= p2_ms) next = p2_ms * 2;
            if (elapsed_ms >= p2_ms * 2) next = total_ms;
            timeout = (int)(next > elapsed_ms ? (next - elapsed_ms) : 5);
        } else {
            /* grace window */
            timeout = (int)(grace_ms - since_resp_ms);
        }
        if (timeout < 1) timeout = 1;
        int pr = poll(pfds, np, timeout);
        if (pr <= 0) continue;

        for (int i = 0; i < np; i++) {
            if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                int slot = map[i];
                uint8_t tmp[65536];
                ssize_t rn = recv(slots[slot].fd, tmp, sizeof(tmp), 0);
                if (rn <= 0) {
                    close(slots[slot].fd);
                    slots[slot].active = 0;
                    slots[slot].fd = -1;
                    continue;
                }

                uint16_t rid = rd16(tmp);
                if (rid != query_id) continue;

                uint64_t lat = now_ns() - slots[slot].sent_ns;

                if (winner < 0) {
                    /* first responder wins */
                    winner = slot;
                    winner_bytes = (int)(rn < (ssize_t)resp_cap ? rn : (ssize_t)resp_cap);
                    memcpy(resp, tmp, (size_t)winner_bytes);
                    winner_time = lat;
                    last_response_ns = now_ns();
                    grace_running = 1;
                } else {
                    /* latecomer — record its latency on the pool */
                    dns_upstream_record_ok(pool, slots[slot].upstream_idx, lat, 0);
                    if (out_stats) out_stats->latecomers++;
                }
                /* mark slot as consumed — close it */
                close(slots[slot].fd);
                slots[slot].active = 0;
                slots[slot].fd = -1;
            }
        }
    }

    /* cleanup any remaining sockets */
    for (int i = 0; i < RACE_MAX; i++) {
        if (slots[i].fd >= 0) close(slots[i].fd);
    }

    if (out_stats) out_stats->phases_run = in_phase3 ? 3 : (next_phase2 > 1 ? 2 : 1);

    if (winner >= 0) {
        if (out_upstream_idx) *out_upstream_idx = slots[winner].upstream_idx;
        if (out_latency_ns)   *out_latency_ns = winner_time;
        return winner_bytes;
    }
    return 0;
}

/** Backwards-compatible wrapper: escalate at 100ms, 300ms, total; grace 50ms. */
int dns_race_query(dns_upstream_pool_t *pool,
                   size_t *upstream_indices, size_t n,
                   const uint8_t *query, size_t qlen,
                   uint8_t *resp, size_t resp_cap,
                   uint32_t window_ms, uint32_t total_ms,
                   size_t *out_upstream_idx,
                   uint64_t *out_latency_ns) {
    return dns_race_query_staged(pool, upstream_indices, n, query, qlen,
                                 resp, resp_cap,
                                 window_ms, window_ms * 3, total_ms, 50,
                                 out_upstream_idx, out_latency_ns, NULL);
}
