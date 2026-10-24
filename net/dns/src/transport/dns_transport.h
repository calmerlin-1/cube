/** dns_transport.h — internal transport interface. */

#ifndef FLYWHEEL_DNS_TRANSPORT_H
#define FLYWHEEL_DNS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

/** Send query to an upstream and receive a response.
 * Returns:
 *   >0  : response bytes written into `resp`
 *    0  : timeout / no response
 *   <0  : error
 * Timeout is in ms.
 * `out_latency_ns` receives round-trip time. */
int dns_transport_udp(const char *host, uint16_t port,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns);

int dns_transport_tcp(const char *host, uint16_t port,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns);

int dns_transport_dot(const char *host, uint16_t port,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns);

int dns_transport_doh(const char *url,
                      const uint8_t *query, size_t qlen,
                      uint8_t *resp, size_t resp_cap,
                      uint32_t timeout_ms, uint64_t *out_latency_ns);

#endif
