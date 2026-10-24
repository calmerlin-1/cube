/** http2.h — HTTP/2 (RFC 9113) protocol engine.
 *
 * Scope: single-request-per-call HTTP/2 client.
 *  - Connection preface + SETTINGS exchange
 *  - HPACK (static table + integer encoding + literal headers)
 *    No Huffman, no dynamic table (servers accept this)
 *  - HEADERS + DATA + END_STREAM
 *  - WINDOW_UPDATE (basic)
 *  - GOAWAY, RST_STREAM, PING
 *
 * Out of scope (for now):
 *  - Huffman coding
 *  - Dynamic HPACK table
 *  - Server push
 *  - Prioritization
 *  - Multiplexing (one request per connection)
 *
 * Assumes ALPN negotiated "h2".
 */

#ifndef CUBE_NET_HTTP2_H
#define CUBE_NET_HTTP2_H

#include "http_client.h"

/* Speak HTTP/2 over an already-connected http_io_t.
 * The io must be an ALPN-h2 TLS session or an h2c-cleartext pipe.
 * Caller owns io. Returns 0 on success, negative on error. */
int http2_send_io(const http_io_t        *io,
                  const char             *host,
                  uint16_t                port,
                  const char             *scheme,     /* "https" or "http" */
                  const http_request_t   *req,
                  http_response_t        *out);

#endif /* CUBE_NET_HTTP2_H */
