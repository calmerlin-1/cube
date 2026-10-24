/** record.c — TLS record framing. Shared across all versions. */

#include "record.h"
#include <string.h>

int tls_record_parse_header(const uint8_t *buf, size_t len, tls_record_t *out) {
    if (!buf || !out) return -1;
    if (len < TLS_RECORD_HEADER_LEN) return 0;
    out->type    = buf[0];
    out->version = (uint16_t)((buf[1] << 8) | buf[2]);
    out->length  = (uint16_t)((buf[3] << 8) | buf[4]);
    out->payload = NULL;
    if (out->length > TLS_MAX_CIPHERTEXT) return -1;
    return TLS_RECORD_HEADER_LEN;
}

int tls_record_write_header(uint8_t type, uint16_t version, uint16_t length,
                            uint8_t out[5]) {
    if (!out) return -1;
    out[0] = type;
    out[1] = (uint8_t)(version >> 8);
    out[2] = (uint8_t)(version & 0xFF);
    out[3] = (uint8_t)(length >> 8);
    out[4] = (uint8_t)(length & 0xFF);
    return 5;
}
