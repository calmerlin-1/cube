/** alert.c — TLS alert messages. */

#include <stdint.h>
#include <string.h>

#define TLS_ALERT_WARNING  1
#define TLS_ALERT_FATAL    2
#define TLS_ALERT_CLOSE_NOTIFY  0

int alert_build(uint8_t level, uint8_t description, uint8_t out[2]) {
    if (!out) return -1;
    out[0] = level;
    out[1] = description;
    return 2;
}

const char *alert_name(uint8_t d) {
    switch (d) {
        case 0:   return "close_notify";
        case 10:  return "unexpected_message";
        case 20:  return "bad_record_mac";
        case 40:  return "handshake_failure";
        case 42:  return "bad_certificate";
        case 43:  return "unsupported_certificate";
        case 44:  return "certificate_revoked";
        case 45:  return "certificate_expired";
        case 46:  return "certificate_unknown";
        case 47:  return "illegal_parameter";
        case 48:  return "unknown_ca";
        case 49:  return "access_denied";
        case 50:  return "decode_error";
        case 51:  return "decrypt_error";
        case 70:  return "protocol_version";
        case 80:  return "internal_error";
        case 109: return "missing_extension";
        case 110: return "unsupported_extension";
        case 112: return "unrecognized_name";
        case 113: return "bad_certificate_status_response";
        case 115: return "unknown_psk_identity";
        case 116: return "certificate_required";
        case 120: return "no_application_protocol";
        default:  return "unknown";
    }
}
