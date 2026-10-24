/** cipher_tiers.c — ClientHello suite lists per tier (strongest first).
 *
 *  Rule: only advertise what the stack can complete AND the tier permits.
 *  Features that are not implemented yet are compiled out; define the macro
 *  when the code lands:
 *    CRISPTLS_HAVE_DHE      FFDHE key exchange (ServerKeyExchange with DH params)
 *    CRISPTLS_HAVE_RSA_KX   static RSA key exchange (RSA-PKCS1 encrypt of pre-master)
 *    CRISPTLS_HAVE_RC4      RC4 stream record class
 */
#include "crisptls_tier.h"

const uint16_t CRISPTLS_CIPHERS_12_MODERN[] = {
    0xC02B,  /* ECDHE_ECDSA_AES_128_GCM_SHA256 */
    0xC02F,  /* ECDHE_RSA_AES_128_GCM_SHA256 */
    0xC02C,  /* ECDHE_ECDSA_AES_256_GCM_SHA384 */
    0xC030,  /* ECDHE_RSA_AES_256_GCM_SHA384 */
    0xCCA9,  /* ECDHE_ECDSA_CHACHA20_POLY1305 */
    0xCCA8,  /* ECDHE_RSA_CHACHA20_POLY1305 */
    0
};

const uint16_t CRISPTLS_CIPHERS_12_COMPAT[] = {
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
#ifdef CRISPTLS_HAVE_DHE
    0x009E,  /* DHE_RSA_AES_128_GCM_SHA256 */
    0x009F,  /* DHE_RSA_AES_256_GCM_SHA384 */
    0xCCAA,  /* DHE_RSA_CHACHA20_POLY1305 */
#endif
    0xC023,  /* ECDHE_ECDSA_AES_128_CBC_SHA256 */
    0xC027,  /* ECDHE_RSA_AES_128_CBC_SHA256 */
    0xC024,  /* ECDHE_ECDSA_AES_256_CBC_SHA384 */
    0xC028,  /* ECDHE_RSA_AES_256_CBC_SHA384 */
    0xC009,  /* ECDHE_ECDSA_AES_128_CBC_SHA */
    0xC013,  /* ECDHE_RSA_AES_128_CBC_SHA */
    0xC00A,  /* ECDHE_ECDSA_AES_256_CBC_SHA */
    0xC014,  /* ECDHE_RSA_AES_256_CBC_SHA */
#ifdef CRISPTLS_HAVE_DHE
    0x0067,  /* DHE_RSA_AES_128_CBC_SHA256 */
    0x006B,  /* DHE_RSA_AES_256_CBC_SHA256 */
    0x0033,  /* DHE_RSA_AES_128_CBC_SHA */
    0x0039,  /* DHE_RSA_AES_256_CBC_SHA */
#endif
    0
};

const uint16_t CRISPTLS_CIPHERS_12_LEGACY[] = {
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
#ifdef CRISPTLS_HAVE_DHE
    0x009E, 0x009F, 0xCCAA,
#endif
    0xC023, 0xC027, 0xC024, 0xC028, 0xC009, 0xC013, 0xC00A, 0xC014,
#ifdef CRISPTLS_HAVE_DHE
    0x0067, 0x006B, 0x0033, 0x0039,
    0x0016,  /* DHE_RSA_3DES_EDE_CBC_SHA */
#endif
#ifdef CRISPTLS_HAVE_RSA_KX
    0x009C, 0x009D,   /* RSA_AES_GCM */
    0x003C, 0x003D,   /* RSA_AES_CBC_SHA256 */
    0x002F, 0x0035,   /* RSA_AES_CBC_SHA */
#endif
    0xC008,  /* ECDHE_ECDSA_3DES_EDE_CBC_SHA  (Sweet32) */
    0xC012,  /* ECDHE_RSA_3DES_EDE_CBC_SHA    (Sweet32) */
#ifdef CRISPTLS_HAVE_RSA_KX
    0x000A,  /* RSA_3DES_EDE_CBC_SHA */
#endif
#ifdef CRISPTLS_HAVE_RC4
    0xC007, 0xC011,   /* ECDHE_*_RC4_SHA */
  #ifdef CRISPTLS_HAVE_RSA_KX
    0x0005, 0x0004,   /* RSA_RC4_128_SHA / MD5 */
  #endif
#endif
    0
};
