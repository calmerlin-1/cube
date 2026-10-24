# crisptls tests

## RFC conformance tests

Each is an independent implementation of the RFC formula, transcribed
from the spec text using libcrypto directly. Byte-for-byte comparison
against crisptls's helpers.

| Test                | RFC reference          | Assertions |
|---------------------|------------------------|------------|
| `tier_test`         | RFC 8446 §4.2, §9.2    | 16         |
| `ssl3_rfc_test`     | RFC 6101 §5.2.3, §6.3, §7.6.1 | 11 |
| `tls_legacy_rfc_test` | RFC 2246 §5, §6.3, §8.1; RFC 5246 §5; RFC 7627 §4 | 17 |

Run all RFC tests:

    make rfc

Should print `ALL RFC TESTS PASSED` and exit 0.

## Unit tests

Pre-existing tests, not audited this session:

- `connect_test` — connection behavior
- `quic_test` / `quic_packet_test` — QUIC protocol
- `sha384_test` — SHA-384 primitive
- `x25519_test` — X25519 key exchange

## Building

    make all       # build everything
    make rfc       # build + run RFC tests only
    make clean     # remove built binaries

Binaries land in `../../net/crisptls/build/`.
