```bash
cd ~/cube && cat > README.md <<'EOF'
# cube

A headless browser and network toolkit in C.

```sh
cube https://example.com
```

Requirements

· C compiler, make, llvm-ar
· POSIX OS: Linux, macOS, BSD, Android/Termux
· Optional: OpenSSL, libsodium

Build

```sh
for dir in utils flywheel/url flywheel/html flywheel/css flywheel/dom \
           flywheel/js flywheel/json net/crisptls net/dns net/tcp \
           net/udp net/http_client net/quic; do
    [ -f "$dir/Makefile" ] && (cd "$dir" && make)
done
make
```

Output: ./cube.

Usage

```sh
cube <url> [options]
```

flag effect
-b, --body-only suppress response headers
--raw skip HTML formatting
-H 'Header: value' add a request header
--no-follow do not follow redirects
--retries N retry failed connections (default 3)
--no-color disable terminal colors
--no-warnings suppress TLS advisories
--trace verbose protocol trace

Multiple URLs:

```sh
cube https://example.com https://httpbin.org/get example.org
```

Schemes http:// and https:// are inferred when omitted.

Layout

```
src/cube.c              CLI driver
flywheel/
  url/                  RFC 3986 URL parser (zero-copy, SIMD-accelerated)
  html/                 HTML5 tokenizer and formatter
  css/                  CSS parser, selector engine, computed style
  dom/                  DOM tree, style cascade, JS bindings
  js/                   JavaScript runtime
  json/                 JSON parser
net/
  tcp/                  TCP socket primitives
  udp/                  UDP socket primitives
  dns/                  DNS resolver (UDP, TCP, DoT, DoH)
  crisptls/             TLS 1.2/1.3 with native crypto
  http_client/          HTTP/1.1 and HTTP/2 client
  quic/                 QUIC (in progress)
tools/
  erdict/               Source-code search, analysis, patching
  dbug/                 Debugger and memory tracer
  sear/                 Predecessor to erdict
  crypto-oracle/        Python test-vector generators
utils/                  Shared utilities
tests/                  Test suite and corpus
```

Libraries

flywheel/url

RFC 3986 compliant. Zero-copy: every field in url_view points into the caller's input buffer. No allocation during parse.

```c
#include "url_parser.h"

url_view v;
if (url_parse("https://example.com/path?q=1", 29, &v) == URL_OK) {
    printf("scheme: %.*s\n", (int)v.scheme_len, v.scheme);
    printf("host:   %.*s\n", (int)v.host_len,   v.host);
    printf("port:   %u\n",   v.port);
}
```

Entry points: url_parse, url_parse_ex, url_parse_whatwg_stable, url_parse_auto, url_join, url_validate, url_canonicalize, url_same_origin, url_same_host.

Byte scanning: SSE2 on x86, NEON on ARM64, scalar fallback. Parity test verifies identical results across backends.

net/crisptls

TLS 1.2 and 1.3. CertificateVerify chain validation, ALPN, SNI, QUIC key derivation.

Native: AES-128/256-GCM, ChaCha20-Poly1305, AES-CBC + HMAC-SHA256, SHA-1/256/384/512, MD5, HMAC, HKDF, P-256 ECDSA, X25519.

Bundled CA bundle: net/crisptls/data/cacert.pem (Mozilla, 118 certs). Fallback: $SSL_CERT_FILE, then OS default.

net/dns

A and AAAA over UDP, TCP, DoT, DoH. Multiple upstreams raced in parallel. Weighted scoring persisted across runs. Configurable cache.

net/http_client

HTTP/1.1 and HTTP/2. HPACK with Huffman coding, stream multiplexing, Content-Length and Transfer-Encoding, redirect following, cookie jar.

Tools

erdict

```sh
erdict src/url_parser.c --funcs
erdict src/url_parser.c --section parse_impl
erdict src/url_parser.c /scheme/ --brief
```

Structure, search, range extraction, call graphs, syntax check, patch application with journal, cross-file rename.

dbug

LD_PRELOAD shim logging malloc, free, memcpy, memset calls with stack traces. Runs a command under tracing; reports leaks and crashes. Linux and Android/Termux.

crypto-oracle

Python scripts generating ECDSA and Ed25519 test vectors against the cryptography package. Used to verify crisptls native implementations.

Runtime

cube reads:

· /dev/urandom (POSIX)
· net/crisptls/data/cacert.pem (bundled)
· /proc/self/exe, /proc/self/statm (Linux)
· $HOME, $TMPDIR (fallback to /tmp)

cube does not spawn subprocesses, does not load external shared libraries, does not require a system CA store. Every read has an in-repo fallback.

erdict and dbug invoke cc, make, /bin/sh. These tools are opt-in and never called by cube.

Testing

```sh
make test          # all test binaries
make throughput    # URL parser benchmark
make parity        # SIMD vs scalar parity check
```

Per-library test directories. URL corpus in flywheel/url/tests/corpus/. Fuzz harnesses for HTML and CSS.

Platforms

· Linux (x86-64, aarch64)
· macOS (Intel, Apple Silicon)
· Android / Termux (aarch64)

Windows: partial. platform.c has Windows paths; build system assumes POSIX shell.

Known build quirks

· Root Makefile does not recurse into flywheel/ or net/. Build each library first (see Build section).
· src/cube.c:1269 uses deprecated url_parse_whatwg. Migrate to url_parse_whatwg_stable.

Limitations

· JavaScript runtime: partial ECMAScript implementation
· QUIC: Initial packet exchange only, full handshake pending
· No WebSocket
· No rendering — HTML formatted for terminal, not painted
· No proxy support
· Cookie jar file-based, not shared database

License

MIT. See LICENSE.
EOF

```

README written. Nothing else.
