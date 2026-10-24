flywheel/url

A zero-copy URL parser, joiner, and builder for C. RFC 3986 compliant, with a WHATWG-compatible mode for browser-style input.

Fast: around 1.72 million URLs per second on an ARM phone CPU at 1.37 GHz. No allocation on the parse path. Every field in the output is a view into the input. Nothing is copied, nothing is freed.

Complete: parse, join, canonicalize, build, compare, scheme lookup, punycode (IDNA), runtime scheme table, browser-compatible normalization.

Small: 5 source files, around 2,300 lines of C, no dependencies beyond libc.

What each file does

include/url_parser.h is the public API for the parser. It declares the url_view struct, the url_err enum, the flags for url_parse_ex, and the functions url_parse, url_parse_ex, url_parse_whatwg, url_join, url_build_origin, url_build_href, url_build_href_encoded, url_build_full, url_canonicalize, url_same_host, url_same_origin, and url_err_name. This is the only header a caller needs for parsing and manipulating URLs.

include/url_schemes.h declares the scheme lookup API. It defines the scheme_info struct with a port and a flags byte, and the flags SCHEME_HAS_PORT, SCHEME_NO_HOST, SCHEME_OPAQUE, and SCHEME_TLS. It declares url_scheme_lookup, url_schemes_load, url_schemes_unload, url_scheme_default_port, url_scheme_allows_no_host, and url_scheme_is_tls.

include/url_percent.h declares the percent-encoding helpers. This is where percent-decoding, percent-encoding of a path, and percent-encoding of a query live, separate from the parser so the parser doesn't decode anything on its own.

include/url_idna.h declares the punycode (RFC 3492) encoder and decoder for internationalized domain names. This is called by the parser when a host contains non-ASCII bytes.

include/url_cache.h declares the LRU hash-table memoizer that stores parsed URLs. This is not wired into url_parse — the parser is already fast enough that a cache would be a net loss — but the code exists for consumers who want to opt in.

include/scan.h, include/scan_scalar.h, include/scan_sse2.h, and include/scan_neon.h are the delimiter-scanning implementations. scan.h picks the right one at compile time based on the target architecture. The scalar version is portable C; the SSE2 and NEON versions use SIMD instructions for x86 and ARM. The parser calls the scanner to find the next delimiter (colon, slash, question mark, hash) in one pass.

src/url_parser.c is the parser itself. It contains url_parse, url_parse_ex, url_parse_whatwg, url_join, url_canonicalize, the four url_build_* functions, url_same_host, url_same_origin, and the internal helpers scan_scheme, normalize_path, append_tail, parse_port, and slice_ci_eq. All the parsing logic lives here. The file is around 1,000 lines. The design is single-pass, zero-copy: the parser walks the input once and writes pointers into a url_view, without allocating anything.

src/url_percent.c contains the percent-encoding helpers. url_percent_decode turns %xx sequences into raw bytes. url_percent_encode_path and url_percent_encode_query turn raw bytes into %xx sequences, using different safe-byte sets for the path and the query. This file is deliberately separate from the parser so the parser can preserve %xx verbatim and let callers decide when to decode.

src/url_schemes.c contains the scheme table and its lookup function. The table is a sorted array of {name, port, flags} rows. Lookup is binary search. The table covers around 40 built-in schemes: http, https, ftp, ftps, ws, wss, file, data, mailto, tel, ssh, sftp, git, ldap, ldaps, smb, nfs, redis, mongodb, postgres, mysql, amqp, mqtt, and the rest. New schemes can be added at runtime via url_schemes_load reading a config file. The file is around 13 KB.

data/url_schemes.c is a copy of the same scheme table used for building at compile time. It generates the binary table via a code generator. For most consumers, src/url_schemes.c is the only one that matters.

data/scheme_ports.conf is the runtime extension file. It's a plain text file with one scheme per line in the format name port flags. Flags are p (has port), h (no host), o (opaque), t (TLS). Blank lines and lines starting with # are ignored. When url_schemes_load is called at startup, this file is parsed and its entries are merged into the built-in table.

data/url_idna.c contains the punycode encoder and decoder per RFC 3492. It handles the biasing, the delta encoding, and the insertion of the xn-- prefix. It does not do Unicode NFC normalization — that's out of scope — so it assumes its input is already normalized.

src/url_cache.c contains the LRU cache. It has an entry_t struct with a name, type, class, TTL, and a list of records. It provides url_cache_new, url_cache_free, url_cache_clear, url_cache_set_max, url_cache_get, and url_cache_put. The cache is keyed on the raw URL bytes and the parsed view.

What the parser does

url_parse takes a byte buffer and a length and writes a url_view with the scheme, userinfo, host, port, path, query, and fragment. Every field in the view is a pointer into the original buffer. The parser does not modify the input, does not allocate, and does not decode anything.

url_parse_whatwg is the browser-compatible variant. It normalizes first, then runs the strict parser. The normalizations are: strip ASCII tab, newline, and carriage return from anywhere in the input; strip leading and trailing ASCII whitespace; convert backslashes to forward slashes for the special schemes (http, https, ws, wss, ftp, file); fix missing authority slashes (for example http:/x.com becomes http://x.com); percent-decode the host; expand integer IPv4 forms to dotted decimal (so 2130706433 becomes 127.0.0.1, 0177.0.0.1 becomes 127.0.0.1, and 127.1 becomes 127.0.0.1).

Both functions return a url_err. URL_OK is zero. Any other value is a specific failure. The errors are URL_ERR_EMPTY, URL_ERR_CTRL, URL_ERR_SPACE, URL_ERR_SCHEME, URL_ERR_SCHEME_NOT_ALLOWED, URL_ERR_HOST_MISSING, URL_ERR_HOST_INVALID, URL_ERR_PORT_INVALID, URL_ERR_PORT_RANGE, URL_ERR_TOO_LONG, URL_ERR_JOIN_FAILED, and URL_ERR_BUFFER_TOO_SMALL. url_err_name returns a stable human string for any of them.

What the parser does not do

It does not decode percent-encoding. A %20 in the path stays as %20. A %2F stays as %2F, which matters because servers treat %2F as a literal slash, not a path separator.

It does not normalize dot segments during parsing. A path /a/./b stays as /a/./b. Use url_canonicalize or url_join when you want dot-segment resolution.

It does not allocate. It does not copy. The url_view is a set of views into the input; the input must outlive the view.

It does not do WHATWG Unicode normalization before IDNA. It only applies punycode when a host has non-ASCII bytes. Full NFC handling is out of scope for now.

It does not handle file: on Windows (drive letters) or the blob: and filesystem: schemes specially.

It does not cache parses by default. src/url_cache.c exists but is not called from url_parse. A caller who wants memoization uses it directly.

It is not thread-safe during scheme reloads. url_schemes_load must be called once at startup before any parsing begins. After that, parsing is fully concurrent.

What the builder does

url_build_origin writes scheme://host[:port] into a caller buffer. Port is included only if it differs from the scheme default.

url_build_href writes scheme://host[:port]/path[?query][#fragment]. The path is written verbatim — no normalization, no re-encoding. This is the byte-exact inverse of url_parse.

url_build_href_encoded writes the same thing but percent-encodes unsafe bytes in the path and query. Use this when the URL will go out onto the wire and might contain bytes that need escaping.

url_build_full writes the full URL including userinfo: scheme://user:pass@host[:port]/path[?query][#fragment].

All four return URL_ERR_BUFFER_TOO_SMALL if the output would overflow the caller buffer. Nothing is written partially.

What the joiner does

url_join resolves a relative reference against a base. The implementation follows RFC 3986 section 5.2.3 for merging and section 5.2.4 for dot-segment removal. The behavior is fully specified. Fragment-only references keep the query. Query-only references clear the fragment. Protocol-relative references replace the host. Absolute paths replace the base path. Dot segments are resolved per the RFC. The 45 test cases from RFC 3986 section 5.4 all pass.

The joiner does not apply WHATWG leniency. Backslashes are not converted; missing slashes are not inserted. If you need WHATWG joining, normalize the base first with url_parse_whatwg, then join.

What the canonicalizer does

url_canonicalize produces a normalized form. It lowercases the scheme and the host, strips the default port, resolves dot segments, and sets an empty path to /. It preserves double slashes inside the path, so /a//b stays /a//b.

Use the canonical form for cache keys, deduplication, or comparing two URLs for equality after normalization.

What the comparators do

url_same_host compares two hosts case-insensitively. Port is ignored.

url_same_origin compares scheme, host, and port. Port comparison uses the effective port, so http://a.com/ and http://a.com:80/ are the same origin. This is the correct check for the same-origin policy, for CSRF protection, and for cookie scoping.

What the scheme table does

url_scheme_lookup finds a scheme by name and returns a scheme_info with a default port and a flags byte. url_scheme_default_port is a convenience wrapper that returns just the port. url_scheme_is_tls returns 1 for schemes that are TLS by default (https, wss, ldaps, ftps, and a few others). url_scheme_allows_no_host returns 1 for schemes where a host is optional or absent (file, data, mailto, tel, and others).

url_schemes_load reads a config file and merges its entries into the built-in table. Return value is the number of schemes loaded, or a negative number if the file cannot be opened. A missing file is not fatal — the built-in table still works. Call once at startup. Not thread-safe during parsing.

What the IDNA does

When a host contains non-ASCII bytes, the parser calls the punycode encoder before returning. https://例え.jp/ becomes host = "xn--r8jz45g.jp". https://münchen.de/ becomes host = "xn--mnchen-3ya.de". The encoder applies RFC 3492 biasing and delta encoding.

The encoder uses a 512-byte thread-local scratch buffer. If the punycode form exceeds 512 bytes, the host is left unencoded. This is a known limitation. It does not apply NFC normalization before encoding, which RFC 3490 requires. In practice, browsers and most text sources produce NFC input already, so this only matters for unusual sources.

What the cache does

src/url_cache.c implements an LRU cache keyed on the raw URL bytes. It is not wired into url_parse. Reasons: the parser is already fast enough that a cache hit saves around 100 nanoseconds; the cache key has to be exact bytes so http://x.com and http://x.com/ are separate entries; and the parser has no natural hook for cache invalidation.

If a caller wants memoization, the cache functions are available. url_cache_new allocates a cache of a given maximum entry count. url_cache_get looks up a URL and returns a cached url_view if found. url_cache_put inserts a new entry. url_cache_set_max changes the maximum and evicts down. url_cache_free frees everything.

The cache is thread-safe for reads but not for concurrent writes. Use one cache per thread or wrap writes in a lock.

Error model

Every function returns a url_err. URL_OK is zero. Any other value is a specific failure. There are no silent failures, no bare -1, no errno reliance.

url_err_name returns a static string for any url_err. It never returns NULL. It is safe to call in log messages without a lookup table.

A caller that wants to handle every error writes a switch on the returned code. The common cases are: empty input, invalid characters, malformed scheme, scheme not allowed by flags, missing host, invalid host, invalid port, port out of range, input too long, join failed, and buffer too small.

Threading

url_parse, url_parse_ex, url_parse_whatwg, url_join, url_canonicalize, and the four url_build_* functions are safe to call from multiple threads concurrently, as long as no thread is calling url_schemes_load or url_schemes_unload at the same time.

url_join uses a thread-local scratch buffer for splicing. This is why it is thread-safe.

url_schemes_load and url_schemes_unload mutate a global table. They must be called once at startup, before any worker threads begin parsing.

The IDNA punycode path uses a 512-byte thread-local scratch buffer. Safe.

Performance

Measured on an ARM phone at 1.37 GHz: 581 nanoseconds per URL minimum, 630 nanoseconds mean, 1.72 million URLs per second. That is roughly 800 cycles per URL, including scheme detection, host lowercasing, IDNA check, port validation, and zero allocations.

For comparison, DNS resolution takes around 500,000 nanoseconds. URL parsing is not a bottleneck in any real pipeline.

What makes it fast: zero-copy views, SIMD-accelerated delimiter scanning (NEON on ARM, SSE2 on x86, scalar fallback elsewhere), single-pass parsing with no back-tracking, and small code that fits in L1 cache.

What would make it faster: nothing measurable. The parser is already several orders of magnitude faster than anything downstream.

Testing

Test sources live in tests/. url_join_tester.c covers the 45 RFC 3986 section 5.4 test cases. url_throughput_tester.c benchmarks repeated parses on a corpus. url_cache_tester.c exercises url_cache.c directly. url_dump.c prints parsed fields for a corpus file. scan_parity.c verifies that the SIMD scanner and the scalar scanner agree on every input.

Build and run any of them:

```
cd flywheel/url
make
cc -O2 -Iinclude tests/url_join_tester.c build/liburl.a -o tests/url_join_tester
./tests/url_join_tester
```

Output for the join tester is 45 passed, 0 failed.

Round-trip testing on 1211 real-world URLs from tests/corpus/real/all_urls.txt gives 100 percent field match across scheme, host, port, path, query, and fragment.

Corpus

The corpus lives in tests/corpus/. Each file exercises a different shape of input.

simple.txt has basic URLs. typical.txt has common real-world shapes. edge.txt has edge cases and intentional rejects. invalid.txt has inputs that must fail. ipv6.txt has bracketed IPv6 hosts. unicode.txt has IDN and IDNA cases. long.txt has very long inputs. repeat.txt is a throughput target with repeated URLs. real/all_urls.txt is 1211 URLs harvested from real pages. real/example.html is the source page.

To add a new test case, append a line to the relevant corpus file. The test harness reads the corpus at run time and prints OK or ERR per line. No code changes are needed to add a new case.

License

Internal. Not for redistribution.


