/**
 * scan.h — portable byte scanning for the URL parser.
 *
 * Implementations live in scan_<arch>.h. One is selected at compile
 * time based on target architecture. All implementations expose the
 * same four static inline functions:
 *
 *     scan_bad_char  scan_find  scan_find_any4  scan_all_scheme
 *
 * Contract for every function: return the index of the first matching
 * byte, or n if none matched.
 *
 * scan_scalar.h is the reference — every architecture-specific version
 * must agree with it byte-for-byte on the same input.
 *
 * To add an architecture:
 *   1. copy scan_scalar.h to scan_<arch>.h
 *   2. replace loop bodies with intrinsics, keeping the same contract
 *   3. add a #elif branch below
 *   4. add a parity test comparing both versions on a corpus
 */

#ifndef FLYWHEEL_URL_SCAN_H
#define FLYWHEEL_URL_SCAN_H

#include <stddef.h>

#if defined(__ARM_NEON) && defined(__aarch64__)
  #include "scan_neon.h"
#elif defined(__SSE2__) && (defined(__x86_64__) || defined(__i386__))
  #include "scan_sse2.h"
#else
  #include "scan_scalar.h"
#endif

#endif /* FLYWHEEL_URL_SCAN_H */
