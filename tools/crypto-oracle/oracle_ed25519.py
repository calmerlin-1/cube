#!/usr/bin/env python3
"""Ed25519 verify test vectors — RFC 8032 §7.1."""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def hx(b): return b.hex()
def section(n):
    print(); print('=' * 70); print(n); print('=' * 70)

section('Ed25519 — RFC 8032 §7.1 Test 1 (empty message)')

# Test 1: empty message
secret_key = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
pub = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
sig = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                    '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
msg = b''

print('pub    :', hx(pub))
print('msg    :', hx(msg))
print('sig    :', hx(sig))

# Verify with cryptography
try:
    ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
    print('verify : PASS')
except InvalidSignature:
    print('verify : FAIL — RFC vector invalid')

section('Ed25519 — RFC 8032 §7.1 Test 2 (1-byte message)')
pub = bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
sig = bytes.fromhex('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
                    '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
msg = b'\x72'
print('pub    :', hx(pub))
print('msg    :', hx(msg))
print('sig    :', hx(sig))
try:
    ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
    print('verify : PASS')
except InvalidSignature:
    print('verify : FAIL')

section('Ed25519 — tampered (must reject)')
pub = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
sig_bad = bytes.fromhex('f5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                        '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
try:
    ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig_bad, b'')
    print('verify : FAIL — should have rejected')
except InvalidSignature:
    print('verify : PASS (tampered sig rejected)')
