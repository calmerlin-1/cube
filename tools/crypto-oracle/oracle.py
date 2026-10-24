#!/usr/bin/env python3
"""crypto-oracle — reference implementation oracle for crisptls crypto.

Run from repo root. Produces expected outputs that C implementations must match.

Usage:
    python3 tools/crypto-oracle/oracle.py

Outputs are stable across runs — commit this script and its expected values
as the authoritative source of truth.
"""

import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import poly1305, hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def hx(b): return b.hex()

def section(name):
    print()
    print('=' * 70)
    print(name)
    print('=' * 70)

# ---------- Poly1305 ----------
section('Poly1305 (RFC 8439 §2.5.2)')
key = bytes.fromhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
msg = b'Cryptographic Forum Research Group'
print('msg len:', len(msg))
print('TAG:', poly1305.Poly1305.generate_tag(key, msg).hex())

# ---------- ChaCha20-Poly1305 AEAD ----------
section('ChaCha20-Poly1305 (RFC 8439 §2.8.2)')
k = bytes.fromhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
iv = bytes.fromhex('070000004041424344454647')
aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
r = ChaCha20Poly1305(k).encrypt(iv, pt, aad)
print('pt len:', len(pt))
print('aad len:', len(aad))
print('CT:', hx(r[:-16]))
print('TAG:', hx(r[-16:]))

# Also show the Poly1305 input structure that must produce this TAG
# Poly key = first 32 bytes of ChaCha20 block 0
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
chacha = Cipher(algorithms.ChaCha20(k, iv + b'\x00\x00\x00\x00'), mode=None).encryptor()
block0 = chacha.update(b'\x00' * 64)
poly_key = block0[:32]
print('Poly key:', hx(poly_key))

# Build poly input per RFC 8439 §2.8
def pad16(b):
    r = len(b) % 16
    return b if r == 0 else b + b'\x00' * (16 - r)
poly_input = pad16(aad) + pad16(r[:-16]) + len(aad).to_bytes(8, 'little') + len(pt).to_bytes(8, 'little')
print('Poly input len:', len(poly_input))
print('Poly1305(poly_key, poly_input):', poly1305.Poly1305.generate_tag(poly_key, poly_input).hex())
print('  (should match TAG above)')

# ---------- AES-GCM ----------
section('AES-128-GCM (NIST TC2)')
k = bytes(16); iv = bytes(12); pt = bytes(16); aad = bytes(16)
r = AESGCM(k).encrypt(iv, pt, aad)
print('CT:', hx(r[:-16]))
print('TAG:', hx(r[-16:]))

section('AES-128-GCM (NIST TC4)')
k = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
iv = bytes.fromhex('cafebabefacedbaddecaf888')
pt = bytes.fromhex('d9313225f88406e5a55909c5aff5269a')
r = AESGCM(k).encrypt(iv, pt, None)
print('CT:', hx(r[:-16]))
print('TAG:', hx(r[-16:]))

section('AES-256-GCM (NIST TC16)')
k = bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
iv = bytes.fromhex('cafebabefacedbaddecaf888')
pt = bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
                   '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
r = AESGCM(k).encrypt(iv, pt, None)
print('pt len:', len(pt))
print('CT:', hx(r[:-16]))
print('TAG:', hx(r[-16:]))

# ---------- HMAC-SHA256 ----------
section('HMAC-SHA256 (RFC 4231 TC1)')
key = b'\x0b' * 20
msg = b'Hi There'
h = crypto_hmac.HMAC(key, hashes.SHA256())
h.update(msg)
print('TAG:', h.finalize().hex())

# ---------- HMAC-SHA384 ----------
section('HMAC-SHA384 (RFC 4231 TC1)')
h = crypto_hmac.HMAC(key, hashes.SHA384())
h.update(msg)
print('TAG:', h.finalize().hex())

# ---------- HKDF-SHA256 ----------
section('HKDF-SHA256 (RFC 5869 TC1)')
ikm = b'\x0b' * 22
salt = bytes(range(13))
info = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
hk = HKDF(algorithm=hashes.SHA256(), length=42, salt=salt, info=info)
okm = hk.derive(ikm)
print('OKM:', hx(okm))

# ---------- SHA-256 ----------
section('SHA-256 (FIPS 180-4)')
from cryptography.hazmat.primitives import hashes as c_hashes
d = c_hashes.Hash(c_hashes.SHA256())
d.update(b'abc')
print('SHA-256(abc):', d.finalize().hex())

# ---------- SHA-384 ----------
section('SHA-384 (FIPS 180-4)')
d = c_hashes.Hash(c_hashes.SHA384())
d.update(b'abc')
print('SHA-384(abc):', d.finalize().hex())

# ---------- SHA-512 ----------
section('SHA-512 (FIPS 180-4)')
d = c_hashes.Hash(c_hashes.SHA512())
d.update(b'abc')
print('SHA-512(abc):', d.finalize().hex())

# ---------- MD5 ----------
section('MD5 (RFC 1321)')
d = c_hashes.Hash(c_hashes.MD5())
d.update(b'abc')
print('MD5(abc):', d.finalize().hex())

# ---------- AES-128-ECB block ----------
section('AES-128-ECB (NIST SP 800-38A F.1.1 block 1)')
key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
print('CT:', hx(cipher.update(pt) + cipher.finalize()))

# ---------- AES-256-ECB block ----------
section('AES-256-ECB (NIST F.1.5 block 1)')
key = bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
print('CT:', hx(cipher.update(pt) + cipher.finalize()))

print()
print('=' * 70)
print('END OF ORACLE OUTPUT — any C test must match these values')
print('=' * 70)
