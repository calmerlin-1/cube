#!/usr/bin/env python3
"""ECDSA-P256 test vectors for crisptls crypto-oracle — RFC 6979 A.2.5."""

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
import hashlib

def hx(b): return b.hex()
def section(n):
    print()
    print('=' * 70)
    print(n)
    print('=' * 70)

section('ECDSA-P256-SHA256 — RFC 6979 A.2.5 "sample"')

# RFC 6979 A.2.5 — P-256, SHA-256, "sample"
pub_x = bytes.fromhex('60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6')
pub_y = bytes.fromhex('7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299')
pub = ec.EllipticCurvePublicNumbers(
    int.from_bytes(pub_x, 'big'), int.from_bytes(pub_y, 'big'),
    ec.SECP256R1()).public_key()

msg = b'sample'
msg_hash = hashlib.sha256(msg).digest()

expected_r = 'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716'
expected_s = 'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8'

print('pub_x     :', hx(pub_x))
print('pub_y     :', hx(pub_y))
print('msg       :', hx(msg))
print('sha256    :', hx(msg_hash))
print('r         :', expected_r)
print('s         :', expected_s)

# Verify with cryptography (sanity)
der_sig = utils.encode_dss_signature(int(expected_r, 16), int(expected_s, 16))
try:
    pub.verify(der_sig, msg, ec.ECDSA(hashes.SHA256()))
    print('verify    : PASS (oracle confirms)')
except InvalidSignature:
    print('verify    : FAIL — RFC vector invalid')

# SPKI DER for the public key
spki_der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
print('spki_der  :', hx(spki_der))
print('spki_len  :', len(spki_der))

# DER-encoded ECDSA-Sig-Value
print('sig_der   :', hx(der_sig))
print('sig_der_len:', len(der_sig))
