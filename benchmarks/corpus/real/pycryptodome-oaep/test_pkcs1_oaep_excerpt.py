# This source excerpt is dedicated to the public domain. If that dedication
# is unavailable, its upstream fallback license grants unrestricted use.
# See benchmarks/THIRD_PARTY_NOTICES.md.

from Crypto.Cipher import PKCS1_OAEP as PKCS


def test_encrypt_too_long(key1024, plaintext):
    cipher = PKCS.new(key1024)
    cipher.encrypt(plaintext)
