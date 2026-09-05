# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See benchmarks/THIRD_PARTY_NOTICES.md.

import binascii

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


def test_rfc7748(vector, backend):
    private = binascii.unhexlify(vector["input_scalar"])
    public = binascii.unhexlify(vector["input_u"])
    shared_key = binascii.unhexlify(vector["output_u"])
    private_key = X25519PrivateKey.from_private_bytes(private)
    public_key = X25519PublicKey.from_public_bytes(public)
    computed_shared_key = private_key.exchange(public_key)
    assert computed_shared_key == shared_key
