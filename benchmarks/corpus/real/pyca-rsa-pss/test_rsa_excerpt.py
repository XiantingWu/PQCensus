# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See benchmarks/THIRD_PARTY_NOTICES.md.

from cryptography.hazmat.primitives.asymmetric import padding


def test_pss_sha2_max_length(rsa_key_2048, hash_alg, backend):
    private_key = rsa_key_2048
    public_key = private_key.public_key()
    pss = padding.PSS(
        mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH
    )
    msg = b"testing signature"
    signature = private_key.sign(msg, pss, hash_alg)
    public_key.verify(signature, msg, pss, hash_alg)
