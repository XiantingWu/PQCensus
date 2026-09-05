# Copyright (c) 2015-2022 Jose Padilla. MIT licensed.
# See benchmarks/THIRD_PARTY_NOTICES.md.

from jwt.algorithms import has_crypto
from jwt.api_jws import PyJWS


def test_rsa_related_algorithms() -> None:
    jws = PyJWS()
    jws_algorithms = jws.get_algorithms()
    if has_crypto:
        assert "RS256" in jws_algorithms
        assert "RS384" in jws_algorithms
        assert "RS512" in jws_algorithms
