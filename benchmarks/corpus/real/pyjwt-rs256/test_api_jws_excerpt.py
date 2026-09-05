# Copyright (c) 2015-2022 Jose Padilla. MIT licensed.
# See benchmarks/THIRD_PARTY_NOTICES.md.

import pytest

from jwt.api_jws import PyJWS


def test_missing_crypto_library_better_error_messages(jws: PyJWS, payload: bytes) -> None:
    with pytest.raises(NotImplementedError) as excinfo:
        jws.encode(payload, "secret", algorithm="RS256")
        assert "cryptography" in str(excinfo.value)
