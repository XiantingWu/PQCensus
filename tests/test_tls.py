from __future__ import annotations

import socket
import ssl

import pytest

from quantumguard.tls import inspect_tls


@pytest.mark.parametrize(
    ("host", "port", "timeout", "message"),
    [
        ("", 443, 5.0, "non-empty"),
        ("bad host", 443, 5.0, "non-empty"),
        ("example.com", 0, 5.0, "between 1 and 65535"),
        ("example.com", 65536, 5.0, "between 1 and 65535"),
        ("example.com", 443, 0.0, "between 0.1 and 30"),
        ("example.com", 443, 31.0, "between 0.1 and 30"),
    ],
)
def test_tls_input_validation(host: str, port: int, timeout: float, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        inspect_tls(host, port=port, timeout=timeout)


def test_tls_handshake_reports_only_observable_transport_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeRaw:
        timeout: float | None = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

    class FakeSecured:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self):
            return {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("commonName", "Example CA"),),),
            }

        def version(self):
            return "TLSv1.3"

    raw = FakeRaw()
    secured = FakeSecured()

    class FakeContext:
        def wrap_socket(self, raw_socket, *, server_hostname: str):
            assert raw_socket is raw
            assert server_hostname == "example.com"
            return secured

    def fake_connection(address, *, timeout: float):
        assert address == ("example.com", 8443)
        assert timeout == 2.5
        return raw

    monkeypatch.setattr(socket, "create_connection", fake_connection)
    monkeypatch.setattr(ssl, "create_default_context", lambda: FakeContext())

    report = inspect_tls("example.com", port=8443, timeout=2.5)
    assert raw.timeout == 2.5
    assert report["transport"] == {
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "symmetric_bits": 256,
    }
    assert report["authentication"]["certificate_subject"] == {"commonName": "example.com"}
    assert report["authentication"]["certificate_issuer"] == {"commonName": "Example CA"}
    assert report["authentication"]["signature_algorithm"] == "UNKNOWN"
    assert report["key_establishment"]["algorithm"] == "UNKNOWN"
    assert report["pqc_readiness"] == "UNKNOWN"
    assert any("does not by itself prove" in item for item in report["limitations"])


def test_tls_missing_cipher_and_certificate_names_are_handled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Resource:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def settimeout(self, timeout: float) -> None:
            pass

        def cipher(self):
            return None

        def getpeercert(self):
            return {}

        def version(self):
            return None

        def wrap_socket(self, raw_socket, *, server_hostname: str):
            return self

    resource = Resource()
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: resource)
    monkeypatch.setattr(ssl, "create_default_context", lambda: resource)
    report = inspect_tls("127.0.0.1")
    assert report["transport"]["cipher"] is None
    assert report["transport"]["symmetric_bits"] is None
    assert report["authentication"]["certificate_subject"] == {}
