from __future__ import annotations

import socket
import ssl
from typing import Any, cast


def inspect_tls(host: str, *, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
    if not host or any(character.isspace() for character in host):
        raise ValueError("host must be a non-empty DNS name or IP address")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not 0.1 <= timeout <= 30:
        raise ValueError("timeout must be between 0.1 and 30 seconds")
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with context.wrap_socket(raw, server_hostname=host) as secured:
            cipher = secured.cipher()
            certificate = cast(dict[str, Any], secured.getpeercert() or {})
            return {
                "schema_version": 1,
                "endpoint": {"host": host, "port": port},
                "transport": {
                    "tls_version": secured.version(),
                    "cipher": cipher[0] if cipher else None,
                    "symmetric_bits": cipher[2] if cipher else None,
                },
                "authentication": {
                    "certificate_subject": _name(certificate.get("subject", ())),
                    "certificate_issuer": _name(certificate.get("issuer", ())),
                    "signature_algorithm": "UNKNOWN",
                    "note": "Python stdlib does not expose the certificate signature OID; QuantumGuard does not infer it from the cipher suite.",
                },
                "key_establishment": {
                    "algorithm": "UNKNOWN",
                    "note": "The negotiated TLS cipher name does not reliably prove the TLS 1.3 key-share group.",
                },
                "pqc_readiness": "UNKNOWN",
                "limitations": [
                    "One bounded TLS handshake only; no application data is sent.",
                    "Hybrid/PQ key-share visibility requires a lower-level handshake parser and is not claimed by this result.",
                    "A modern TLS version or symmetric cipher does not by itself prove post-quantum readiness.",
                ],
            }


def _name(values: tuple[Any, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for group in values:
        for key, value in group:
            result[str(key)] = str(value)
    return result
