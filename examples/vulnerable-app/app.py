import ssl

import jwt
from cryptography.hazmat.primitives.asymmetric import x25519


def sign_access_token(payload: dict, private_key: str) -> str:
    return jwt.encode(payload, private_key, algorithm="RS256")


def establish_session(peer_public_bytes: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.generate()
    peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_key)


tls_context = ssl.create_default_context()
