from cryptography.hazmat.primitives.asymmetric import x25519


def legacy_peer_compatibility(peer_public_bytes: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.generate()
    peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_key)
