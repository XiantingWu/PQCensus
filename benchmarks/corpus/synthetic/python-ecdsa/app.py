from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

signature_algorithm = ec.ECDSA(hashes.SHA256())
