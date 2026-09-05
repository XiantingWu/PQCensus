import jwt


def sign_access_token(payload, private_key):
    return jwt.encode(payload, private_key, algorithm="RS256")
