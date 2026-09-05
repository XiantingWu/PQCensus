import jwt

token = jwt.encode({"sub": "123"}, private_key, algorithm="RS256")
