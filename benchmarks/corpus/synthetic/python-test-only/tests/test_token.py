import jwt

token = jwt.encode({"sub": "fixture"}, private_key, algorithm="RS256")
