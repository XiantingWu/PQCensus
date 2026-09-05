import hashlib
import hmac

tag = hmac.new(key, message, hashlib.sha256)
