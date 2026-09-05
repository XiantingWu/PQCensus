import ssl

context = ssl.create_default_context()
context.set_ciphers("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
