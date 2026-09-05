import ssl

context = ssl.create_default_context()
context.set_ciphers("TLS_RSA_WITH_AES_256_GCM_SHA384")
