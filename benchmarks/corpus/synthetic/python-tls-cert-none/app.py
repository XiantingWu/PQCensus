import ssl

context = ssl.create_default_context()
context.verify_mode = ssl.CERT_NONE
