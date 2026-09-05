import ssl

context = ssl.create_default_context()
context.check_hostname = False
