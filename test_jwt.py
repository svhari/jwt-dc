# test_jwt.py
#
# example that demonstrates how JWT encodes your information
# 15 Jan 2024

from jose import jwt

data = {"username": "sam", "admin": True}
encoded_jwt = jwt.encode(data, key="secret-key")
print(encoded_jwt)
decoded_jwt = jwt.decode(encoded_jwt, key="secret-key")
print(decoded_jwt)