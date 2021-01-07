import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat import backends



'''
padder = PKCS7(128).padder()
padded_data = padder.update(b"11111111111111112222222222") + padder.finalize()

unpadder = PKCS7(128).unpadder()
data = unpadder.update(padded_data) + unpadder.finalize()


iv = os.urandom(16)
algorithm = algorithms.AES(key)
mode = modes.CBC(iv)
cipher = Cipher(algorithm, mode, backend=backends.default_backend())


encryptor = cipher.encryptor()
ctx = encryptor.update(b"a secret message") + encryptor.finalize()


decryptor = cipher.decryptor()
decryptor.update(ctx) + decryptor.finalize()
'''
