import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat import backends


def build_cipher(key: bytes, iv: bytes, alg: str, mode: str) -> Cipher:
    """
    Builds a Cipher object used by both encryption and decryption functions.
    """

    # Dictionary that maps supported and enabled algorithms names to it's classes and key sizes.
    # The lib cryptography doesn't differentiate algorithms based on the key size,
    # it's just a matter of passing the desired key size to it.
    enabled_algorithms = {
        'AES128':    {'class': algorithms.AES,       'key_size': 128},
        'AES192':    {'class': algorithms.AES,       'key_size': 192},
        'AES256':    {'class': algorithms.AES,       'key_size': 256},
        'DES':       {'class': algorithms.TripleDES, 'key_size': 64},  # as k1, k2, and k3 are the same, it becomes a simple DES (https://en.wikipedia.org/wiki/Triple_DES#Keying_options)
        '3DES-EDE2': {'class': algorithms.TripleDES, 'key_size': 128},
        '3DES-EDE3': {'class': algorithms.TripleDES, 'key_size': 192},
    }

    # Dictionary that maps supported and enabled modes names to it's classes.
    enabled_modes = {
        'ECB': modes.ECB,
        'CBC': modes.CBC,
        # 'CFB1': None,
        'CFB8': modes.CFB8,
        # 'CFB64': None,
        # 'CFB128': None,
        'CTR': modes.CTR,
    }

    # Gets the algorithm and mode.
    alg_obj = enabled_algorithms[alg]
    mode_obj = enabled_modes[mode]

    # Check if the key size is the right one as cryptography lib doesn't differentiate it.
    assert len(key) * 8 == alg_obj['key_size'], 'wrong key size'

    # Creates the Cipher object with a default cryptography backend.
    return Cipher(alg_obj['class'](key), mode_obj(iv), backend=backends.default_backend())


def encrypt(data: bytes, key: bytes, iv: bytes, alg: str, mode: str, pkcs5: bool) -> bytes:
    """
    Uses a Cipher object to encrypt a data.
    """

    # Pad a data with PKCS5
    if pkcs5:
        data = padder_pkcs5(data)

    cipher = build_cipher(key, iv, alg, mode)
    encryptor = cipher.encryptor()

    return encryptor.update(data) + encryptor.finalize()


def decrypt(data: bytes, key: bytes, iv: bytes, alg: str, mode: str, pkcs5: bool) -> bytes:
    """
    Uses a Cipher object to decrypt a data.
    """

    # Unpad a PKCS5 padded data.
    if pkcs5:
        data = unpadder_pkcs5(data)

    cipher = build_cipher(key, iv, alg, mode)
    decryptor = cipher.decryptor()

    return decryptor.update(data) + decryptor.finalize()


def padder_pkcs5(data: bytes) -> bytes:
    """
    PKCS7 is a generalization of PKCS5, allowing a wide range of block sizes,
    then we can just use it with block size 128 bits.
    """

    # Pads with PKCS7 using 128 bits block size.
    p = PKCS7(128).padder()
    return p.update(data) + p.finalize()


def unpadder_pkcs5(data: bytes) -> bytes:
    """
    PKCS7 is a generalization of PKCS5, allowing a wide range of block sizes,
    then we can just use it with block size 128 bits.
    """

    # Unpads a PKCS7-padded data.
    p = PKCS7(128).unpadder()
    return p.update(data) + p.finalize()

