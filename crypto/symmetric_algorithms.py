"""
Module: symmetric_algorithms.py
Description: This module provides implementation of 3DES and AES128.
Author: Igor
Date: 17/06/2026.
"""

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES128
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.decrepit.ciphers import modes
from cryptography.hazmat.primitives.ciphers import Cipher

from config import SymmetricAlgorithm

def _pad(data: bytes, block_size: int) -> bytes:
    padder = padding.PKCS7(block_size).padder()
    return padder.update(data) + padder.finalize()


def _unpad(data: bytes, block_size: int) -> bytes:
    unpadder = padding.PKCS7(block_size).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt_3des(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    algorithm = TripleDES(key)
    mode = modes.CFB(iv)
    encryptor = Cipher(algorithm,mode=mode).encryptor()
    return encryptor.update(plaintext)

def decrypt_3des(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    algorithm = TripleDES(key)
    mode = modes.CFB(iv)
    decryptor = Cipher(algorithm, mode=mode).decryptor()
    return decryptor.update(ciphertext)

def encrypt_aes128(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    algorithm = AES128(key)
    mode = modes.CFB(iv)
    encryptor = Cipher(algorithm,mode=mode).encryptor()
    return encryptor.update(plaintext)

def decrypt_aes128(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    algorithm = AES128(key)
    mode = modes.CFB(iv)
    decryptor = Cipher(algorithm,mode=mode).decryptor()
    return decryptor.update(ciphertext)

_ALGOS = {
    "TripleDES": { "encrypt": encrypt_3des, "decrypt": decrypt_3des , "iv_size": 8},
    "AES128": { "encrypt": encrypt_aes128, "decrypt": decrypt_aes128 , "iv_size": 16}
}

def generate_iv(algorithm: str) -> bytes:
    return os.urandom(_ALGOS[algorithm]["iv_size"])

def encrypt(algorithm: str, plaintext: str | bytes, key: str | bytes, iv: bytes) -> bytes:
    if algorithm not in _ALGOS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return _ALGOS[algorithm]["encrypt"](bytes(plaintext), bytes(key), iv)


def decrypt(algorithm: str, ciphertext: str | bytes, key: str | bytes, iv: bytes) -> bytes:
    if algorithm not in _ALGOS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return _ALGOS[algorithm]["decrypt"](bytes(ciphertext), bytes(key), iv)



def test():
    msg = b"""
            Hello world! Testing symmetric algorithms: 3DES and AES128.
            Module: symmetric_algorithms.py
            Description: This module provides implementation of 3DES and AES128.
            Author: Igor
            Date: 17/06/2026.
            """


    key_3des = b"12345678ABCDEFGH87654321"  # 24 bytes (3 x 8 bytes)
    key_aes128 = b"1234567890ABCDEF"  # 16 bytes

    iv_3des = generate_iv(SymmetricAlgorithm.TRIPLE_DES.value)
    iv_aes128 = generate_iv(SymmetricAlgorithm.AES128.value)

    des = encrypt(SymmetricAlgorithm.TRIPLE_DES.value, _pad(msg,64), key_3des, iv_3des)
    aes = encrypt(SymmetricAlgorithm.AES128.value, _pad(msg,128), key_aes128, iv_aes128)
    print("CODED:")
    print(des.decode(errors="ignore"))
    print(aes.decode(errors="ignore"))
    des = decrypt(SymmetricAlgorithm.TRIPLE_DES.value, des, key_3des, iv_3des)
    aes = decrypt(SymmetricAlgorithm.AES128.value, aes, key_aes128, iv_aes128)
    des = _unpad(des, 64)
    aes = _unpad(aes, 128)
    print("DECODED:")
    print(des.decode(errors="ignore"))
    print(aes.decode(errors="ignore"))


if __name__ == "__main__":
    test()