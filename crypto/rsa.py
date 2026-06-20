"""
Module: rsa.py
Description: This module provides RSA operations: key-pair generation, session-key
             encryption/decryption and message signing/verification (SHA-1).
Author: Andrej
Date: 20/06/2026.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from config import SymmetricAlgorithm
from crypto import symmetric_algorithms
from crypto.hashing import hash_function


def generate_keys(key_size=2048):
    private_key = generate_private_key(public_exponent=65537, key_size=key_size)
    
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode("utf-8")
    
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return private_pem, public_pem


def get_key_id(public_pem):
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    return format(public_key.public_numbers().n % (2 ** 64), "016X")


def encrypt(public_pem, data):
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    return public_key.encrypt(data, padding.PKCS1v15())


def decrypt(private_pem, data):
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    return private_key.decrypt(data, padding.PKCS1v15())


def sign(private_pem, data):
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA1())


def verify(public_pem, signature, data):
    public_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        return True
    except InvalidSignature:
        return False


def protect_private_key(private_pem, password):
    key = hash_function(password.encode("utf-8"))[:16]
    iv = symmetric_algorithms.generate_iv(SymmetricAlgorithm.AES128.value)
    encrypted = symmetric_algorithms.encrypt(
        SymmetricAlgorithm.AES128.value, private_pem.encode("utf-8"), key, iv
    )
    return encrypted, iv


def export_pem(pem, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(pem)


def import_public_pem(path):
    with open(path, "r", encoding="utf-8") as f:
        pem = f.read()
    serialization.load_pem_public_key(pem.encode("utf-8"))
    return pem


def import_private_pem(path):
    with open(path, "r", encoding="utf-8") as f:
        pem = f.read()
    serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    return pem