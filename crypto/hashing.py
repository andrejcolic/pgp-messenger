"""
Module: hashing.py
Description: This module provides implementation of SHA-1.
Author: Igor
Date: 17/06/2026.
"""
import hashlib

from cryptography.hazmat.primitives import hashes

def hash_function(data: bytes | str) -> bytes:
    """
    :param data: block_size 8 bytes
    :return:
    """
    digest = hashes.Hash(hashes.SHA1())
    digest.update(data)
    return digest.finalize()


def test():
    data = b"""
            Hello world! Testing hash algorithm SHA-1.
            Module: hashing.py
            Description: This module provides implementation of SHA-A.
            Author: Igor
            Date: 17/06/2026.
            """
    hashed_data = hash_function(data)
    print(f"DATA: {data.decode(errors="ignore")}")
    print(f"HASHED DATA: {hashed_data.hex()}")


if __name__ == "__main__":
    test()