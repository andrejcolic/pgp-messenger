"""
Module: radix64.py
Description: This module provides implementation of radix-64 conversion.
Author: Igor
Date: 17/06/2026.
"""

import base64
import binascii

def convert_to_radix64(data: bytes) -> bytes:
    """
        Encodes data into Radix64 format.
    """
    return base64.b64encode(data)

def is_valid_radix64(data: str | bytes) -> bool:
    """
    Check if data is valid Radix64 format.
    """
    if isinstance(data, bytes):
        try:
            data = data.decode('ascii')
        except UnicodeDecodeError:
            return False
    

    base65_alphabet = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    return all(c in base65_alphabet for c in data)

def convert_from_radix64(data: str | bytes) -> bytes:
    """
    Decode Radix64 data.
    Raises ValueError if data is not in valid format.
    """
    error_msg = ("Datoteka nije u Radix64 formatu.\n"
                 "Uverite se da je pri generisanju izabrana opcija \'Radix-64\'")
    try:
        if not is_valid_radix64(data):
            raise ValueError (error_msg)
        decoded = base64.b64decode(data)
        return decoded
    except (binascii.Error, ValueError) as e:
        if "Incorrect padding" in str(e) or "Invalid base64-encoded string" in str(e):
            raise ValueError(error_msg) from e
        raise
