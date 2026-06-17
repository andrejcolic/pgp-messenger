"""
Module: radix64.py
Description: This module provides implementation of radix-64 conversion.
Author: Igor
Date: 17/06/2026.
"""

import base64

def convert_to_radix64(data: bytes) -> bytes:
    return base64.b64encode(data)

def convert_to_radix64_str(data: bytes) -> str:
    data = base64.b64encode(data)
    return data.decode('utf-8')

def convert_from_radix64(data: str | bytes) -> bytes:
    data = base64.b64decode(data)
    return data