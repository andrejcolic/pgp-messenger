"""
pip install -r requirements.txt
"""

from enum import Enum

class SymmetricAlgorithm(Enum):
    TRIPLE_DES = "TripleDES"
    AES128 = "AES128"