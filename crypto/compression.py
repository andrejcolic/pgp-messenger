"""
Module: compression.py
Description: This module provides implementation of compression, ZLIB algorithm.
Author: Igor
Date: 17/06/2026.
"""

import zlib

def compress(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    return zlib.decompress(data)


"""
def compress2(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=zlib.Z_DEFAULT_COMPRESSION, wbits=-15)
    return compressor.compress(data) + compressor.flush()

def decompress2(data: bytes) -> bytes:
    decompressor = zlib.decompressobj(wbits=-15)
    return decompressor.decompress(data) + decompressor.flush()
"""


def test():
    data = b"""
            Hello world! Testing compression algorithm ZLIB.
            Module: compression.py
            Description: This module provides implementation of compression, ZLIB algorithm.
            Author: Igor
            Date: 17/06/2026.
            """


    compressed_data = compress(data)
    #compressed_data2 = compress2(data)
    decompressed_data = decompress(compressed_data)

    print("RAW DATA SIZE:", len(data))
    print("COMPRESSED DATA SIZE:", len(compressed_data))
    #print("COMPRESSED DATA 2 SIZE:", len(compressed_data2))
    print("DECOMPRESSED DATA SIZE:", len(decompressed_data))
    print("COMPRESSED DATA:", compressed_data.hex())
    print("DECOMPRESSED DATA:", decompressed_data.decode(errors="ignore"))


test()