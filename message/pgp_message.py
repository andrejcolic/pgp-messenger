"""
Module: pgp_message.py
Description: PGP message structure and its binary (de)serialization.
"""

from dataclasses import dataclass


def _pack_with_length(data: bytes, length_size: int) -> bytes:
    return len(data).to_bytes(length_size, "big") + data


def _unpack_with_length(data: bytes, offset: int, length_size: int) -> tuple[bytes, int]:
    length = int.from_bytes(data[offset:offset + length_size], "big")
    offset += length_size
    value = data[offset:offset + length]
    return value, offset + length


def key_id_to_bytes(key_id: str) -> bytes:
    return bytes.fromhex(key_id)


def key_id_from_bytes(data: bytes) -> str:
    return data.hex().upper()


@dataclass
class SignatureComponent:
    """Timestamp || sender key ID || leading two octets || RSA-encrypted SHA-1 digest."""
    timestamp: int
    sender_key_id: str
    leading_two_octets: bytes      # first 2 bytes of the SHA-1 digest, in the clear
    encrypted_digest: bytes

    def to_bytes(self) -> bytes:
        if len(self.leading_two_octets) != 2:
            raise ValueError("leading_two_octets must be exactly 2 bytes")
        out = bytearray()
        out += self.timestamp.to_bytes(4, "big")
        out += key_id_to_bytes(self.sender_key_id)
        out += self.leading_two_octets
        out += _pack_with_length(self.encrypted_digest, length_size=2)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["SignatureComponent", bytes]:
        offset = 0
        timestamp = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        sender_key_id = key_id_from_bytes(data[offset:offset + 8])
        offset += 8
        leading_two_octets = data[offset:offset + 2]
        offset += 2
        encrypted_digest, offset = _unpack_with_length(data, offset, length_size=2)
        return cls(timestamp, sender_key_id, leading_two_octets, encrypted_digest), data[offset:]


@dataclass
class MessageComponent:
    """Filename || Timestamp || Data."""
    filename: str
    timestamp: int
    data: bytes

    def to_bytes(self) -> bytes:
        out = bytearray()
        out += _pack_with_length(self.filename.encode("utf-8"), length_size=1)
        out += self.timestamp.to_bytes(4, "big")
        out += _pack_with_length(self.data, length_size=4)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple["MessageComponent", bytes]:
        offset = 0
        filename_bytes, offset = _unpack_with_length(data, offset, length_size=1)
        timestamp = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        message_data, offset = _unpack_with_length(data, offset, length_size=4)
        return cls(filename_bytes.decode("utf-8"), timestamp, message_data), data[offset:]


class _Flags:
    CONFIDENTIALITY = 0x01
    AUTHENTICATION = 0x02
    COMPRESSION = 0x04


@dataclass
class PGPMessage:
    """
    Full PGP message ready to be written to a file (before optional radix-64).

    Binary format of to_bytes():
        [1 B]      flags (bit0 confidentiality, bit1 authentication, bit2 compression)
        if confidentiality:
            [8 B]      recipient_key_id      (recipient's Key ID)
            [1 B + N]  symmetric_algorithm   (length-prefixed UTF-8 string)
            [2 B + M]  encrypted_session_key (length-prefixed RSA ciphertext)
            [1 B + K]  iv                    (length-prefixed)
        [4 B + L]  payload (optionally compressed/encrypted signature + message)
    """
    confidentiality: bool = False
    authentication: bool = False
    compression: bool = False
    symmetric_algorithm: str | None = None
    encrypted_session_key: bytes | None = None
    recipient_key_id: str | None = None
    iv: bytes | None = None
    payload: bytes = b""

    def to_bytes(self) -> bytes:
        flags = 0
        if self.confidentiality:
            flags |= _Flags.CONFIDENTIALITY
        if self.authentication:
            flags |= _Flags.AUTHENTICATION
        if self.compression:
            flags |= _Flags.COMPRESSION

        out = bytearray([flags])

        if self.confidentiality:
            if (self.symmetric_algorithm is None
                    or self.encrypted_session_key is None
                    or self.iv is None):
                raise ValueError("confidentiality requires symmetric_algorithm, "
                                 "encrypted_session_key and iv")
            out += key_id_to_bytes(self.recipient_key_id)
            out += _pack_with_length(self.symmetric_algorithm.encode("utf-8"), length_size=1)
            out += _pack_with_length(self.encrypted_session_key, length_size=2)
            out += _pack_with_length(self.iv, length_size=1)

        out += _pack_with_length(self.payload, length_size=4)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PGPMessage":
        if not data:
            raise ValueError("Empty input — cannot parse PGP message")

        offset = 0
        flags = data[offset]
        offset += 1

        confidentiality = bool(flags & _Flags.CONFIDENTIALITY)
        authentication = bool(flags & _Flags.AUTHENTICATION)
        compression = bool(flags & _Flags.COMPRESSION)

        symmetric_algorithm = None
        encrypted_session_key = None
        iv = None
        recipient_key_id = None

        if confidentiality:
            recipient_key_id = key_id_from_bytes(data[offset:offset + 8])
            offset += 8
            alg_bytes, offset = _unpack_with_length(data, offset, length_size=1)
            symmetric_algorithm = alg_bytes.decode("utf-8")
            encrypted_session_key, offset = _unpack_with_length(data, offset, length_size=2)
            iv, offset = _unpack_with_length(data, offset, length_size=1)

        payload, offset = _unpack_with_length(data, offset, length_size=4)

        return cls(
            confidentiality=confidentiality,
            authentication=authentication,
            compression=compression,
            symmetric_algorithm=symmetric_algorithm,
            encrypted_session_key=encrypted_session_key,
            recipient_key_id=recipient_key_id,
            iv=iv,
            payload=payload,
        )


if __name__ == "__main__":
    message = MessageComponent(filename="message.txt", timestamp=1_718_000_000, data=b"Hello, world!")
    signature = SignatureComponent(
        timestamp=1_718_000_000,
        sender_key_id="A1B2C3D4E5F60718",
        leading_two_octets=b"\xAB\xCD",
        encrypted_digest=b"\x01" * 128,
    )
    inner = signature.to_bytes() + message.to_bytes()

    parsed = PGPMessage.from_bytes(PGPMessage(authentication=True, payload=inner).to_bytes())
    sig2, rest = SignatureComponent.from_bytes(parsed.payload)
    msg2, rest = MessageComponent.from_bytes(rest)
    assert parsed.authentication and not parsed.confidentiality
    assert sig2 == signature and msg2 == message and rest == b""
    print("OK: authentication without confidentiality")

    enc = PGPMessage(
        confidentiality=True,
        compression=True,
        symmetric_algorithm="AES128",
        encrypted_session_key=b"\x02" * 256,
        iv=b"\x00" * 16,
        payload=b"compressed-and-encrypted-blob",
    )
    parsed2 = PGPMessage.from_bytes(enc.to_bytes())
    assert parsed2.confidentiality and parsed2.compression and not parsed2.authentication
    assert parsed2.symmetric_algorithm == "AES128"
    assert parsed2.encrypted_session_key == enc.encrypted_session_key
    assert parsed2.iv == enc.iv and parsed2.payload == enc.payload
    print("OK: confidentiality + compression")
