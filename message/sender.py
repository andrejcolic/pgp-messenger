"""
Module: sender.py
Description: This module provides PGP message sending flow.
             Flow: Authentication -> Compression -> Encryption -> Radix64
Author: Andrej
Date: 20/06/2026.
"""

import os
import time
from collections.abc import Callable
from dataclasses import dataclass

from config import SymmetricAlgorithm
from crypto import rsa
from crypto.hashing import hash_function
from crypto.compression import compress
from crypto.radix64 import convert_to_radix64
from crypto.symmetric_algorithms import encrypt, decrypt, generate_iv
from message.keyring import PublicKeyRing, PrivateKeyRing, PrivateKeyEntry
from message.pgp_message import PGPMessage, SignatureComponent, MessageComponent


# Session key length per algorithm (AES128 -> 16 bytes, TripleDES -> 24 bytes).
_SESSION_KEY_SIZES = {
    SymmetricAlgorithm.AES128.value: 16,
    SymmetricAlgorithm.TRIPLE_DES.value: 24,
}


@dataclass
class SentResult:
    """
    Data class to store the produced PGP file, to be written to disk by the GUI.
    """
    data: bytes                         # final PGP message (radix64 or raw bytes)
    success: bool
    error_msg: str | None = None


def send_message(
    data: bytes,
    filename: str,
        *,
    authentication: bool,
    confidentiality: bool,
    compression: bool,
    is_radix64: bool,
    symmetric_algorithm: str | None,
    sender_key_id: str | None,
    recipient_key_id: str | None,
    public_ring: PublicKeyRing,
    private_ring: PrivateKeyRing,
    get_password: Callable[[...], str],
) -> SentResult:


    try:
        message = MessageComponent(filename=filename, timestamp=int(time.time()), data=data)

        payload = message.to_bytes()
        if authentication:
            signature = _build_signature(message, sender_key_id, private_ring, get_password)
            payload = signature.to_bytes() + payload

        payload = _compress_payload(payload) if compression else payload

        encrypted_session_key = None
        iv = None
        if confidentiality:
            payload, encrypted_session_key, iv = _encrypt_payload(
                payload, recipient_key_id, symmetric_algorithm, public_ring
            )

        msgPGP = PGPMessage(
            confidentiality=confidentiality,
            authentication=authentication,
            compression=compression,
            symmetric_algorithm=symmetric_algorithm if confidentiality else None,
            encrypted_session_key=encrypted_session_key,
            recipient_key_id=recipient_key_id if confidentiality else None,
            iv=iv,
            payload=payload,
        )

        raw = msgPGP.to_bytes()
        raw = convert_to_radix64(raw) if is_radix64 else raw

        return SentResult(
            data=raw,
            success=True,
            error_msg=None,
        )
    except ValueError as e:
        return SentResult(
            data=b"",
            success=False,
            error_msg=str(e),
        )


def _build_signature(
        message: MessageComponent,
        sender_key_id: str,
        private_key_ring: PrivateKeyRing,
        get_password: Callable[[...], str],
) -> SignatureComponent:

    entry = private_key_ring.get_by_id(sender_key_id)
    if entry is None:
        raise ValueError("Sender private key not found")

    password = get_password(entry)
    private_key = _unlock_private_key(entry, password)

    message_bytes = message.to_bytes()
    digest = hash_function(message_bytes)
    encrypted_digest = rsa.sign(private_key, message_bytes)

    return SignatureComponent(
        timestamp=int(time.time()),
        sender_key_id=entry.key_id,
        leading_two_octets=digest[:2],
        encrypted_digest=encrypted_digest,
    )


def _encrypt_payload(
        payload: bytes,
        recipient_key_id: str,
        algorithm: str,
        public_key_ring: PublicKeyRing,
) -> tuple[bytes, bytes, bytes]:

    entry = public_key_ring.get_by_id(recipient_key_id)
    if entry is None:
        raise ValueError("Recipient public key not found")

    session_key = os.urandom(_SESSION_KEY_SIZES[algorithm])
    iv = generate_iv(algorithm)

    encrypted_payload = encrypt(algorithm, payload, session_key, iv)
    encrypted_session_key = rsa.encrypt(entry.public_key_pem, session_key)

    return encrypted_payload, encrypted_session_key, iv


def _unlock_private_key(entry: PrivateKeyEntry, password: str) -> str:

    symetric_key = hash_function(password.encode("utf-8"))[:16]
    pem = decrypt(SymmetricAlgorithm.AES128.value, entry.encrypted_private_key, symetric_key, entry.iv)
    return pem.decode("utf-8")


def _compress_payload(payload: bytes) -> bytes:
    return compress(payload)
