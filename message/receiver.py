"""
Module: receiver.py
Description: This module provides PGP message receiving flow.
             Flow: Radix64 -> Decryption -> Decompression -> Authentification
Author: Igor
Date: 19/06/2026.
"""

from collections.abc import Callable
from dataclasses import dataclass

from config import SymmetricAlgorithm
from crypto import rsa
from crypto.hashing import hash_function
from message.keyring import PublicKeyRing, PrivateKeyRing, PrivateKeyEntry
from crypto.radix64 import convert_from_radix64
from crypto.symmetric_algorithms import decrypt
from message.pgp_message import PGPMessage, SignatureComponent, MessageComponent
from crypto.compression import decompress


@dataclass
class ReceivedResult:
    """
    Data class to store the received message, to be shown in GUI.
    """
    filename: str
    data: bytes                         # original message
    success: bool
    error_msg: str | None = None
    signature_present: bool = False
    signature_valid: bool | None = None # None -> cannot be verified (missing key)
    sender_user_id: str | None = None
    timestamp: int | None = None


def receive_message(
    file_bytes: bytes,
        *,
    is_radix64: bool,       # ovde ili da se doda kao flag u pgp_msg
    public_ring: PublicKeyRing,
    private_ring: PrivateKeyRing,
    get_password: Callable[[...], str],
) -> ReceivedResult:


    try:
        raw = convert_from_radix64(file_bytes) if is_radix64 else file_bytes

        msgPGP = PGPMessage.from_bytes(raw)

        payload = _decrypt_payload(msgPGP, private_ring, get_password)

        payload = _decompress_payload(payload) if msgPGP.compression else payload

        signature = None
        data = payload
        valid_signature: tuple[bool | None, str | None] = (None, None)

        if msgPGP.authentication:
            signature, data = SignatureComponent.from_bytes(payload)
        message, _ = MessageComponent.from_bytes(data)

        if signature:
            valid_signature = _verify_signature(signature, message, public_ring)

        return ReceivedResult(
            filename=message.filename,
            data=message.data,
            success=True,
            error_msg=None,
            signature_present=signature is not None,
            signature_valid=valid_signature[0],
            sender_user_id=valid_signature[1],
            timestamp=message.timestamp,
        )
    except ValueError as e:
        return ReceivedResult(
            filename="",
            data=b"",
            success=False,
            error_msg=str(e),
            signature_present=False,
            signature_valid=None,
            sender_user_id=None,
            timestamp=None,
        )



def _decrypt_payload(
        message: PGPMessage,
        private_key_ring: PrivateKeyRing,
        get_password: Callable[[...], str],
) -> bytes:

    payload = message.payload

    if not message.confidentiality:
        return payload

    entry = private_key_ring.get_by_id(message.recipient_key_id)
    if entry is None:
        raise ValueError("Entry not found")

    password = get_password(entry)
    private_key = _unlock_private_key(entry, password)
    session_key = rsa.decrypt(private_key, message.encrypted_session_key)
    return decrypt(message.symmetric_algorithm, payload, session_key, message.iv)


def _unlock_private_key(entry: PrivateKeyEntry, password: str) -> str:

    symetric_key = hash_function(password.encode("utf-8"))[:16]
    pem = decrypt(SymmetricAlgorithm.AES128.value, entry.encrypted_private_key, symetric_key, entry.iv)
    return pem.decode("utf-8")


def _decompress_payload(payload: bytes) -> bytes:
    return decompress(payload)

def _verify_signature(
    signature: SignatureComponent,
    message_component: MessageComponent,
    public_ring: PublicKeyRing,
) -> tuple[bool | None, str | None]:

    entry = public_ring.get_by_id(signature.sender_key_id)
    if entry is None:
        return None, None

    digest = hash_function(message_component.to_bytes())
    if digest[:2] != signature.leading_two_octets:
        return False, entry.user_id

    is_valid = rsa.verify(entry.public_key_pem, signature.encrypted_digest, message_component.to_bytes())

    return is_valid, entry.user_id