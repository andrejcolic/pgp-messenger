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
from crypto.radix64 import convert_from_radix64, is_valid_radix64
from crypto.symmetric_algorithms import decrypt
from message.pgp_message import PGPMessage, SignatureComponent, MessageComponent
from crypto.compression import decompress


@dataclass
class ReceivedResult:
    """
    Data class to store the received message, to be shown in GUI.
    """
    filename: str                       # Original filename
    data: bytes                         # Original message
    success: bool                       # True -> message received successfully | False -> error occurred
    error_msg: str | None = None        # Error message when success is False
    signature_present: bool = False     # True -> is present | False -> is not present
    signature_valid: bool | None = None # True -> is valid | False -> is not valid |
                                        # None -> cannot be verified (missing key) or signature is not present
    sender_user_id: str | None = None   # Sender user ID if signature is present and valid, otherwise None
    timestamp: int | None = None        # Timestamp of the message if signature is present and valid, otherwise None


def receive_message(
    file_bytes: bytes,
        *,
    is_radix64: bool,       # ovde ili da se doda kao flag u pgp_msg
    public_ring: PublicKeyRing,
    private_ring: PrivateKeyRing,
    get_password: Callable[[...], str],
) -> ReceivedResult:
    """
    Provides PGP message receiving flow.
    1. Convert from Radix64 if needed
    2. Decrypt the message if needed
    3. Decompress the message if needed
    4. Verify the signature if present
    :param file_bytes:
    :param is_radix64:
    :param public_ring:
    :param private_ring:
    :param get_password:
    :return:
    """


    try:
        _check_radix_format(is_radix64, file_bytes)

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

def _check_radix_format(is_radix64: bool, data: bytes):
    if not is_radix64 and is_valid_radix64(data):
        raise ValueError("Datoteka je u Radix64 formatu.\n"
                         "Izaberite opciju \'Radix-64\'")
    elif is_radix64 and not is_valid_radix64(data):
        raise ValueError("Datoteka nije u Radix64 formatu.\n"
                         "Isključite opciju \'Radix-64\'")


def _decrypt_payload(
        message: PGPMessage,
        private_key_ring: PrivateKeyRing,
        get_password: Callable[[...], str],
) -> bytes:
    """
    Decrypts the payload of the PGP message if confidentiality is enabled.
    1. Get the private key entry from the private key ring using the recipient's key ID.
    2. Unlock the private key using the provided password.
    3. Decrypt the session key using RSA decryption with the unlocked private key.
    4. Decrypt the payload using the symmetric algorithm specified in the message, the decrypted session key, and the initialization vector (IV) from the message.
    5. Return the decrypted payload.
    :param message:
    :param private_key_ring:
    :param get_password:
    :return:
    """

    payload = message.payload

    if not message.confidentiality:
        return payload

    entry = private_key_ring.get_by_id(message.recipient_key_id)
    if entry is None:
        raise ValueError("Korisnik više ne postoji (ulaz nije pronadjen)!")

    password = get_password(entry)
    try:
        private_key = _unlock_private_key(entry, password)
        session_key = rsa.decrypt(private_key, message.encrypted_session_key)
        return decrypt(message.symmetric_algorithm, payload, session_key, message.iv)
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        raise ValueError("Pogrešna lozinka ili oštećen privatni ključ.") from e


def _unlock_private_key(entry: PrivateKeyEntry, password: str) -> str:
    """
    Unlocks the private key using the provided password.
    :param entry:
    :param password:
    :return:
    """

    symetric_key = hash_function(password.encode("utf-8"))[:16]
    try:
        pem = decrypt(SymmetricAlgorithm.AES128.value, entry.encrypted_private_key, symetric_key, entry.iv)
        return pem.decode("utf-8")
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        raise ValueError("Pogrešna lozinka za privatni ključ.") from e


def _decompress_payload(payload: bytes) -> bytes:
    """
    Decompresses the payload of the PGP message if confidentiality is enabled.
    :param payload:
    :return:
    """
    return decompress(payload)

def _verify_signature(
    signature: SignatureComponent,
    message_component: MessageComponent,
    public_ring: PublicKeyRing,
) -> tuple[bool | None, str | None]:
    """
    Verifies the signature of the message component.
    :param signature:
    :param message_component:
    :param public_ring:
    :return:
    """

    entry = public_ring.get_by_id(signature.sender_key_id)
    if entry is None:
        return None, None

    digest = hash_function(message_component.to_bytes())
    if digest[:2] != signature.leading_two_octets:
        return False, entry.user_id

    is_valid = rsa.verify(entry.public_key_pem, signature.encrypted_digest, message_component.to_bytes())

    return is_valid, entry.user_id