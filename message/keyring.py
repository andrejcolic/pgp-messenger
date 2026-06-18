"""
Module: keyring.py
Description: Public and private key rings with JSON persistence, indexed by key_id.
             Private keys are stored already encrypted (see crypto/rsa_ops.py).
"""

import base64
import json
import os
from dataclasses import dataclass


@dataclass
class PublicKeyEntry:
    key_id: str            # low 64 bits of the public key (PU mod 2^64), as a hex string
    timestamp: int
    name: str
    email: str
    public_key_pem: str

    @property
    def user_id(self) -> str:
        return f"{self.name} <{self.email}>"


@dataclass
class PrivateKeyEntry:
    key_id: str
    timestamp: int
    name: str
    email: str
    public_key_pem: str
    encrypted_private_key: bytes
    iv: bytes

    @property
    def user_id(self) -> str:
        return f"{self.name} <{self.email}>"


class _KeyRing:
    """JSON-backed store mapping key_id -> entry. Subclasses define _to_dict/_from_dict."""

    def __init__(self, storage_path: str) -> None:
        self.storage_path = storage_path
        self._entries = {}
        self._load()

    def add_key(self, entry) -> None:
        self._entries[entry.key_id] = entry
        self._save()

    def remove_key(self, key_id: str) -> bool:
        if key_id not in self._entries:
            return False
        del self._entries[key_id]
        self._save()
        return True

    def get_by_id(self, key_id: str):
        return self._entries.get(key_id)

    def get_all(self) -> list:
        return list(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key_id: str) -> bool:
        return key_id in self._entries

    def _load(self) -> None:
        if not os.path.exists(self.storage_path):
            return
        with open(self.storage_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self._entries = {key_id: self._from_dict(key_id, data) for key_id, data in raw.items()}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.storage_path) or ".", exist_ok=True)
        raw = {entry.key_id: self._to_dict(entry) for entry in self._entries.values()}
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2, ensure_ascii=False)


class PublicKeyRing(_KeyRing):
    def _to_dict(self, e: PublicKeyEntry) -> dict:
        return {
            "timestamp": e.timestamp,
            "name": e.name,
            "email": e.email,
            "public_key_pem": e.public_key_pem,
        }

    def _from_dict(self, key_id: str, d: dict) -> PublicKeyEntry:
        return PublicKeyEntry(key_id, d["timestamp"], d["name"], d["email"], d["public_key_pem"])

    def get_by_email(self, email: str) -> PublicKeyEntry | None:
        return next((e for e in self._entries.values() if e.email == email), None)


class PrivateKeyRing(_KeyRing):
    def _to_dict(self, e: PrivateKeyEntry) -> dict:
        return {
            "timestamp": e.timestamp,
            "name": e.name,
            "email": e.email,
            "public_key_pem": e.public_key_pem,
            "encrypted_private_key": base64.b64encode(e.encrypted_private_key).decode("ascii"),
            "iv": base64.b64encode(e.iv).decode("ascii"),
        }

    def _from_dict(self, key_id: str, d: dict) -> PrivateKeyEntry:
        return PrivateKeyEntry(
            key_id,
            d["timestamp"],
            d["name"],
            d["email"],
            d["public_key_pem"],
            base64.b64decode(d["encrypted_private_key"]),
            base64.b64decode(d["iv"]),
        )
