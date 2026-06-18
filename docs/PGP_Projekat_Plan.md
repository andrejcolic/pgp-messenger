# PGP Aplikacija — Zaštita Podataka 2025/2026
## Plan Rada i Kodna Šablona

> Ovaj dokument je usklađen sa **trenutno napisanim kodom**. Tamo gde se postojeći
> kod razlikuje od materijala sa vežbi (`docs/07 - pgp.pdf`), merodavan je materijal —
> takva mesta su označena sa ⚠️ i moraju da se isprave (vidi tačku 8).

---

## 1. Podela Posla

### Pregled

Posao je podeljen po **funkcionalnim celinama**, gde svaki član radi i na **logici**
i na **GUI-ju** za svoju oblast (u skladu sa pravilom da nije dozvoljeno da jedan radi
samo logiku, a drugi samo GUI).

---

### 👤 Član 1 — Upravljanje Ključevima + Slanje Poruke

| Oblast | Zadaci | Status |
|--------|--------|--------|
| **RSA generisanje** | Generisanje para ključeva (1024/2048 bita), unos imena/mejla/lozinke | TODO `crypto/rsa_ops.py` |
| **Upravljanje ključevima** | Brisanje para, zaštita privatnog ključa lozinkom | TODO |
| **Struktura prstena** | `PublicKeyRing` i `PrivateKeyRing` (in-memory + JSON perzistencija) | ✅ `message/keyring.py` |
| **Modeli ulaza** | `PublicKeyEntry`, `PrivateKeyEntry` (dataklase) | ✅ `message/keyring.py` |
| **Uvoz/Izvoz** | Uvoz i izvoz javnog ključa i celog para u `.pem` formatu | TODO `crypto/rsa_ops.py` |
| **Slanje poruke** | Koordinacija toka: potpisivanje → kompresija → šifrovanje → radix-64 | TODO `message/sender.py` |
| **Potpisivanje** | SHA-1 heš + RSA potpis, izbor privatnog ključa pošiljaoca | TODO |
| **Šifrovanje ključa sesije** | Izbor javnog ključa primaoca, RSA enkripcija Ks | TODO |
| **Struktura fajla** | Pakovanje svih komponenti u izlazni fajl | ✅ `message/pgp_message.py` (zajedničko) |
| **GUI — Upravljanje ključevima** | Tab za prsten ključeva, forme za generisanje i uvoz/izvoz | TODO `gui/tab_keys.py` |
| **GUI — Slanje poruke** | Tab za slanje, checkbox-ovi servisa, izbor ključeva | TODO `gui/tab_send.py` |

---

### 👤 Član 2 — Kriptografska Jezgra + Prijem Poruke

| Oblast | Zadaci | Status |
|--------|--------|--------|
| **Simetrični algoritmi** | TripleDES i AES128, **CFB mod** (šifrovanje/dešifrovanje Ks i poruke) | ⚠️ `crypto/symmetric_algorithms.py` (sada ECB — ispraviti) |
| **Kompresija** | ZIP kompresija i dekompresija (zlib) | ✅ `crypto/compression.py` |
| **Radix-64** | Konverzija u radix-64 ASCII i obrnuto (Base64) | ✅ `crypto/radix64.py` |
| **Heš** | SHA-1 heš funkcija | ✅ `crypto/hashing.py` |
| **Struktura paketa** | Parsiranje/deserijalizacija formata pri prijemu | ✅ `message/pgp_message.py` (zajedničko) |
| **Prijem poruke** | Koordinacija toka: radix-64 → dešifrovanje → dekompresija → autentikacija | TODO `message/receiver.py` |
| **Autentikacija** | SHA-1 + RSA verifikacija heša, prikaz info o autoru potpisa | TODO |
| **Dešifrovanje** | Dešifrovanje Ks privatnim ključem primaoca, dešifrovanje poruke | TODO |
| **Upravljanje greškama** | Jasne poruke o neuspešnom dešifrovanju/autentikaciji | TODO |
| **GUI — Prijem poruke** | Tab za prijem, prikaz rezultata autentikacije i autora | TODO `gui/tab_receive.py` |
| **GUI — Dijalozi** | Unos lozinke, prikaz grešaka, čuvanje fajla | TODO `gui/dialogs.py` |

---

### Zajednička odgovornost (oba člana)

- `config.py` — konstante i podešavanja
- `main.py` — entry point i spajanje tabova (TODO: trenutno prazan)
- `message/pgp_message.py` — zajednička struktura poruke (✅ dogovoreno i implementirano)
- Code review međusobnog koda
- Testiranje integrisanog sistema

---

## 2. Struktura Projekta (stvarna)

```
pgp-messenger/
│
├── main.py                         # Entry point — pokreće GUI [ZAJEDNIČKO] (TODO: prazan)
├── config.py                       # Konstante (algoritmi, veličine ključeva, putanje) [ZAJEDNIČKO]
├── requirements.txt                # cryptography~=49.0.0
│
├── docs/                           # Tekst zadatka, materijali (07 - pgp.pdf), ovaj plan
│
├── crypto/                         # Kriptografska jezgra
│   ├── symmetric_algorithms.py     # TripleDES + AES128, CFB mod [ČLAN 2]  ⚠️ trenutno ECB
│   ├── hashing.py                  # SHA-1 [ČLAN 2]
│   ├── compression.py              # ZIP / zlib [ČLAN 2]
│   ├── radix64.py                  # radix-64 konverzija [ČLAN 2]
│   └── rsa_ops.py                  # RSA operacije [ČLAN 1] (TODO)
│
├── message/                        # Struktura poruke i tok slanja/prijema
│   ├── keyring.py                  # PublicKeyEntry/Ring, PrivateKeyEntry/Ring [ČLAN 1]
│   ├── pgp_message.py              # SignatureComponent, MessageComponent, PGPMessage [ZAJEDNIČKO]
│   ├── sender.py                   # Tok slanja [ČLAN 1] (TODO)
│   └── receiver.py                 # Tok prijema [ČLAN 2] (TODO)
│
└── gui/                            # (TODO — još nije kreiran)
    ├── main_window.py              # Glavni prozor sa tabovima [ZAJEDNIČKO]
    ├── tab_keys.py                 # Upravljanje ključevima [ČLAN 1]
    ├── tab_send.py                 # Slanje poruke [ČLAN 1]
    ├── tab_receive.py              # Prijem poruke [ČLAN 2]
    └── dialogs.py                  # Zajednički dijalozi [ČLAN 2]
```

> Napomena: modeli ulaza (`*Entry`) i prstenovi (`*Ring`) su objedinjeni u jednom fajlu
> `message/keyring.py` (umesto razdvojenih `models` + `ring`), jer su uže povezani.

---

## 3. Kodna Šablona — Pravila

### 3.1 Opšte Konvencije

```python
# Python verzija: 3.10+ (razvija se na 3.14)

# Imenovanje (identifikatori na engleskom, docstring/komentari na srpskom):
# - Klase:       PascalCase        →  PublicKeyRing, PGPMessage
# - Funkcije:    snake_case        →  generate_key_pair(), encrypt()
# - Konstante:   UPPER_SNAKE_CASE  →  KEY_SIZES, PUBLIC_EXPONENT
# - Privatne:    _snake_case       →  _pack_with_length()
# - Fajlovi:     snake_case.py     →  keyring.py, symmetric_algorithms.py

# Maksimalna dužina linije: 100 karaktera
# Koristiti tip anotacije gde god je moguće
# test()/demo kod UVEK pod  if __name__ == "__main__":
```

### 3.2 Šablona za Modul

```python
"""
Modul: keyring.py
Opis:  Kratak opis modula na srpskom.
"""

import json
import os
from dataclasses import dataclass

from config import SymmetricAlgorithm
```

### 3.3 Prstenovi ključeva — `message/keyring.py` (implementirano)

Javni API (koristi ga i `sender.py` i `receiver.py`):

```python
@dataclass
class PublicKeyEntry:
    key_id: str            # poslednjih 64 bita javnog ključa (PU mod 2^64), hex string (16 znakova, uppercase)
    timestamp: int
    name: str
    email: str
    public_key_pem: str
    # property user_id -> "name <email>"

@dataclass
class PrivateKeyEntry:
    key_id: str
    timestamp: int
    name: str
    email: str
    public_key_pem: str
    encrypted_private_key: bytes   # privatni ključ šifrovan AES-om sa SHA-1(lozinka)
    iv: bytes                      # IV za to šifrovanje (CFB/CBC)
    # property user_id -> "name <email>"

class PublicKeyRing:        # JSON perzistencija, indeks po key_id
    def __init__(self, storage_path: str) -> None: ...
    def add_key(self, entry: PublicKeyEntry) -> None: ...
    def remove_key(self, key_id: str) -> bool: ...
    def get_by_id(self, key_id: str) -> PublicKeyEntry | None: ...
    def get_by_email(self, email: str) -> PublicKeyEntry | None: ...
    def get_all(self) -> list[PublicKeyEntry]: ...
    # __len__, __contains__

class PrivateKeyRing:       # isti API (bez get_by_email)
    ...
```

### 3.4 Šablona za GUI Tab (TODO)

```python
"""
Modul: tab_send.py
Opis:  GUI tab za slanje PGP poruke.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from message.keyring import PublicKeyRing, PrivateKeyRing


class TabSend(ttk.Frame):
    """
    Tab za slanje PGP poruke. Servisi (checkbox-ovi):
      - Potpisivanje (autentikacija) — SHA-1 + RSA privatnim ključem pošiljaoca
      - Šifrovanje (tajnost) — TripleDES/AES128 (CFB), Ks šifrovan RSA javnim ključem primaoca
      - Kompresija — ZIP
      - Konverzija u radix-64
    """

    def __init__(self, parent: ttk.Notebook,
                 public_ring: PublicKeyRing,
                 private_ring: PrivateKeyRing) -> None:
        super().__init__(parent)
        self.public_ring = public_ring
        self.private_ring = private_ring
        self._build_ui()

    def _build_ui(self) -> None:
        ...  # TODO
```

### 3.5 Kripto — simetrični algoritmi (`crypto/symmetric_algorithms.py`)

> ⚠️ **Ciljni interfejs** — trenutni kod koristi ECB bez IV-a i mora da se prebaci na **CFB**
> (materijal `07 - pgp.pdf`, str. 11: „64-bitni cipher feedback (CFB) mod funkcionisanja").
> CFB je stream mod → **padding nije potreban**. Dispatch po stringu (`SymmetricAlgorithm.X.value`)
> ostaje kao sada (`_ALGOS` dict).

```python
"""
Modul: symmetric_algorithms.py
Opis:  Simetrično šifrovanje ključa sesije i poruke.
       Izabrana 2 od 4: TripleDES i AES128. Mod rada: CFB.
"""
from config import SymmetricAlgorithm

# Dužine (bajtova):  ključ sesije / IV (= veličina bloka)
#   AES128:     16 / 16
#   TripleDES:  24 /  8

def generate_session_key(algorithm: str) -> bytes:
    """Slučajan one-time ključ odgovarajuće dužine (16 za AES128, 24 za TripleDES)."""

def generate_iv(algorithm: str) -> bytes:
    """Slučajan IV veličine bloka (16 za AES128, 8 za TripleDES)."""

def encrypt(algorithm: str, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Šifruje u CFB modu. Diže ValueError za nepodržan algoritam."""

def decrypt(algorithm: str, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Dešifruje u CFB modu."""
```

Ostali kripto moduli (implementirani, stabilni interfejsi):

```python
# crypto/hashing.py
def hash_function(data: bytes) -> bytes          # SHA-1, 20 bajtova

# crypto/compression.py
def compress(data: bytes) -> bytes               # zlib
def decompress(data: bytes) -> bytes

# crypto/radix64.py
def convert_to_radix64(data: bytes) -> bytes
def convert_to_radix64_str(data: bytes) -> str
def convert_from_radix64(data: str | bytes) -> bytes
```

### 3.6 `config.py` — Deljene Konstante

Trenutno sadrži enum simetričnih algoritama; ostale konstante dodati po potrebi.

```python
from enum import Enum

class SymmetricAlgorithm(Enum):
    TRIPLE_DES = "TripleDES"
    AES128     = "AES128"

# Predlog dopuna (TODO):
# KEY_SIZES        = [1024, 2048]     # RSA
# PUBLIC_EXPONENT  = 65537
# HASH_ALGORITHM   = "SHA-1"
# PUBLIC_RING_PATH  = "data/public_keyring.json"
# PRIVATE_RING_PATH = "data/private_keyring.json"
```

### 3.7 `message/pgp_message.py` — Struktura Poruke (implementirano)

> ✅ Dogovoreno i implementirano. Format je **binarni sa flag bajtom**, ne sa tipovima paketa.
> Radix-64 konverzija cele datoteke radi se **izvan** ovog modula.

Komponente (str. 22 materijala):

```python
@dataclass
class SignatureComponent:
    """Timestamp || Key ID pošiljaoca || vodeća 2 okteta || RSA(SHA-1 digest)."""
    timestamp: int
    sender_key_id: str
    leading_two_octets: bytes      # prva 2 bajta SHA-1 heša
    encrypted_digest: bytes        # SHA-1 heš šifrovan privatnim ključem (RSA)
    # to_bytes() / from_bytes(data) -> (component, rest)

@dataclass
class MessageComponent:
    """Filename || Timestamp || Data."""
    filename: str
    timestamp: int
    data: bytes
    # to_bytes() / from_bytes(data) -> (component, rest)

@dataclass
class PGPMessage:
    """
    Kompletna poruka za upis u fajl.

    Binarni format to_bytes():
        [1 B]  flags  (bit0 confidentiality, bit1 authentication, bit2 compression)
        ── ako confidentiality ──
        [1 B + N]  symmetric_algorithm  (length-prefixed UTF-8, npr. "AES128")
        [2 B + M]  encrypted_session_key (length-prefixed RSA ciphertext)
        [1 B + K]  iv                    (length-prefixed IV)
        ──
        [4 B + L]  payload  ((opciono kompresovan/šifrovan) Signature + Message)
    """
    confidentiality: bool = False
    authentication: bool = False
    compression: bool = False
    symmetric_algorithm: str | None = None       # SymmetricAlgorithm.X.value
    encrypted_session_key: bytes | None = None
    iv: bytes | None = None
    payload: bytes = b""
    # to_bytes() / from_bytes(data) -> PGPMessage
```

Tok pakovanja payload-a (Član 1, `sender.py`):
`Signature.to_bytes() + Message.to_bytes()` → (opc. `compress`) → (opc. `encrypt` CFB) → `PGPMessage` → `to_bytes()` → (opc. `convert_to_radix64`).

---

## 4. Pravila za Git

```
# <tip>(<oblast>): <opis>
# tipovi: feat | fix | refactor | style | docs | test

feat(keyring): implementacija prstenova javnih i privatnih ključeva
feat(crypto): AES128 i TripleDES u CFB modu
fix(crypto): test() pod __main__ umesto poziva pri importu
feat(sender): tok potpisivanje-kompresija-sifrovanje-radix64
```

**Git tok:**
1. `main` — uvek stabilna, merge gotovih feature-a
2. `feature/clan1-...` — Član 1
3. `feature/clan2-...` — Član 2
4. Pre merge-a → code review drugog člana

---

## 5. Redosled Implementacije

### Faza 1 — Osnova ✅ (uglavnom završeno)
- [x] Struktura foldera, `requirements.txt`
- [x] `message/pgp_message.py` dogovoren i implementiran
- [x] `config.py` (enum algoritama; dopune po potrebi)
- [ ] Skeletni `main.py` sa praznim tabovima

### Faza 2 — Paralelni rad

**Član 1:**
- [x] `message/keyring.py` — modeli + prstenovi (JSON perzistencija)
- [ ] `crypto/rsa_ops.py` — generisanje, zaštita lozinkom, sign/verify, enkripcija Ks, PEM uvoz/izvoz
- [ ] `gui/tab_keys.py`

**Član 2:**
- [x] `crypto/hashing.py` — SHA-1
- [x] `crypto/compression.py` — ZIP/zlib
- [x] `crypto/radix64.py` — radix-64
- [ ] ⚠️ `crypto/symmetric_algorithms.py` — prebaciti na **CFB**, dodati IV u interfejs (vidi tačku 8)
- [ ] `gui/dialogs.py`

### Faza 3 — Integracija
- [ ] `message/sender.py` (Član 1) — koristi crypto module Člana 2
- [ ] `message/receiver.py` (Član 2) — koristi prsten ključeva Člana 1
- [ ] `gui/tab_send.py` (Član 1), `gui/tab_receive.py` (Član 2)

### Faza 4 — Testiranje i Poliranje
- [ ] End-to-end: slanje → prijem (sve kombinacije servisa)
- [ ] Granični slučajevi i upravljanje greškama
- [ ] Finalno dotjerivanje GUI-ja

---

## 6. `requirements.txt`

```txt
cryptography~=49.0.0
# tkinter dolazi uz standardnu Python instalaciju
```

---

## 7. Napomene o Implementaciji (iz materijala)

- **ID ključa:** poslednja 64 bita javnog ključa (`PU mod 2^64`), hex string, 16 znakova uppercase. Koristi se u potpisu i u komponenti ključa sesije. (`packet.key_id_to_bytes/from_bytes`.)
- **Ključ sesije:** slučajan one-time ključ za svaku poruku; AES128 → 16 bajtova, TripleDES → 24 bajta. Šifruje se RSA javnim ključem primaoca.
- **Mod simetričnog šifrovanja:** **CFB** (str. 11). CFB ne zahteva padding.
- **Zaštita privatnog ključa (str. 25):** lozinka → SHA-1 → 160-bit heš → uzima se **128 bita** kao ključ → šifrovanje privatnog ključa (CAST-128 u materijalu; kod nas AES128). Pristup PR uvek traži lozinku. (`PrivateKeyEntry.encrypted_private_key` + `iv`.)
- **Redosled servisa (slanje):** Potpisivanje → Kompresija (ZIP) → Šifrovanje → Radix-64.
- **Redosled servisa (prijem):** Radix-64 → Dešifrovanje → Dekompresija → Autentikacija.
- **Potpis pre kompresije:** čuva se nekompresovani potpis (kompresija nije deterministička).
- **Vodeća dva okteta heša:** brza provera da li je iskorišćen pravi javni ključ pre pune verifikacije.
- **Replay zaštita:** potpis uključuje timestamp nastajanja.

---

## 8. ⚠️ Odstupanja od materijala koja se MORAJU ispraviti

| # | Fajl | Problem | Ispravka |
|---|------|---------|----------|
| 1 | `crypto/symmetric_algorithms.py` | Koristi **ECB** mod | Prebaciti na **CFB** (`modes.CFB(iv)`) — materijal str. 11 |
| 2 | `crypto/symmetric_algorithms.py` | `encrypt/decrypt` ne primaju IV | Dodati `iv` parametar + `generate_iv()` (CFB zahteva IV; `pgp_message`/`keyring` ga već nose) |
| 3 | `crypto/compression.py` (lin. 50), `crypto/hashing.py` (lin. 33) | `test()` se poziva na nivou modula → printuje pri importu | Staviti pod `if __name__ == "__main__":` |
| 4 | `crypto/symmetric_algorithms.py` | Drugi parametar `decrypt` se zove `plaintext` | Preimenovati u `ciphertext` (kozmetika) |
