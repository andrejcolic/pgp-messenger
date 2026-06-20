"""
Modul: tab_receive.py
Opis:  GUI tab za prijem PGP poruke.
       Korisnik bira fajl -> aplikacija prepoznaje pakete -> desifruje/verifikuje ->
       prikazuje rezultat -> nudi cuvanje originalne poruke na zeljenu destinaciju.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.ttk import Notebook

from message.keyring import PublicKeyRing, PrivateKeyRing
from message.receiver import receive_message, ReceivedResult
from gui.tab_dialogs import ask_password, show_error, show_receive_result, PasswordCancelled


class TabReceive(ttk.Frame):
    """
    Tab za prijem PGP poruke.

    Tok:
      1. Korisnik bira fajl (.pgp ili .asc/radix64) preko dugmeta "Izaberi fajl".
      2. Aplikacija pokusava da prepozna da li je sadrzaj radix-64 (na osnovu ekstenzije
         ili sadrzaja) - korisnik moze i rucno da forsira preko checkbox-a.
      3. Klikom na "Primi poruku" pokrece se receive_message() iz message/receiver.py.
      4. Ako receive_message zatrazi lozinku za privatni kljuc, ask_password() dijalog
         se otvara automatski (receive_message ga zove kroz get_password callback).
      5. Rezultat (uspeh/neuspeh, status potpisa) se prikazuje korisniku.
      6. Ako je prijem uspesan, korisniku se nudi cuvanje originalne poruke na disk.
    """

    def __init__(
        self,
        parent: ttk.Notebook,
        public_ring: PublicKeyRing,
        private_ring: PrivateKeyRing,
    ) -> None:
        super().__init__(parent)
        self.public_ring = public_ring
        self.private_ring = private_ring

        self._selected_path: str | None = None
        self._last_result: ReceivedResult | None = None

        self._build_ui()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=15)
        outer.pack(fill="both", expand=True)

        # --- Izbor fajla ---
        file_frame = ttk.LabelFrame(outer, text="1. Izaberite primljeni fajl", padding=10)
        file_frame.pack(fill="x", pady=(0, 10))

        self._path_var = tk.StringVar(value="(nije izabran nijedan fajl)")
        ttk.Label(
            file_frame, textvariable=self._path_var, foreground="#444"
        ).pack(side="left", fill="x", expand=True)

        ttk.Button(
            file_frame, text="Izaberi fajl...", command=self._on_choose_file
        ).pack(side="right")

        # --- Opcije ---
        options_frame = ttk.LabelFrame(outer, text="2. Opcije", padding=10)
        options_frame.pack(fill="x", pady=(0, 10))

        self._radix64_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame,
            text="Fajl je u radix-64 (ASCII) formatu",
            variable=self._radix64_var,
        ).pack(anchor="w")

        # --- Akcija ---
        action_frame = ttk.Frame(outer)
        action_frame.pack(fill="x", pady=(0, 10))

        self._receive_btn = ttk.Button(
            action_frame,
            text="Primi poruku",
            command=self._on_receive,
            state="disabled",
        )
        self._receive_btn.pack(side="left")

        self._save_btn = ttk.Button(
            action_frame,
            text="Sačuvaj poruku kao...",
            command=self._on_save,
            state="disabled",
        )
        self._save_btn.pack(side="left", padx=(10, 0))

        # --- Status / poslednji rezultat ---
        status_frame = ttk.LabelFrame(outer, text="Status", padding=10)
        status_frame.pack(fill="both", expand=True)

        self._status_var = tk.StringVar(value="Spremno za prijem.")
        self._status_label = ttk.Label(
            status_frame, textvariable=self._status_var, wraplength=420, justify="left"
        )
        self._status_label.pack(anchor="w")

    # ------------------------------------------------------------- handlers

    def _on_choose_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Izaberite PGP fajl",
            filetypes=[
                ("Svi fajlovi", "*.*"),
                ("PGP fajlovi", "*.pgp"),
                ("Radix-64 fajlovi", "*.asc"),
            ],
        )
        if not path:
            return

        self._selected_path = path
        self._path_var.set(os.path.basename(path))
        self._receive_btn.config(state="normal")
        self._save_btn.config(state="disabled")
        self._last_result = None

        # Pomoc korisniku: ako ekstenzija sugerise radix-64 tekstualni format, predlozi checkbox.
        if path.lower().endswith((".asc", ".txt")):
            self._radix64_var.set(True)
        else:
            self._radix64_var.set(False)

        self._set_status(f"Izabran fajl: {path}")

    def _on_receive(self) -> None:
        if not self._selected_path:
            show_error(self, "Niste izabrali fajl.")
            return

        try:
            with open(self._selected_path, "rb") as f:
                file_bytes = f.read()
        except OSError as e:
            show_error(self, f"Fajl nije moguće pročitati:\n{e}")
            return

        def get_password(entry):
            # Diže PasswordCancelled ako korisnik otkaže - receive_message to ne hvata
            # eksplicitno (hvata samo ValueError), pa hvatamo ovde oko celog poziva.
            return ask_password(self, entry)

        try:
            result = receive_message(
                file_bytes,
                is_radix64=self._radix64_var.get(),
                public_ring=self.public_ring,
                private_ring=self.private_ring,
                get_password=get_password,
            )
        except PasswordCancelled:
            self._set_status("Prijem otkazan (lozinka nije uneta).")
            return
        except Exception as e:
            # Catch-all za sve sto receive_message eventualno ne uhvati interno
            # (npr. zlib.error iz dekompresije, izuzeci iz RSA operacija).
            # Zahtev iz zadatka: jasna poruka o gresci, ne sirov traceback.
            show_error(self, f"Neočekivana greška pri prijemu:\n{e}")
            self._set_status("Prijem neuspešan (neočekivana greška).")
            return

        self._last_result = result

        if not result.success:
            show_error(self, result.error_msg or "Prijem poruke nije uspeo.")
            self._set_status(f"Prijem neuspešan: {result.error_msg}")
            self._save_btn.config(state="disabled")
            return

        show_receive_result(self, result)
        self._set_status(self._format_success_status(result))
        self._save_btn.config(state="normal")

    def _on_save(self) -> None:
        if self._last_result is None or not self._last_result.success:
            show_error(self, "Nema primljene poruke za čuvanje.")
            return

        suggested_name = self._last_result.filename or "poruka.txt"
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Sačuvaj originalnu poruku",
            initialfile=suggested_name,
        )
        if not path:
            return

        try:
            with open(path, "wb") as f:
                f.write(self._last_result.data)
        except OSError as e:
            show_error(self, f"Čuvanje fajla nije uspelo:\n{e}")
            return

        self._set_status(f"Poruka sačuvana: {path}")

    # --------------------------------------------------------------- helpers

    def _set_status(self, text: str) -> None:
        self._status_var.set(text)

    @staticmethod
    def _format_success_status(result: ReceivedResult) -> str:
        parts = [f"Uspešno primljeno: {result.filename}"]
        if result.signature_present:
            if result.signature_valid is True:
                parts.append(f"Potpis validan ({result.sender_user_id})")
            elif result.signature_valid is False:
                parts.append("Potpis NIJE validan")
            else:
                parts.append("Potpis se ne može verifikovati (nepoznat ključ)")
        else:
            parts.append("Poruka nije bila potpisana")
        return " | ".join(parts)


if __name__ == "__main__":
    notebook = Notebook()
    private_ring = PrivateKeyRing("private_key_ring.txt")
    public_ring = PublicKeyRing("public_key_ring.txt")
    TabReceive(notebook, private_ring=private_ring, public_ring=public_ring).pack()