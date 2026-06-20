"""
Modul: tab_send.py
Opis:  GUI tab za slanje PGP poruke.
       Korisnik unese poruku (tekst ili fajl) -> izabere servise i ključeve ->
       aplikacija sastavi PGP poruku (potpis/kompresija/šifrovanje/radix-64) ->
       nudi čuvanje rezultata na disk.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog

from config import SymmetricAlgorithm
from message.keyring import PublicKeyRing, PrivateKeyRing
from message.sender import send_message
from gui.tab_dialogs import ask_password, show_error, show_info, PasswordCancelled

ALGORITHMS = [SymmetricAlgorithm.AES128.value, SymmetricAlgorithm.TRIPLE_DES.value]


class TabSend(ttk.Frame):
    """
    Tab za slanje PGP poruke. Servisi (checkbox-ovi):
      - Potpisivanje (autentikacija) — SHA-1 + RSA privatnim ključem pošiljaoca
      - Šifrovanje (tajnost) — TripleDES/AES128 (CFB), Ks šifrovan RSA javnim ključem primaoca
      - Kompresija — ZIP
      - Konverzija u radix-64
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
        self._sender_map: dict[str, str] = {}
        self._recipient_map: dict[str, str] = {}

        self._build_ui()
        self._refresh_keys()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=15)
        outer.pack(fill="both", expand=True)

        # --- Unos poruke ---
        msg_frame = ttk.LabelFrame(outer, text="1. Poruka", padding=10)
        msg_frame.pack(fill="both", expand=True, pady=(0, 10))

        self._text = tk.Text(msg_frame, height=6, wrap="word")
        self._text.pack(fill="both", expand=True)

        file_row = ttk.Frame(msg_frame)
        file_row.pack(fill="x", pady=(8, 0))
        self._path_var = tk.StringVar(value="(ili izaberite fajl umesto teksta)")
        ttk.Label(file_row, textvariable=self._path_var, foreground="#444").pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(file_row, text="Izaberi fajl...", command=self._on_choose_file).pack(side="left")
        ttk.Button(file_row, text="Očisti fajl", command=self._on_clear_file).pack(
            side="left", padx=(8, 0)
        )

        # --- Servisi ---
        services_frame = ttk.LabelFrame(outer, text="2. Servisi", padding=10)
        services_frame.pack(fill="x", pady=(0, 10))

        self._sign_var = tk.BooleanVar(value=False)
        self._encrypt_var = tk.BooleanVar(value=False)
        self._compress_var = tk.BooleanVar(value=False)
        self._radix64_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(
            services_frame, text="Potpisivanje", variable=self._sign_var
        ).pack(side="left")
        ttk.Checkbutton(
            services_frame, text="Šifrovanje", variable=self._encrypt_var
        ).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(
            services_frame, text="Kompresija", variable=self._compress_var
        ).pack(side="left", padx=(12, 0))
        ttk.Checkbutton(
            services_frame, text="Radix-64", variable=self._radix64_var
        ).pack(side="left", padx=(12, 0))

        # --- Ključevi i algoritam ---
        keys_frame = ttk.LabelFrame(outer, text="3. Ključevi i algoritam", padding=10)
        keys_frame.pack(fill="x", pady=(0, 10))

        self._sender_var = tk.StringVar()
        self._recipient_var = tk.StringVar()
        self._algo_var = tk.StringVar(value=ALGORITHMS[0])

        ttk.Label(keys_frame, text="Potpisnik (privatni):").grid(row=0, column=0, sticky="w", pady=2)
        self._sender_combo = ttk.Combobox(
            keys_frame, textvariable=self._sender_var, state="readonly", width=45
        )
        self._sender_combo.grid(row=0, column=1, sticky="w", pady=2)

        ttk.Label(keys_frame, text="Primalac (javni):").grid(row=1, column=0, sticky="w", pady=2)
        self._recipient_combo = ttk.Combobox(
            keys_frame, textvariable=self._recipient_var, state="readonly", width=45
        )
        self._recipient_combo.grid(row=1, column=1, sticky="w", pady=2)

        ttk.Label(keys_frame, text="Algoritam:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Combobox(
            keys_frame, textvariable=self._algo_var, values=ALGORITHMS, state="readonly", width=15
        ).grid(row=2, column=1, sticky="w", pady=2)

        ttk.Button(keys_frame, text="Osveži ključeve", command=self._refresh_keys).grid(
            row=3, column=1, sticky="w", pady=(8, 0)
        )

        # --- Akcija + status ---
        action_frame = ttk.Frame(outer)
        action_frame.pack(fill="x")
        ttk.Button(action_frame, text="Pošalji (sačuvaj kao...)", command=self._on_send).pack(
            side="left"
        )
        self._status_var = tk.StringVar(value="Spremno za slanje.")
        ttk.Label(action_frame, textvariable=self._status_var, foreground="#444").pack(
            side="left", padx=(12, 0)
        )

    # ------------------------------------------------------------- handlers

    def _on_choose_file(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Izaberite fajl za slanje")
        if not path:
            return
        self._selected_path = path
        self._path_var.set(os.path.basename(path))

    def _on_clear_file(self) -> None:
        self._selected_path = None
        self._path_var.set("(ili izaberite fajl umesto teksta)")

    def _on_send(self) -> None:
        data, filename = self._collect_message()
        if data is None:
            return

        authentication = self._sign_var.get()
        confidentiality = self._encrypt_var.get()

        sender_key_id = None
        if authentication:
            sender_key_id = self._sender_map.get(self._sender_var.get())
            if sender_key_id is None:
                show_error(self, "Izaberite privatni ključ za potpisivanje.")
                return

        recipient_key_id = None
        algorithm = None
        if confidentiality:
            recipient_key_id = self._recipient_map.get(self._recipient_var.get())
            if recipient_key_id is None:
                show_error(self, "Izaberite javni ključ primaoca za šifrovanje.")
                return
            algorithm = self._algo_var.get()

        def get_password(entry):
            return ask_password(self, entry)

        try:
            result = send_message(
                data,
                filename,
                authentication=authentication,
                confidentiality=confidentiality,
                compression=self._compress_var.get(),
                is_radix64=self._radix64_var.get(),
                symmetric_algorithm=algorithm,
                sender_key_id=sender_key_id,
                recipient_key_id=recipient_key_id,
                public_ring=self.public_ring,
                private_ring=self.private_ring,
                get_password=get_password,
            )
        except PasswordCancelled:
            self._status_var.set("Slanje otkazano (lozinka nije uneta).")
            return
        except Exception as e:
            show_error(self, f"Neočekivana greška pri slanju:\n{e}")
            self._status_var.set("Slanje neuspešno (neočekivana greška).")
            return

        if not result.success:
            show_error(self, result.error_msg or "Slanje poruke nije uspelo.")
            self._status_var.set(f"Slanje neuspešno: {result.error_msg}")
            return

        self._save_result(result.data)

    def _save_result(self, output: bytes) -> None:
        is_radix64 = self._radix64_var.get()
        default_ext = ".asc" if is_radix64 else ".pgp"
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Sačuvaj PGP poruku",
            defaultextension=default_ext,
            initialfile=f"poruka{default_ext}",
            filetypes=[("PGP fajlovi", "*.pgp"), ("Radix-64 fajlovi", "*.asc"), ("Svi fajlovi", "*.*")],
        )
        if not path:
            self._status_var.set("Poruka sastavljena, ali nije sačuvana.")
            return

        try:
            with open(path, "wb") as f:
                f.write(output)
        except OSError as e:
            show_error(self, f"Čuvanje fajla nije uspelo:\n{e}")
            return

        self._status_var.set(f"Poruka sačuvana: {path}")
        show_info(self, "Slanje", f"Poruka uspešno sačuvana:\n{path}")

    # --------------------------------------------------------------- helpers

    def _collect_message(self) -> tuple[bytes | None, str]:
        """Vraća (data, filename). Ako je izabran fajl koristi njega, inače upisani tekst."""
        if self._selected_path:
            try:
                with open(self._selected_path, "rb") as f:
                    return f.read(), os.path.basename(self._selected_path)
            except OSError as e:
                show_error(self, f"Fajl nije moguće pročitati:\n{e}")
                return None, ""

        text = self._text.get("1.0", "end-1c")
        if not text:
            show_error(self, "Unesite poruku ili izaberite fajl.")
            return None, ""
        return text.encode("utf-8"), "poruka.txt"

    def _refresh_keys(self) -> None:
        self._sender_map = {
            f"{e.user_id} [{e.key_id}]": e.key_id for e in self.private_ring.get_all()
        }
        self._recipient_map = {
            f"{e.user_id} [{e.key_id}]": e.key_id for e in self.public_ring.get_all()
        }
        self._sender_combo["values"] = list(self._sender_map.keys())
        self._recipient_combo["values"] = list(self._recipient_map.keys())


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Slanje poruke")
    root.geometry("640x620")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    public_ring = PublicKeyRing("public_key_ring.txt")
    private_ring = PrivateKeyRing("private_key_ring.txt")
    notebook.add(TabSend(notebook, public_ring, private_ring), text="Slanje")

    root.mainloop()
