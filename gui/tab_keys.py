"""
Modul: tab_keys.py
Opis:  GUI tab za upravljanje ključevima.
       Prikazuje prsten ključeva (javni + privatni), generiše nove parove,
       briše ih i uvozi/izvozi javni ključ ili ceo par u .pem formatu.
"""

import time
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog, messagebox

from crypto import rsa
from message.keyring import PublicKeyRing, PrivateKeyRing, PublicKeyEntry, PrivateKeyEntry
from gui.tab_dialogs import ask_password, show_error, show_info, PasswordCancelled

KEY_SIZES = [1024, 2048]


class TabKeys(ttk.Frame):
    """
    Tab za upravljanje ključevima.

    Tok:
      1. Korisnik vidi tabelu svih ključeva u prstenu (tip, key ID, ime, email, datum).
      2. Formom dole generiše novi par (ime/email/lozinka/veličina) — privatni ključ se
         odmah šifruje lozinkom (SHA-1(lozinka) -> AES128) i čuva u privatnom prstenu.
      3. Dugmadima može da obriše izabrani ključ ili da uveze/izveze .pem fajlove.
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

        self._build_ui()
        self._refresh()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=15)
        outer.pack(fill="both", expand=True)

        # --- Tabela ključeva ---
        table_frame = ttk.LabelFrame(outer, text="Prsten ključeva", padding=10)
        table_frame.pack(fill="both", expand=True, pady=(0, 10))

        columns = ("tip", "key_id", "ime", "email", "datum")
        self._tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)
        for col, text, width in [
            ("tip", "Tip", 90),
            ("key_id", "Key ID", 150),
            ("ime", "Ime", 130),
            ("email", "Email", 180),
            ("datum", "Datum", 130),
        ]:
            self._tree.heading(col, text=text)
            self._tree.column(col, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        self._tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # --- Dugmad za izabrani ključ ---
        btn_frame = ttk.Frame(outer)
        btn_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(btn_frame, text="Obriši", command=self._on_delete).pack(side="left")
        ttk.Button(btn_frame, text="Izvezi javni...", command=self._on_export_public).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btn_frame, text="Izvezi par...", command=self._on_export_pair).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btn_frame, text="Uvezi javni...", command=self._on_import_public).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btn_frame, text="Uvezi par...", command=self._on_import_pair).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(btn_frame, text="Osveži", command=self._refresh).pack(side="right")

        # --- Forma za generisanje novog para ---
        gen_frame = ttk.LabelFrame(outer, text="Generiši novi par ključeva", padding=10)
        gen_frame.pack(fill="x")

        self._name_var = tk.StringVar()
        self._email_var = tk.StringVar()
        self._password_var = tk.StringVar()
        self._size_var = tk.StringVar(value=str(KEY_SIZES[-1]))

        ttk.Label(gen_frame, text="Ime:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Entry(gen_frame, textvariable=self._name_var, width=28).grid(
            row=0, column=1, sticky="w", pady=2
        )

        ttk.Label(gen_frame, text="Email:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(gen_frame, textvariable=self._email_var, width=28).grid(
            row=1, column=1, sticky="w", pady=2
        )

        ttk.Label(gen_frame, text="Lozinka:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(gen_frame, textvariable=self._password_var, show="*", width=28).grid(
            row=2, column=1, sticky="w", pady=2
        )

        ttk.Label(gen_frame, text="Veličina:").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Combobox(
            gen_frame,
            textvariable=self._size_var,
            values=[str(s) for s in KEY_SIZES],
            state="readonly",
            width=10,
        ).grid(row=3, column=1, sticky="w", pady=2)

        ttk.Button(gen_frame, text="Generiši par ključeva", command=self._on_generate).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )

    # ------------------------------------------------------------- handlers

    def _on_generate(self) -> None:
        name = self._name_var.get().strip()
        email = self._email_var.get().strip()
        password = self._password_var.get()

        if not name or not email or not password:
            show_error(self, "Ime, email i lozinka su obavezni.")
            return

        key_size = int(self._size_var.get())
        private_pem, public_pem = rsa.generate_keys(key_size)
        key_id = rsa.get_key_id(public_pem)
        encrypted_private, iv = rsa.protect_private_key(private_pem, password)

        timestamp = int(time.time())
        self.public_ring.add_key(PublicKeyEntry(key_id, timestamp, name, email, public_pem))
        self.private_ring.add_key(
            PrivateKeyEntry(key_id, timestamp, name, email, public_pem, encrypted_private, iv)
        )

        self._name_var.set("")
        self._email_var.set("")
        self._password_var.set("")
        self._refresh()
        show_info(self, "Ključevi", f"Generisan par ključeva.\nKey ID: {key_id}")

    def _on_delete(self) -> None:
        key_id = self._selected_key_id()
        if key_id is None:
            show_error(self, "Niste izabrali ključ.")
            return

        if not messagebox.askyesno(
            "Brisanje", f"Obrisati ključ {key_id}?", parent=self
        ):
            return

        self.public_ring.remove_key(key_id)
        self.private_ring.remove_key(key_id)
        self._refresh()

    def _on_export_public(self) -> None:
        key_id = self._selected_key_id()
        if key_id is None:
            show_error(self, "Niste izabrali ključ.")
            return

        entry = self.public_ring.get_by_id(key_id)
        if entry is None:
            show_error(self, "Za izabrani unos ne postoji javni ključ.")
            return

        path = filedialog.asksaveasfilename(
            parent=self,
            title="Izvezi javni ključ",
            defaultextension=".pem",
            initialfile=f"{key_id}_public.pem",
            filetypes=[("PEM ključevi", "*.pem"), ("Svi fajlovi", "*.*")],
        )
        if not path:
            return

        rsa.export_pem(entry.public_key_pem, path)
        show_info(self, "Izvoz", f"Javni ključ sačuvan:\n{path}")

    def _on_export_pair(self) -> None:
        key_id = self._selected_key_id()
        if key_id is None:
            show_error(self, "Niste izabrali ključ.")
            return

        entry = self.private_ring.get_by_id(key_id)
        if entry is None:
            show_error(self, "Za izabrani unos ne postoji privatni ključ.")
            return

        try:
            password = ask_password(self, entry)
        except PasswordCancelled:
            return

        try:
            private_pem = rsa.unlock_private_key(entry.encrypted_private_key, entry.iv, password)
            rsa.public_pem_from_private(private_pem)  # validacija lozinke
        except Exception:
            show_error(self, "Pogrešna lozinka ili oštećen ključ.")
            return

        path = filedialog.asksaveasfilename(
            parent=self,
            title="Izvezi par ključeva",
            defaultextension=".pem",
            initialfile=f"{key_id}_keypair.pem",
            filetypes=[("PEM ključevi", "*.pem"), ("Svi fajlovi", "*.*")],
        )
        if not path:
            return

        rsa.export_pem(private_pem, path)
        show_info(self, "Izvoz", f"Par ključeva sačuvan:\n{path}")

    def _on_import_public(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Uvezi javni ključ",
            filetypes=[("PEM ključevi", "*.pem"), ("Svi fajlovi", "*.*")],
        )
        if not path:
            return

        try:
            public_pem = rsa.import_public_pem(path)
        except Exception:
            show_error(self, "Fajl nije validan javni ključ.")
            return

        name = simpledialog.askstring("Uvoz", "Ime vlasnika ključa:", parent=self)
        if not name:
            return
        email = simpledialog.askstring("Uvoz", "Email vlasnika ključa:", parent=self)
        if not email:
            return

        key_id = rsa.get_key_id(public_pem)
        self.public_ring.add_key(
            PublicKeyEntry(key_id, int(time.time()), name.strip(), email.strip(), public_pem)
        )
        self._refresh()
        show_info(self, "Uvoz", f"Uvezen javni ključ.\nKey ID: {key_id}")

    def _on_import_pair(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Uvezi par ključeva",
            filetypes=[("PEM ključevi", "*.pem"), ("Svi fajlovi", "*.*")],
        )
        if not path:
            return

        try:
            private_pem = rsa.import_private_pem(path)
            public_pem = rsa.public_pem_from_private(private_pem)
        except Exception:
            show_error(self, "Fajl nije validan privatni ključ.")
            return

        name = simpledialog.askstring("Uvoz", "Ime vlasnika ključa:", parent=self)
        if not name:
            return
        email = simpledialog.askstring("Uvoz", "Email vlasnika ključa:", parent=self)
        if not email:
            return
        password = simpledialog.askstring(
            "Uvoz", "Postavi lozinku za zaštitu privatnog ključa:", parent=self, show="*"
        )
        if not password:
            return

        key_id = rsa.get_key_id(public_pem)
        encrypted_private, iv = rsa.protect_private_key(private_pem, password)
        timestamp = int(time.time())
        self.public_ring.add_key(
            PublicKeyEntry(key_id, timestamp, name.strip(), email.strip(), public_pem)
        )
        self.private_ring.add_key(
            PrivateKeyEntry(
                key_id, timestamp, name.strip(), email.strip(), public_pem, encrypted_private, iv
            )
        )
        self._refresh()
        show_info(self, "Uvoz", f"Uvezen par ključeva.\nKey ID: {key_id}")

    # --------------------------------------------------------------- helpers

    def _refresh(self) -> None:
        self._tree.delete(*self._tree.get_children())

        key_ids = {e.key_id for e in self.public_ring.get_all()}
        key_ids |= {e.key_id for e in self.private_ring.get_all()}

        for key_id in sorted(key_ids):
            public = self.public_ring.get_by_id(key_id)
            private = self.private_ring.get_by_id(key_id)
            entry = private or public

            if public and private:
                tip = "Par"
            elif public:
                tip = "Javni"
            else:
                tip = "Privatni"

            datum = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.timestamp))
            self._tree.insert(
                "", "end", iid=key_id, values=(tip, key_id, entry.name, entry.email, datum)
            )

    def _selected_key_id(self) -> str | None:
        selection = self._tree.selection()
        return selection[0] if selection else None


if __name__ == "__main__":
    root = tk.Tk()
    root.title("Upravljanje ključevima")
    root.geometry("760x560")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    public_ring = PublicKeyRing("public_key_ring.txt")
    private_ring = PrivateKeyRing("private_key_ring.txt")
    notebook.add(TabKeys(notebook, public_ring, private_ring), text="Ključevi")

    root.mainloop()
