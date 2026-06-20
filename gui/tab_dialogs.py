"""
Modul: dialogs.py
Opis:  Zajednicki GUI dijalozi - unos lozinke, prikaz gresaka i prikaz rezultata prijema poruke.
       Koriste ih i tab_send.py i tab_receive.py.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from message.keyring import PrivateKeyEntry


class PasswordCancelled(Exception):
    """Diže se kada korisnik otkaže unos lozinke u dijalogu."""


def ask_password(parent: tk.Widget, entry: PrivateKeyEntry) -> str:
    """
    Modalni dijalog koji traži lozinku za dati privatni ključ.

    Vraća unetu lozinku. Ako korisnik klikne "Otkaži" ili zatvori prozor,
    diže PasswordCancelled (umesto da vraća None), tako da pozivni kod
    (receiver.py / sender.py) može da to hvata kao deo iste exception
    hijerarhije kao i ostale greške u toku.
    """
    dialog = tk.Toplevel(parent)
    dialog.title("Unos lozinke")
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()

    result: dict[str, str | None] = {"password": None}

    frame = ttk.Frame(dialog, padding=15)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text="Potreban je privatni ključ:").pack(anchor="w")
    ttk.Label(frame, text=entry.user_id, font=("TkDefaultFont", 9, "bold")).pack(
        anchor="w", pady=(0, 10)
    )
    ttk.Label(frame, text="Lozinka:").pack(anchor="w")

    password_var = tk.StringVar()
    entry_widget = ttk.Entry(frame, textvariable=password_var, show="*", width=30)
    entry_widget.pack(fill="x", pady=(0, 10))
    entry_widget.focus_set()

    def on_ok(_event=None) -> None:
        result["password"] = password_var.get()
        dialog.destroy()

    def on_cancel(_event=None) -> None:
        dialog.destroy()

    btn_frame = ttk.Frame(frame)
    btn_frame.pack(fill="x")
    ttk.Button(btn_frame, text="Otkaži", command=on_cancel).pack(side="right", padx=(5, 0))
    ttk.Button(btn_frame, text="OK", command=on_ok).pack(side="right")

    dialog.bind("<Return>", on_ok)
    dialog.bind("<Escape>", on_cancel)

    # centriranje u odnosu na roditeljski prozor
    dialog.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    dialog.wait_window()

    if result["password"] is None:
        raise PasswordCancelled("Korisnik je otkazao unos lozinke")
    return result["password"]


def show_error(parent: tk.Widget, message: str) -> None:
    """Prikazuje jasnu poruku o grešci (npr. pogrešna lozinka, korumpiran fajl, nevažeći potpis)."""
    messagebox.showerror("Greška", message, parent=parent)


def show_info(parent: tk.Widget, title: str, message: str) -> None:
    messagebox.showinfo(title, message, parent=parent)


def show_receive_result(parent: tk.Widget, result) -> None:
    """
    Prikazuje ishod uspešnog prijema: ime fajla, da li je poruka bila potpisana,
    i ako jeste, da li je potpis validan i ko je potpisnik.

    'result' je ReceivedResult iz message/receiver.py (success=True u ovoj tački).
    """
    lines = [f"Fajl: {result.filename}"]

    if not result.signature_present:
        lines.append("Poruka nije bila potpisana.")
    elif result.signature_valid is True:
        lines.append(f"Potpis je VALIDAN.")
        lines.append(f"Potpisnik: {result.sender_user_id}")
    elif result.signature_valid is False:
        lines.append("Potpis NIJE validan!")
        if result.sender_user_id:
            lines.append(f"(Pronađen javni ključ: {result.sender_user_id})")
    else:
        lines.append("Potpis NIJE moguće verifikovati - nepoznat javni ključ pošiljaoca.")

    messagebox.showinfo("Rezultat prijema", "\n".join(lines), parent=parent)