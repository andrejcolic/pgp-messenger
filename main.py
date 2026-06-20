"""
Modul: main.py
Opis:  Entry point aplikacije. Pravi prstenove ključeva i glavni prozor sa
       tabovima: Ključevi, Slanje, Prijem.
"""

import tkinter as tk
from tkinter import ttk

from message.keyring import PublicKeyRing, PrivateKeyRing
from gui.tab_keys import TabKeys
from gui.tab_send import TabSend
from gui.tab_recieve import TabReceive

PUBLIC_RING_PATH = "public_key_ring.txt"
PRIVATE_RING_PATH = "private_key_ring.txt"


def main() -> None:
    public_ring = PublicKeyRing(PUBLIC_RING_PATH)
    private_ring = PrivateKeyRing(PRIVATE_RING_PATH)

    root = tk.Tk()
    root.title("PGP Messenger — Zaštita podataka")
    root.geometry("780x640")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    notebook.add(TabKeys(notebook, public_ring, private_ring), text="Ključevi")
    notebook.add(TabSend(notebook, public_ring, private_ring), text="Slanje")
    notebook.add(TabReceive(notebook, public_ring=public_ring, private_ring=private_ring),
                 text="Prijem")

    root.mainloop()


if __name__ == "__main__":
    main()
