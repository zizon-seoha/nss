import tkinter as tk

import auth


class KeyWindow:
    """Key-entry window.

    User registers/logs in on the website, copies their key, and pastes it here.
    If a saved key still verifies, skip the window (auto-start).
    Call .run() -> returns True when the key is valid, False if the user closed it.
    """

    def __init__(self):
        self.success = False
        self.root = tk.Tk()
        self.root.title("키 입력")
        self.root.geometry("440x300")
        self.root.resizable(False, False)
        self.root.configure(bg="white")

        title_font = ("Malgun Gothic", 17, "bold")
        label_font = ("Malgun Gothic", 11)

        tk.Label(self.root, text="얼굴 인식 프로그램", font=title_font, bg="white").pack(pady=(26, 4))
        tk.Label(
            self.root,
            text="웹사이트에서 로그인하면 받은 '키'를 아래에 붙여넣으세요.",
            font=("Malgun Gothic", 10),
            fg="#666",
            bg="white",
        ).pack(pady=(0, 16))

        tk.Label(self.root, text="키", font=label_font, bg="white").pack(anchor="w", padx=40)
        self.key_entry = tk.Entry(self.root, width=40, font=("Malgun Gothic", 12))
        self.key_entry.pack(pady=(2, 16), ipady=4)
        self.key_entry.bind("<Return>", lambda _e: self._on_submit())
        self.key_entry.focus()

        tk.Button(
            self.root, text="확인", width=16, font=("Malgun Gothic", 12, "bold"),
            fg="white", bg="#1976d2", activebackground="#1565c0",
            command=self._on_submit,
        ).pack(pady=4, ipady=3)

        self.status = tk.Label(self.root, text="", fg="#c62828", bg="white",
                               font=("Malgun Gothic", 10), wraplength=380)
        self.status.pack(pady=12)

    def _on_submit(self):
        key = self.key_entry.get().strip()
        ok, msg = auth.verify_key(key)
        if ok:
            auth.save_key(key)
            self.success = True
            self.root.destroy()
        else:
            self.status.config(text=msg)

    def run(self) -> bool:
        # Try silent auto-start with the saved key first.
        saved = auth.load_key()
        if saved:
            ok, _ = auth.verify_key(saved)
            if ok:
                self.root.destroy()
                return True
            auth.clear_key()  # stale/revoked key -> drop it, ask again
        self.root.mainloop()
        return self.success


def require_login() -> bool:
    return KeyWindow().run()


if __name__ == "__main__":
    print("granted" if require_login() else "denied")
