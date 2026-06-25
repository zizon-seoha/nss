"""관리자 승인 GUI.

프로그래밍을 몰라도 쓸 수 있는 승인 화면.
실행: python admin_ui.py
사용: 서버를 켠 상태에서 이 창을 열고 '새로고침' -> 대기 중인 사용자 옆 '승인' 클릭.
"""

import json
import tkinter as tk
from tkinter import messagebox, ttk
from urllib import error, request

# Render 배포 주소. 관리자 키는 Render 환경변수 ADMIN_KEY에 넣은 값과 같아야 함.
DEFAULT_SERVER_URL = "https://face-auth-dfva.onrender.com"
DEFAULT_ADMIN_KEY = ""

TIMEOUT = 10


def _call(method: str, url: str, admin_key: str):
    """서버에 요청을 보내고 (성공여부, 데이터또는메시지)를 돌려준다."""
    req = request.Request(url, method=method, headers={"X-Admin-Key": admin_key})
    try:
        with request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
            return True, json.loads(body) if body else None
    except error.HTTPError as e:
        try:
            detail = json.loads(e.read().decode("utf-8")).get("detail", str(e))
        except Exception:
            detail = str(e)
        return False, detail
    except error.URLError as e:
        return False, f"서버에 연결할 수 없습니다: {e.reason}"


class AdminWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("관리자 승인 화면")
        self.root.geometry("560x520")
        self.root.minsize(480, 400)

        big = ("Malgun Gothic", 12)
        title_font = ("Malgun Gothic", 16, "bold")

        tk.Label(self.root, text="회원 승인 관리", font=title_font).pack(pady=(16, 4))
        tk.Label(
            self.root,
            text="대기 중인 회원 옆 [승인] 버튼을 누르면 로그인할 수 있게 됩니다.",
            font=("Malgun Gothic", 10),
            fg="#555",
        ).pack(pady=(0, 10))

        # 설정 영역 (서버 주소 + 관리자 키)
        cfg = tk.Frame(self.root)
        cfg.pack(fill="x", padx=16)
        tk.Label(cfg, text="서버 주소", font=("Malgun Gothic", 10)).grid(row=0, column=0, sticky="w")
        self.url_entry = tk.Entry(cfg, font=("Malgun Gothic", 10), width=46)
        self.url_entry.insert(0, DEFAULT_SERVER_URL)
        self.url_entry.grid(row=0, column=1, padx=6, pady=2, sticky="we")
        tk.Label(cfg, text="관리자 키", font=("Malgun Gothic", 10)).grid(row=1, column=0, sticky="w")
        self.key_entry = tk.Entry(cfg, font=("Malgun Gothic", 10), width=46, show="*")
        self.key_entry.insert(0, DEFAULT_ADMIN_KEY)
        self.key_entry.grid(row=1, column=1, padx=6, pady=2, sticky="we")
        cfg.columnconfigure(1, weight=1)

        tk.Button(
            self.root,
            text="↻ 새로고침 (회원 목록 불러오기)",
            font=big,
            command=self.refresh,
        ).pack(pady=12)

        # 회원 목록 표
        cols = ("email", "status")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=10)
        self.tree.heading("email", text="이메일")
        self.tree.heading("status", text="상태")
        self.tree.column("email", width=320)
        self.tree.column("status", width=120, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        style = ttk.Style()
        style.configure("Treeview", font=("Malgun Gothic", 11), rowheight=28)
        style.configure("Treeview.Heading", font=("Malgun Gothic", 11, "bold"))

        btns = tk.Frame(self.root)
        btns.pack(pady=(0, 12))
        tk.Button(btns, text="선택한 회원 승인 ✔", font=big, fg="white", bg="#2e7d32",
                  command=self.approve_selected).grid(row=0, column=0, padx=6)
        tk.Button(btns, text="선택한 회원 차단 ✖", font=big,
                  command=self.revoke_selected).grid(row=0, column=1, padx=6)

        self.status = tk.Label(self.root, text="시작하려면 [새로고침]을 누르세요.",
                               font=("Malgun Gothic", 10), fg="#555")
        self.status.pack(pady=(0, 10))

    def _base(self):
        return self.url_entry.get().strip().rstrip("/")

    def _key(self):
        return self.key_entry.get().strip()

    def _selected_email(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("선택 필요", "목록에서 회원을 먼저 클릭해 선택하세요.")
            return None
        return self.tree.item(sel[0], "values")[0]

    def refresh(self):
        ok, data = _call("GET", f"{self._base()}/admin/users", self._key())
        if not ok:
            self.status.config(text=f"불러오기 실패: {data}", fg="#c62828")
            return
        self.tree.delete(*self.tree.get_children())
        pending = 0
        for u in data:
            allowed = u["is_allowed"]
            label = "승인됨" if allowed else "대기 중"
            if not allowed:
                pending += 1
            self.tree.insert("", "end", values=(u["email"], label))
        self.status.config(
            text=f"전체 {len(data)}명 · 대기 중 {pending}명", fg="#555"
        )

    def approve_selected(self):
        email = self._selected_email()
        if not email:
            return
        ok, data = _call("POST", f"{self._base()}/admin/approve/{email}", self._key())
        if ok:
            self.status.config(text=f"{email} 승인 완료", fg="#2e7d32")
            self.refresh()
        else:
            self.status.config(text=f"승인 실패: {data}", fg="#c62828")

    def revoke_selected(self):
        email = self._selected_email()
        if not email:
            return
        if not messagebox.askyesno("확인", f"{email} 의 로그인 권한을 차단할까요?"):
            return
        ok, data = _call("POST", f"{self._base()}/admin/revoke/{email}", self._key())
        if ok:
            self.status.config(text=f"{email} 차단 완료", fg="#555")
            self.refresh()
        else:
            self.status.config(text=f"차단 실패: {data}", fg="#c62828")

    def run(self):
        self.root.after(300, self.refresh)  # 창 뜨자마자 한 번 자동 로드
        self.root.mainloop()


if __name__ == "__main__":
    AdminWindow().run()
