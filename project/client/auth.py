import json
import os

import requests

# CHANGE THIS to your Render URL after deploy, e.g. "https://my-auth.onrender.com"
SERVER_URL = "http://127.0.0.1:8000"

# Key cached next to the user's home so a PyInstaller .exe can still write it.
KEY_PATH = os.path.join(os.path.expanduser("~"), ".face_detection_key")

TIMEOUT = 10


def save_key(key: str) -> None:
    with open(KEY_PATH, "w", encoding="utf-8") as f:
        json.dump({"key": key}, f)


def load_key() -> str | None:
    if not os.path.exists(KEY_PATH):
        return None
    try:
        with open(KEY_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("key")
    except (json.JSONDecodeError, OSError):
        return None


def clear_key() -> None:
    if os.path.exists(KEY_PATH):
        os.remove(KEY_PATH)


def verify_key(key: str) -> tuple[bool, str]:
    """Ask the server whether this key belongs to an approved account.

    Returns (ok, message).
    """
    if not key:
        return False, "키를 입력하세요."
    try:
        r = requests.post(
            f"{SERVER_URL}/verify-key",
            json={"key": key},
            timeout=TIMEOUT,
        )
    except requests.RequestException as e:
        return False, f"서버에 연결할 수 없습니다: {e}"
    if r.status_code == 200:
        return True, "확인됨"
    return False, _detail(r)


def _detail(resp) -> str:
    try:
        return resp.json().get("detail", resp.text)
    except ValueError:
        return resp.text
