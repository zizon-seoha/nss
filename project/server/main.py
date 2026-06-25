import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

import models
from database import Base, engine, get_db

# Secrets from env, but fall back to dev defaults so local test runs with no setup.
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "dev-admin-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Face Detection Auth Server")


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # Permanent key the desktop app (main.py) uses.
    api_key: str


class VerifyRequest(BaseModel):
    token: str


class KeyRequest(BaseModel):
    key: str


class UserOut(BaseModel):
    email: str
    is_allowed: bool


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# --------------------------------------------------------------------------- #
# Web page: register + login in the browser. Login shows the permanent key.
# --------------------------------------------------------------------------- #
INDEX_HTML = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>얼굴인식 회원</title>
<style>
  body { font-family: 'Malgun Gothic', sans-serif; max-width: 440px; margin: 36px auto; padding: 0 16px; color: #222; }
  h1 { text-align: center; }
  .card { border: 1px solid #ddd; border-radius: 10px; padding: 18px 20px; margin: 18px 0; }
  .card h2 { margin: 0 0 12px; font-size: 18px; }
  input { width: 100%; box-sizing: border-box; padding: 10px; margin: 6px 0; font-size: 15px; border: 1px solid #ccc; border-radius: 6px; }
  button { width: 100%; padding: 11px; font-size: 15px; border: 0; border-radius: 6px; cursor: pointer; }
  .primary { background: #1976d2; color: #fff; }
  .ghost { background: #eee; margin-top: 8px; }
  .msg { font-size: 13px; margin: 8px 0 0; min-height: 18px; }
  .ok { color: #2e7d32; }
  .err { color: #c62828; }
  #key_box { margin-top: 14px; padding: 12px; background: #f1f8e9; border-radius: 8px; }
  textarea { width: 100%; box-sizing: border-box; font-size: 14px; padding: 8px; border: 1px solid #c5e1a5; border-radius: 6px; resize: none; }
</style>
</head>
<body>
  <h1>얼굴인식 회원</h1>

  <div class="card">
    <h2>회원가입</h2>
    <input id="r_email" placeholder="이메일" autocomplete="off">
    <input id="r_pw" type="password" placeholder="비밀번호">
    <button class="primary" onclick="doRegister()">회원가입</button>
    <p id="r_msg" class="msg"></p>
  </div>

  <div class="card">
    <h2>로그인</h2>
    <input id="l_email" placeholder="이메일" autocomplete="off">
    <input id="l_pw" type="password" placeholder="비밀번호">
    <button class="primary" onclick="doLogin()">로그인</button>
    <p id="l_msg" class="msg"></p>
    <div id="key_box" style="display:none">
      <b>내 키</b> — 아래 키를 복사해 프로그램에 입력하세요.
      <textarea id="key_out" rows="2" readonly></textarea>
      <button class="ghost" onclick="copyKey()">키 복사</button>
    </div>
  </div>

<script>
async function doRegister() {
  const email = document.getElementById('r_email').value.trim();
  const pw = document.getElementById('r_pw').value;
  const msg = document.getElementById('r_msg');
  if (!email || !pw) { msg.className = 'msg err'; msg.textContent = '이메일과 비밀번호를 입력하세요.'; return; }
  const r = await fetch('/register', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({email, password: pw}) });
  const d = await r.json().catch(() => ({}));
  if (r.ok) { msg.className = 'msg ok'; msg.textContent = '가입 완료! 관리자 승인 후 로그인하세요.'; }
  else { msg.className = 'msg err'; msg.textContent = d.detail || '가입 실패'; }
}
async function doLogin() {
  const email = document.getElementById('l_email').value.trim();
  const pw = document.getElementById('l_pw').value;
  const msg = document.getElementById('l_msg');
  const box = document.getElementById('key_box');
  if (!email || !pw) { msg.className = 'msg err'; msg.textContent = '이메일과 비밀번호를 입력하세요.'; return; }
  const body = new URLSearchParams({ username: email, password: pw });
  const r = await fetch('/login', { method: 'POST', body });
  const d = await r.json().catch(() => ({}));
  if (r.ok) {
    msg.className = 'msg ok'; msg.textContent = '로그인 성공!';
    document.getElementById('key_out').value = d.api_key;
    box.style.display = 'block';
  } else {
    msg.className = 'msg err'; msg.textContent = d.detail || '로그인 실패';
    box.style.display = 'none';
  }
}
function copyKey() {
  const t = document.getElementById('key_out');
  t.select();
  navigator.clipboard.writeText(t.value).catch(() => document.execCommand('copy'));
}
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다")
    # New users default to is_allowed=False; cannot log in until admin approves.
    user = models.User(
        email=req.email,
        hashed_password=hash_password(req.password),
        is_allowed=False,
    )
    db.add(user)
    db.commit()
    return {"detail": "Registered. Wait for admin approval."}


@app.post("/login", response_model=TokenResponse)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # OAuth2PasswordRequestForm uses 'username' field; client sends email there.
    user = db.query(models.User).filter(models.User.email == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 틀렸습니다")
    if not user.is_allowed:
        raise HTTPException(status_code=403, detail="아직 관리자 승인 대기 중입니다")
    # Generate the permanent key once, on first successful login.
    if not user.api_key:
        user.api_key = secrets.token_urlsafe(24)
        db.commit()
    return TokenResponse(access_token=create_access_token(user.email), api_key=user.api_key)


@app.post("/verify")
def verify(req: VerifyRequest, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(req.token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.is_allowed:
        raise HTTPException(status_code=403, detail="Account not allowed")
    return {"email": email, "valid": True}


@app.post("/verify-key")
def verify_key(req: KeyRequest, db: Session = Depends(get_db)):
    # Used by the desktop app. Key works only while the account stays approved.
    user = db.query(models.User).filter(models.User.api_key == req.key).first()
    if not user or not user.is_allowed:
        raise HTTPException(status_code=403, detail="잘못된 키이거나 승인되지 않은 계정입니다")
    return {"email": user.email, "valid": True}


@app.get("/admin/users", response_model=list[UserOut])
def list_users(x_admin_key: str = Header(...), db: Session = Depends(get_db)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Bad admin key")
    users = db.query(models.User).order_by(models.User.is_allowed, models.User.email).all()
    return [UserOut(email=u.email, is_allowed=u.is_allowed) for u in users]


@app.post("/admin/approve/{email}")
def approve(email: str, x_admin_key: str = Header(...), db: Session = Depends(get_db)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Bad admin key")
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_allowed = True
    db.commit()
    return {"detail": f"{email} approved"}


@app.post("/admin/revoke/{email}")
def revoke(email: str, x_admin_key: str = Header(...), db: Session = Depends(get_db)):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Bad admin key")
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_allowed = False
    db.commit()
    return {"detail": f"{email} revoked"}
