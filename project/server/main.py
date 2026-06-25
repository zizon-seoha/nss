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
<title>얼굴인식</title>
<link rel="stylesheet" as="style" crossorigin href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css">
<style>
  :root {
    --bg: #141517; --card: #1E2023; --input: #26282C; --line: #303338;
    --text: #EDEEF0; --sub: #8C9099; --accent: #3182F6; --accent-press: #2272EB;
    --ok: #4ED17F; --err: #FF6B6B;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: var(--bg); color: var(--text); padding: 24px;
    font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, 'Malgun Gothic', sans-serif;
  }
  .card { width: 100%; max-width: 380px; background: var(--card); border-radius: 24px; padding: 34px 26px; }
  .logo { width: 52px; height: 52px; border-radius: 16px; background: var(--accent); display: flex;
          align-items: center; justify-content: center; font-size: 28px; margin: 0 auto 16px; }
  h1 { margin: 0; text-align: center; font-size: 22px; font-weight: 700; letter-spacing: -0.4px; }
  .desc { text-align: center; color: var(--sub); font-size: 13px; margin: 8px 0 24px; }
  .tabs { display: flex; background: var(--input); border-radius: 13px; padding: 4px; margin-bottom: 22px; }
  .tab { flex: 1; text-align: center; padding: 10px 0; font-size: 14px; font-weight: 600; color: var(--sub);
         border-radius: 10px; cursor: pointer; transition: .15s; user-select: none; }
  .tab.active { background: var(--card); color: var(--text); box-shadow: 0 1px 5px rgba(0,0,0,.35); }
  form { display: none; }
  form.active { display: block; }
  label { display: block; font-size: 12px; color: var(--sub); margin: 0 0 6px 2px; }
  input { width: 100%; padding: 14px; margin-bottom: 14px; font-size: 15px; color: var(--text);
          background: var(--input); border: 1px solid transparent; border-radius: 13px; outline: none;
          transition: .15s; font-family: inherit; }
  input::placeholder { color: #5C616B; }
  input:focus { border-color: var(--accent); }
  .primary { width: 100%; padding: 15px; font-size: 15px; font-weight: 700; color: #fff; background: var(--accent);
             border: 0; border-radius: 13px; cursor: pointer; transition: .15s; font-family: inherit; }
  .primary:hover { background: var(--accent-press); }
  .primary:active { transform: scale(.99); }
  .msg { font-size: 13px; margin: 13px 2px 0; min-height: 18px; text-align: center; }
  .ok { color: var(--ok); }
  .err { color: var(--err); }
  #key_box { margin-top: 18px; padding: 16px; background: var(--input); border-radius: 16px; }
  #key_box .lbl { font-size: 13px; color: var(--sub); margin-bottom: 9px; }
  textarea { width: 100%; font-family: Consolas, 'SFMono-Regular', monospace; font-size: 13px; color: var(--text);
             background: var(--bg); padding: 11px; border: 1px solid var(--line); border-radius: 11px; resize: none; outline: none; }
  .ghost { width: 100%; margin-top: 10px; padding: 12px; font-size: 14px; font-weight: 600; color: var(--accent);
           background: transparent; border: 1px solid var(--accent); border-radius: 12px; cursor: pointer; font-family: inherit; }
  .ghost:active { background: rgba(49,130,246,.12); }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">🙂</div>
    <h1>얼굴인식</h1>
    <p class="desc">로그인하면 실행 키를 받을 수 있어요</p>

    <div class="tabs">
      <div class="tab active" id="tab_login" onclick="switchTab('login')">로그인</div>
      <div class="tab" id="tab_register" onclick="switchTab('register')">회원가입</div>
    </div>

    <form id="form_login" class="active">
      <label>이메일</label>
      <input id="l_email" placeholder="you@example.com" autocomplete="off">
      <label>비밀번호</label>
      <input id="l_pw" type="password" placeholder="비밀번호">
      <button type="button" class="primary" onclick="doLogin()">로그인</button>
      <p id="l_msg" class="msg"></p>
      <div id="key_box" style="display:none">
        <div class="lbl">🔑 내 키 — 복사해서 프로그램에 붙여넣으세요</div>
        <textarea id="key_out" rows="2" readonly></textarea>
        <button type="button" class="ghost" onclick="copyKey()">키 복사하기</button>
      </div>
    </form>

    <form id="form_register">
      <label>이메일</label>
      <input id="r_email" placeholder="you@example.com" autocomplete="off">
      <label>비밀번호</label>
      <input id="r_pw" type="password" placeholder="비밀번호">
      <button type="button" class="primary" onclick="doRegister()">회원가입</button>
      <p id="r_msg" class="msg"></p>
    </form>
  </div>

<script>
function switchTab(name) {
  const login = name === 'login';
  document.getElementById('tab_login').classList.toggle('active', login);
  document.getElementById('tab_register').classList.toggle('active', !login);
  document.getElementById('form_login').classList.toggle('active', login);
  document.getElementById('form_register').classList.toggle('active', !login);
}
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
