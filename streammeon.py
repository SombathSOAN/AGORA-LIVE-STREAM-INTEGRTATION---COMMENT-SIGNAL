# streamneon.py
import os, time, uuid, asyncio
from datetime import datetime, timedelta
from typing import Dict

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field as PydField, EmailStr
from sqlmodel import SQLModel, Field, create_engine, Session, select
from passlib.context import CryptContext
import jwt

# ------------------ Config ------------------
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_SUPER_SECRET")
JWT_ALG = "HS256"
ACCESS_TTL_MIN = int(os.getenv("JWT_TTL_MIN", "120"))

# IMPORTANT:
# - For local dev against Railway, use EXTERNAL DB URL with sslmode=require
# - For production inside Railway, use the INTERNAL URL

DB_URL = os.getenv("DATABASE_URL") or os.getenv("DATABASE_PUBLIC_URL")
engine = create_engine(DB_URL, echo=False, pool_pre_ping=True)

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="KMK Live (Python)")

# tighten allow_origins in prod (e.g., ["https://stream.kmk.railway.app"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# ------------------ DB Models ------------------
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(index=True, unique=True)
    name: str
    password_hash: str
    role: str = Field(default="user")  # "vendor" or "user"

class LiveSession(SQLModel, table=True):
    id: str = Field(default_factory=lambda: f"sess_{uuid.uuid4()}", primary_key=True)
    title: str
    vendor_id: int
    is_live: bool = Field(default=True)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: datetime | None = None

def init_db():
    SQLModel.metadata.create_all(engine)

# ------------------ Schemas ------------------
class RegisterIn(BaseModel):
    email: EmailStr
    name: str = PydField(min_length=1, max_length=80)
    password: str = PydField(min_length=6, max_length=72)
    role: str = PydField(pattern="^(vendor|user)$")

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "Bearer"

class LiveCreateIn(BaseModel):
    title: str = PydField(min_length=1, max_length=120)

class LiveSummary(BaseModel):
    session_id: str
    title: str
    vendor: dict
    viewer_count: int

class LiveDetail(BaseModel):
    session_id: str
    title: str
    vendor: dict
    is_live: bool
    started_at: float
    viewer_count: int

# ------------------ Auth helpers ------------------
def make_token(u: User) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": str(u.id),
        "role": u.role,
        "name": u.name,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TTL_MIN)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def _parse_bearer(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return parts[1]

async def get_current_user(Authorization: str | None = Header(default=None)):
    token = _parse_bearer(Authorization)
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid/expired token")
    with Session(engine) as s:
        u = s.get(User, int(payload["sub"]))
        if not u:
            raise HTTPException(status_code=401, detail="User not found")
        return u

def require_role(role: str):
    async def _checker(u: User = Depends(get_current_user)):
        if u.role != role:
            raise HTTPException(status_code=403, detail=f"{role} role required")
        return u
    return _checker

# ------------------ REST: User/Auth ------------------
@app.post("/auth/register", response_model=TokenOut, tags=["auth"])
def register(data: RegisterIn):
    with Session(engine) as s:
        if s.exec(select(User).where(User.email == data.email)).first():
            raise HTTPException(400, "Email already registered")
        u = User(email=data.email, name=data.name, role=data.role, password_hash=pwd.hash(data.password))
        s.add(u); s.commit(); s.refresh(u)
        return TokenOut(access_token=make_token(u))

@app.post("/auth/login", response_model=TokenOut, tags=["auth"])
def login(data: LoginIn):
    with Session(engine) as s:
        u = s.exec(select(User).where(User.email == data.email)).first()
        if not u or not pwd.verify(data.password, u.password_hash):
            raise HTTPException(400, "Incorrect email/password")
        return TokenOut(access_token=make_token(u))

@app.get("/me", tags=["auth"])
def me(u: User = Depends(get_current_user)):
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role}

# ------------------ REST: Live sessions ------------------
@app.post("/live/sessions", response_model=LiveDetail, tags=["live"])
async def create_live(body: LiveCreateIn, vendor: User = Depends(require_role("vendor"))):
    sess = LiveSession(title=body.title, vendor_id=vendor.id, is_live=True)
    with Session(engine) as s:
        s.add(sess); s.commit(); s.refresh(sess)
    return LiveDetail(
        session_id=sess.id, title=sess.title,
        vendor={"id": vendor.id, "name": vendor.name},
        is_live=True, started_at=sess.started_at.timestamp(),
        viewer_count=get_viewer_count(sess.id),
    )

@app.post("/live/sessions/{session_id}/end", status_code=204, tags=["live"])
async def end_live(session_id: str, vendor: User = Depends(require_role("vendor"))):
    with Session(engine) as s:
        sess = s.get(LiveSession, session_id)
        if not sess or sess.vendor_id != vendor.id:
            raise HTTPException(404, "Session not found")
        if not sess.is_live:
            return
        sess.is_live = False
        sess.ended_at = datetime.utcnow()
        s.add(sess); s.commit()
    # Broadcast terminate and close connections
    await broadcast(session_id, {"type": "terminate", "reason": "ended_by_vendor"})
    await close_room(session_id)

@app.get("/live/sessions/active", response_model=list[LiveSummary], tags=["live"])
def list_active():
    with Session(engine) as s:
        rows = s.exec(select(LiveSession).where(LiveSession.is_live == True).order_by(LiveSession.started_at.desc())).all()
    return [
        LiveSummary(
            session_id=r.id, title=r.title,
            vendor={"id": r.vendor_id},
            viewer_count=get_viewer_count(r.id),
        ) for r in rows
    ]

@app.get("/live/sessions/{session_id}", response_model=LiveDetail, tags=["live"])
def get_session(session_id: str):
    with Session(engine) as s:
        sess = s.get(LiveSession, session_id)
        if not sess:
            raise HTTPException(404, "Session not found")
        vendor = s.get(User, sess.vendor_id)
    return LiveDetail(
        session_id=sess.id, title=sess.title,
        vendor={"id": vendor.id, "name": vendor.name if vendor else "Unknown"},
        is_live=sess.is_live, started_at=sess.started_at.timestamp(),
        viewer_count=get_viewer_count(sess.id),
    )

# ------------------ WebSocket hub (text-only chat, ephemeral) ------------------
class Conn:
    def __init__(self, ws: WebSocket, user_id: int, name: str, role: str):
        self.ws = ws
        self.user_id = user_id
        self.name = name
        self.role = role
        self.last_msg = 0.0  # rate limit: 1 msg / 2s

# rooms structure: { session_id: { websocket_obj: Conn } }
rooms: Dict[str, Dict[WebSocket, Conn]] = {}

def get_viewer_count(session_id: str) -> int:
    return len(rooms.get(session_id, {}))

async def broadcast(session_id: str, data: dict):
    room = rooms.get(session_id, {})
    dead = []
    for ws, _c in list(room.items()):
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        room.pop(ws, None)

async def close_room(session_id: str):
    room = rooms.get(session_id, {})
    for ws in list(room.keys()):
        try:
            await ws.close()
        except Exception:
            pass
    rooms.pop(session_id, None)

@app.websocket("/ws/live/{session_id}")
async def ws_live(session_id: str, websocket: WebSocket):
    # Auth: /ws/live/{id}?token=JWT
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4401); return
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        await websocket.close(code=4401); return

    user_id = int(payload.get("sub", "0"))
    name = payload.get("name", f"u{user_id}")
    role = payload.get("role", "user")

    # Check session exists & is live
    with Session(engine) as s:
        sess = s.get(LiveSession, session_id)
        if not sess or not sess.is_live:
            await websocket.close(code=4404); return

    await websocket.accept()
    rooms.setdefault(session_id, {})
    rooms[session_id][websocket] = Conn(websocket, user_id, name, role)

    # Welcome + viewer count
    await websocket.send_json({"type": "welcome", "session_id": session_id, "viewer_count": get_viewer_count(session_id)})
    await broadcast(session_id, {"type": "viewer_count", "viewer_count": get_viewer_count(session_id)})

    try:
        while True:
            msg = await websocket.receive_json()
            if msg.get("type") == "chat":
                # text-only, sanitize, rate-limit
                c = rooms[session_id][websocket]
                now = time.time()
                if now - c.last_msg < 2.0:
                    # soft drop (or send rate-limited notice)
                    continue
                c.last_msg = now

                text = (msg.get("text") or "").strip()
                if not text:
                    continue
                if len(text) > 240:
                    text = text[:240]

                safe = (text
                        .replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace('"', "&quot;")
                        .replace("'", "&#39;"))

                await broadcast(session_id, {
                    "type": "chat",
                    "id": str(uuid.uuid4()),
                    "text": safe,
                    "sender": {"id": c.user_id, "name": c.name, "role": c.role},
                    "ts": int(time.time()*1000),
                })
            else:
                # ignore other types; extend for moderation etc.
                pass

    except WebSocketDisconnect:
        pass
    finally:
        # remove conn and update viewer count
        room = rooms.get(session_id, {})
        room.pop(websocket, None)
        if not room:
            rooms.pop(session_id, None)
        await broadcast(session_id, {"type": "viewer_count", "viewer_count": get_viewer_count(session_id)})

# ------------------ Startup ------------------
@app.get("/health")
def health():
    return {"ok": True, "db": DB_URL.split("@")[-1] if "@" in DB_URL else DB_URL}

@app.on_event("startup")
def on_start():
    init_db()