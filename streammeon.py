import os
import time
import json
import jwt
import uuid
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Body
from pydantic import BaseModel, EmailStr, constr
from passlib.hash import bcrypt
from starlette.websockets import WebSocketState

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# ----------------------------
# Config
# ----------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    # your Railway DB provided earlier
    "postgresql://postgres:hCukXsTnUaLQmoVVsICaDhRSBWyXfVIZ@postgres-glu6.railway.internal:5432/railway"
)
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TTL_MIN = int(os.getenv("ACCESS_TTL_MIN", "120"))

# CORS: allow your dev/prod frontends
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# ----------------------------
# DB
# ----------------------------
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('vendor','user')),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS live_sessions (
          id TEXT PRIMARY KEY,
          vendor_id INTEGER NOT NULL REFERENCES users(id),
          title TEXT NOT NULL,
          is_live BOOLEAN NOT NULL DEFAULT TRUE,
          started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          ended_at TIMESTAMPTZ
        );
        """))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS comments (
          id SERIAL PRIMARY KEY,
          session_id TEXT NOT NULL REFERENCES live_sessions(id),
          user_id INTEGER NOT NULL REFERENCES users(id),
          user_name TEXT NOT NULL,
          message TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """))

# ----------------------------
# Auth helpers
# ----------------------------
def make_token(sub: int, role: str, name: str) -> str:
    now = int(time.time())
    payload = {
        "sub": str(sub),
        "role": role,
        "name": name,
        "iat": now,
        "exp": now + (ACCESS_TTL_MIN * 60),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def parse_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def bearer_to_token(header_val: Optional[str]) -> Optional[str]:
    if not header_val:
        return None
    parts = header_val.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None

# ----------------------------
# Schemas
# ----------------------------
class RegisterIn(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: str  # "vendor" or "user"

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class LiveCreateIn(BaseModel):
    title: constr(min_length=1, max_length=200)

class CommentIn(BaseModel):
    message: constr(min_length=1, max_length=1000)

# ----------------------------
# FastAPI
# ----------------------------
app = FastAPI(title="KMK Live Streaming APIs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in CORS_ORIGINS] if CORS_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup():
    init_db()

# ----------------------------
# REST: Health
# ----------------------------
@app.get("/health")
def health():
    return {"ok": True, "time": int(time.time())}

# ----------------------------
# REST: Auth
# ----------------------------
@app.post("/auth/register")
def register(body: RegisterIn):
    if body.role not in ("vendor", "user"):
        raise HTTPException(422, "role must be 'vendor' or 'user'")
    pw_hash = bcrypt.hash(body.password)
    with engine.begin() as conn:
        try:
            row = conn.execute(
                text("INSERT INTO users (email, name, password_hash, role) VALUES (:e,:n,:p,:r) RETURNING id"),
                {"e": body.email, "n": body.name, "p": pw_hash, "r": body.role}
            ).first()
        except Exception as e:
            # likely duplicate email
            raise HTTPException(400, "Email already registered")
    token = make_token(row[0], body.role, body.name)
    return {"access_token": token, "token_type": "Bearer", "user": {"id": row[0], "email": body.email, "name": body.name, "role": body.role}}

@app.post("/auth/login")
def login(body: LoginIn):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, name, password_hash, role FROM users WHERE email = :e"),
            {"e": body.email}
        ).first()
        if not row:
            raise HTTPException(401, "Invalid credentials")
        if not bcrypt.verify(body.password, row.password_hash):
            raise HTTPException(401, "Invalid credentials")
    token = make_token(row.id, row.role, row.name)
    return {"access_token": token, "token_type": "Bearer", "user": {"id": row.id, "email": body.email, "name": row.name, "role": row.role}}

@app.get("/me")
def me(
    authorization: Optional[str] = Header(None),
    authorization_query: Optional[str] = Query(None, alias="authorization"),
):
    token = bearer_to_token(authorization or authorization_query)
    if not token:
        raise HTTPException(401, "Missing token")
    claims = parse_token(token)
    uid = int(claims["sub"])
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, email, name, role FROM users WHERE id=:i"), {"i": uid}).first()
        if not row:
            raise HTTPException(401, "User not found")
    return {"id": row.id, "email": row.email, "name": row.name, "role": row.role}

# ----------------------------
# REST: Live sessions
# ----------------------------
def new_session_id() -> str:
    return "sess_" + str(uuid.uuid4())

@app.post("/live/sessions")
def create_live(
    body: LiveCreateIn,
    authorization: Optional[str] = Header(None),
    authorization_query: Optional[str] = Query(None, alias="authorization"),
):
    token = bearer_to_token(authorization or authorization_query)
    if not token:
        raise HTTPException(401, "Missing token")
    claims = parse_token(token)
    if claims.get("role") != "vendor":
        raise HTTPException(403, "Only vendor can create live session")
    sid = new_session_id()
    with engine.begin() as conn:
        created = conn.execute(
            text(
                """
                INSERT INTO live_sessions (id, vendor_id, title, is_live)
                VALUES (:id,:vendor,:title, TRUE)
                RETURNING started_at
                """
            ),
            {"id": sid, "vendor": int(claims["sub"]), "title": body.title}
        ).first()
        vend = conn.execute(text("SELECT id, name FROM users WHERE id=:i"), {"i": int(claims["sub"])}).first()
    return {
        "session_id": sid,
        "title": body.title,
        "vendor": {"id": vend.id, "name": vend.name},
        "is_live": True,
        "started_at": created.started_at.isoformat() if created and created.started_at else None,
        "viewer_count": viewer_count(sid)
    }

@app.get("/live/sessions/{session_id}")
def get_live(session_id: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, vendor_id, title, is_live, started_at, ended_at FROM live_sessions WHERE id=:i"), {"i": session_id}).first()
        if not row:
            raise HTTPException(404, "Session not found")
        vend = conn.execute(text("SELECT id, name FROM users WHERE id=:i"), {"i": row.vendor_id}).first()
    return {
        "session_id": row.id,
        "title": row.title,
        "vendor": {"id": vend.id, "name": vend.name} if vend else None,
        "is_live": row.is_live,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "ended_at": row.ended_at.isoformat() if row.ended_at else None,
        "viewer_count": viewer_count(session_id)
    }

@app.get("/live/sessions/active")
def list_active():
    with engine.begin() as conn:
        rows = conn.execute(text(
            """
            SELECT ls.id, ls.title, ls.is_live, ls.started_at,
                   u.id AS vendor_id, u.name AS vendor_name
            FROM live_sessions ls
            JOIN users u ON u.id = ls.vendor_id
            WHERE ls.is_live = TRUE
            ORDER BY ls.started_at DESC
            """
        )).all()
        out = []
        for r in rows:
            out.append({
                "session_id": r.id,
                "title": r.title,
                "vendor": {"id": r.vendor_id, "name": r.vendor_name},
                "is_live": r.is_live,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "viewer_count": viewer_count(r.id)
            })
    return {"items": out}

@app.post("/live/sessions/{session_id}/end")
def end_live(
    session_id: str,
    authorization: Optional[str] = Header(None),
    authorization_query: Optional[str] = Query(None, alias="authorization"),
):
    token = bearer_to_token(authorization or authorization_query)
    if not token:
        raise HTTPException(401, "Missing token")
    claims = parse_token(token)
    uid = int(claims["sub"])
    with engine.begin() as conn:
        row = conn.execute(text("SELECT vendor_id, is_live FROM live_sessions WHERE id=:i"), {"i": session_id}).first()
        if not row:
            raise HTTPException(404, "Session not found")
        if row.vendor_id != uid or claims.get("role") != "vendor":
            raise HTTPException(403, "Only session vendor can end")
        conn.execute(text("UPDATE live_sessions SET is_live=FALSE, ended_at=NOW() WHERE id=:i"), {"i": session_id})
    # notify all connections
    asyncio.create_task(broadcast_event(session_id, {"type":"session_ended"}))
    # close signaling peers gracefully
    asyncio.create_task(close_all_ws_for_session(session_id))
    # cleanup room state shortly after
    asyncio.create_task(cleanup_room_after(session_id))
    return {"ok": True}

# ----------------------------
# REST: Comments
# ----------------------------
@app.get("/live/sessions/{session_id}/comments")
def list_comments(session_id: str, limit: int = 50):
    # clamp limit for safety
    try:
        limit = max(1, min(int(limit), 200))
    except Exception:
        limit = 50
    with engine.begin() as conn:
        rows = conn.execute(
            text("""SELECT id, user_id, user_name, message, created_at
                    FROM comments WHERE session_id=:s
                    ORDER BY id DESC LIMIT :lim"""),
            {"s": session_id, "lim": limit}
        ).all()
    items = []
    for r in rows[::-1]:
        items.append({
            "id": r.id,
            "user_id": r.user_id,
            "user_name": r.user_name,
            "message": r.message,
            "created_at": r.created_at.isoformat() if r.created_at else None
        })
    return {"items": items}

@app.post("/live/sessions/{session_id}/comments")
def post_comment(
    session_id: str,
    body: CommentIn,
    authorization: Optional[str] = Header(None),
    authorization_query: Optional[str] = Query(None, alias="authorization"),
):
    token = bearer_to_token(authorization or authorization_query)
    if not token:
        raise HTTPException(401, "Missing token")
    claims = parse_token(token)
    uid = int(claims["sub"])
    uname = claims.get("name", "Unknown")
    # ensure session
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM live_sessions WHERE id=:s AND is_live=TRUE"), {"s": session_id}).first()
        if not exists:
            raise HTTPException(404, "Live not found or ended")
        conn.execute(
            text("""INSERT INTO comments (session_id, user_id, user_name, message)
                    VALUES (:sid, :uid, :uname, :msg)"""),
            {"sid": session_id, "uid": uid, "uname": uname, "msg": body.message}
        )
    payload = {"type":"comment", "user_id": uid, "user_name": uname, "message": body.message, "ts": int(time.time()*1000)}
    asyncio.create_task(broadcast_event(session_id, payload))
    return {"ok": True}

# ----------------------------
# In-memory live state for WS
# ----------------------------
class LiveRoom:
    def __init__(self):
        self.chat_peers: set[WebSocket] = set()
        self.signal_vendor: Optional[WebSocket] = None
        self.signal_viewers: set[WebSocket] = set()
        self.viewer_count: int = 0

rooms: Dict[str, LiveRoom] = {}

def get_room(sid: str) -> LiveRoom:
    room = rooms.get(sid)
    if not room:
        room = LiveRoom()
        rooms[sid] = room
    return room

def viewer_count(sid: str) -> int:
    return get_room(sid).viewer_count

async def broadcast_event(sid: str, data: dict):
    room = get_room(sid)
    dead = []
    msg = json.dumps(data)
    for ws in list(room.chat_peers):
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        room.chat_peers.discard(ws)

async def cleanup_room_after(sid: str, delay: float = 1.0):
    try:
        await asyncio.sleep(delay)
    except Exception:
        pass
    rooms.pop(sid, None)

async def close_all_ws_for_session(sid: str):
    room = get_room(sid)
    # copy sets to avoid mutation during iteration
    for ws in list(room.chat_peers):
        try:
            await ws.close(code=1000)
        except Exception:
            pass
    if room.signal_vendor:
        try:
            await room.signal_vendor.close(code=1000)
        except Exception:
            pass
    for ws in list(room.signal_viewers):
        try:
            await ws.close(code=1000)
        except Exception:
            pass

# ----------------------------
# WS: Chat + presence (real-time comments & viewer count)
# ----------------------------
@app.websocket("/ws/live/{session_id}")
async def ws_live(websocket: WebSocket, session_id: str, token: str = Query(None)):
    # Auth via ?token= or Authorization header
    token_val = token or bearer_to_token(websocket.headers.get("authorization"))
    if not token_val:
        await websocket.close(code=4401, reason="Missing token")
        return
    try:
        claims = parse_token(token_val)
    except HTTPException:
        await websocket.close(code=4401, reason="Invalid token")
        return

    # Make sure session exists and is live
    with engine.begin() as conn:
        found = conn.execute(text("SELECT is_live FROM live_sessions WHERE id=:s"), {"s": session_id}).first()
        if not found or not found.is_live:
            await websocket.close(code=4404, reason="Session not found or not live")
            return

    await websocket.accept()
    room = get_room(session_id)
    room.chat_peers.add(websocket)

    # Increase viewer count for non-vendor (vendors also connect to see chat, but shouldn’t count as viewer)
    is_vendor = (claims.get("role") == "vendor")
    if not is_vendor:
        room.viewer_count += 1
        # announce
        try:
            await broadcast_event(session_id, {"type":"viewer_count", "count": room.viewer_count})
        except Exception:
            pass

    # On connect: optionally send recent comments
    try:
        with engine.begin() as conn:
            rows = conn.execute(
                text("""SELECT user_name, message, created_at
                        FROM comments WHERE session_id=:s
                        ORDER BY id DESC LIMIT 30"""),
                {"s": session_id}
            ).all()
        for r in rows[::-1]:
            await websocket.send_text(json.dumps({
                "type": "comment",
                "user_name": r.user_name,
                "message": r.message,
                "ts": int(r.created_at.timestamp()*1000) if r.created_at else None
            }))
        # also send current viewer count snapshot
        await websocket.send_text(json.dumps({"type":"viewer_count", "count": room.viewer_count}))
    except Exception:
        # don't kill the socket if snapshot fails
        pass

    try:
        while True:
            msg = await websocket.receive_text()
            # Optional: allow client to send chat over WS as well
            # Expected payload: {"type":"comment","message":"hi"}
            try:
                data = json.loads(msg)
            except Exception:
                continue
            if data.get("type") == "ping":
                await websocket.send_text(json.dumps({"type":"pong"}))
                continue
            if data.get("type") == "comment":
                uname = claims.get("name", "Unknown")
                uid = int(claims["sub"])
                text_msg = (data.get("message") or "").strip()
                if len(text_msg) > 1000:
                    text_msg = text_msg[:1000]
                if not text_msg:
                    continue
                with engine.begin() as conn:
                    conn.execute(
                        text("""INSERT INTO comments (session_id, user_id, user_name, message)
                                VALUES (:sid,:uid,:uname,:msg)"""),
                        {"sid": session_id, "uid": uid, "uname": uname, "msg": text_msg}
                    )
                await broadcast_event(session_id, {
                    "type":"comment", "user_id": uid, "user_name": uname, "message": text_msg, "ts": int(time.time()*1000)
                })
    except WebSocketDisconnect:
        pass
    except Exception:
        # swallow to avoid crashing app; client saw close already by then
        pass
    finally:
        # cleanup
        room.chat_peers.discard(websocket)
        if not is_vendor:
            room.viewer_count = max(0, room.viewer_count - 1)
            try:
                await broadcast_event(session_id, {"type":"viewer_count", "count": room.viewer_count})
            except Exception:
                pass
        # ensure socket closed
        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1000)
            except Exception:
                pass

# ----------------------------
# WS: WebRTC signaling (vendor ↔ viewers)
#   protocol (no hello required):
#   - client → server: {"type":"role","value":"vendor"|"viewer"}  (recommended first)
#   - offer/answer/candidate relayed between vendor and viewers
#   - server does not inspect SDP, only relays
# ----------------------------
@app.websocket("/ws/signal/{session_id}")
async def ws_signal(websocket: WebSocket, session_id: str, token: str = Query(None)):
    # Auth via ?token= or Authorization header
    token_val = token or bearer_to_token(websocket.headers.get("authorization"))
    if not token_val:
        await websocket.close(code=4401, reason="Missing token")
        return
    try:
        claims = parse_token(token_val)
    except HTTPException:
        await websocket.close(code=4401, reason="Invalid token")
        return

    # Must belong to an existing session
    with engine.begin() as conn:
        row = conn.execute(text("SELECT vendor_id, is_live FROM live_sessions WHERE id=:s"), {"s": session_id}).first()
        if not row or not row.is_live:
            await websocket.close(code=4404, reason="Session not found or not live")
            return
    await websocket.accept()

    room = get_room(session_id)

    # default role inference from JWT, but allow client to send {"type":"role","value":...}
    role = "vendor" if claims.get("role") == "vendor" and int(claims["sub"]) == row.vendor_id else "viewer"

    # Place into room based on role
    if role == "vendor":
        # only single vendor signaling socket
        if room.signal_vendor and room.signal_vendor.client_state == WebSocketState.CONNECTED:
            # a vendor is already connected → replace old one
            try:
                await room.signal_vendor.close(code=1000)
            except Exception:
                pass
        room.signal_vendor = websocket
    else:
        room.signal_viewers.add(websocket)

    async def send(ws: Optional[WebSocket], payload: dict):
        if not ws: return
        if ws.client_state != WebSocketState.CONNECTED: return
        try:
            await ws.send_text(json.dumps(payload))
        except Exception:
            pass

    try:
        while True:
            # accept either text/json; ignore pings
            message = await websocket.receive_text()
            try:
                data = json.loads(message)
            except Exception:
                continue

            if data.get("type") == "role" and data.get("value") in ("vendor", "viewer"):
                # allow client to explicitly set role
                requested = data["value"]
                if requested == "vendor":
                    # Only allow if JWT claims match session vendor
                    if not (claims.get("role") == "vendor" and int(claims["sub"]) == row.vendor_id):
                        await send(websocket, {"type": "role_ack", "role": role, "error": "forbidden"})
                        continue
                role = requested
                if role == "vendor":
                    if room.signal_vendor and room.signal_vendor is not websocket:
                        try:
                            await room.signal_vendor.close(code=1000)
                        except Exception:
                            pass
                    room.signal_vendor = websocket
                    room.signal_viewers.discard(websocket)
                else:
                    if websocket is room.signal_vendor:
                        room.signal_vendor = None
                    room.signal_viewers.add(websocket)
                await send(websocket, {"type":"role_ack","role":role})
                continue

            # Relay offers/answers/candidates
            if data.get("type") in ("offer","answer","candidate","bye"):
                if role == "vendor":
                    # send to all viewers (you can add target viewerId if needed)
                    dead = []
                    for v in list(room.signal_viewers):
                        try:
                            if v.client_state == WebSocketState.CONNECTED:
                                await v.send_text(json.dumps(data))
                            else:
                                dead.append(v)
                        except Exception:
                            dead.append(v)
                    for d in dead:
                        room.signal_viewers.discard(d)
                else:
                    # send to vendor
                    await send(room.signal_vendor, data)
                continue

            if data.get("type") == "ping":
                await send(websocket, {"type":"pong"})
                continue

    except WebSocketDisconnect:
        pass
    except Exception:
        # keep server alive
        pass
    finally:
        # cleanup allocation
        if websocket is room.signal_vendor:
            room.signal_vendor = None
        room.signal_viewers.discard(websocket)
        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await websocket.close(code=1000)
            except Exception:
                pass

# ----------------------------
# Local dev entrypoint (Railway uses PORT)
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("streammeon:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
