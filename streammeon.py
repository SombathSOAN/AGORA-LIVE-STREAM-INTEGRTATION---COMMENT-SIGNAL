import os
import time
import json
import jwt
import uuid
import asyncio
import re
import secrets
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Body
from pydantic import BaseModel, EmailStr, constr
from passlib.hash import bcrypt
from starlette.websockets import WebSocketState

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

# ----------------------------
# Config
# ----------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    # Local default for development (TablePlus URL provided)
    "postgresql+psycopg2://admin@127.0.0.1:5432/streammeon"
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

# Track user id type used by DB ('UUID' or 'INTEGER')
USER_ID_TYPE: str = "UUID"
USERS_COLS: set[str] = set()

def to_user_id(val: Any):
    """Coerce claim/user id into correct DB type for queries.
    Returns None if coercion fails.
    """
    global USER_ID_TYPE
    try:
        if USER_ID_TYPE == "UUID":
            return str(val) if val is not None else None
        # INTEGER path
        return int(val) if val is not None else None
    except Exception:
        return None

def init_db():
    with engine.begin() as conn:
        # Ensure UUID generation function exists (safe no-op if already installed)
        try:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        except Exception:
            pass
        # Detect if users table exists
        exists = conn.execute(text(
            "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='users'"
        )).first()
        user_id_type = "UUID"
        if not exists:
            # Create fresh users table with UUID id
            conn.execute(text("""
            CREATE TABLE users (
              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              email TEXT UNIQUE NOT NULL,
              name TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL CHECK (role IN ('vendor','user')),
              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """))
        else:
            # Determine current id column type
            trow = conn.execute(text(
                "SELECT data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='id'"
            )).first()
            if trow and str(trow.data_type).lower().strip() == "integer":
                user_id_type = "INTEGER"
            else:
                user_id_type = "UUID"
            # Ensure default for UUID id if applicable
            if user_id_type == "UUID":
                try:
                    conn.execute(text("ALTER TABLE users ALTER COLUMN id SET DEFAULT gen_random_uuid()"))
                except Exception:
                    pass
            # Ensure required columns exist
            for ddl in (
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
            ):
                try:
                    conn.execute(text(ddl))
                except Exception:
                    pass
            # Defaults for existing rows
            try:
                conn.execute(text("UPDATE users SET name = COALESCE(NULLIF(name, ''), split_part(COALESCE(email,''), '@', 1)) WHERE name IS NULL OR name = ''"))
            except Exception:
                pass
            try:
                conn.execute(text("UPDATE users SET role = 'user' WHERE role IS NULL OR role NOT IN ('vendor','user')"))
            except Exception:
                pass
        # If an older users table exists without expected columns, add them
        for ddl in (
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()",
        ):
            try:
                conn.execute(text(ddl))
            except Exception:
                pass
        # Fill sane defaults for rows missing values
        try:
            conn.execute(text("UPDATE users SET name = COALESCE(NULLIF(name, ''), split_part(COALESCE(email,''), '@', 1)) WHERE name IS NULL OR name = ''"))
        except Exception:
            pass
        try:
            conn.execute(text("UPDATE users SET role = 'user' WHERE role IS NULL OR role NOT IN ('vendor','user')"))
        except Exception:
            pass
        # Create dependent tables using the detected user id type
        vendor_col_type = user_id_type
        user_fk_type = user_id_type
        conn.execute(text(f"""
        CREATE TABLE IF NOT EXISTS live_sessions (
          id TEXT PRIMARY KEY,
          vendor_id {vendor_col_type} NOT NULL REFERENCES users(id),
          title TEXT NOT NULL,
          is_live BOOLEAN NOT NULL DEFAULT TRUE,
          started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          ended_at TIMESTAMPTZ
        );
        """))
        conn.execute(text(f"""
        CREATE TABLE IF NOT EXISTS comments (
          id SERIAL PRIMARY KEY,
          session_id TEXT NOT NULL REFERENCES live_sessions(id),
          user_id {user_fk_type} NOT NULL REFERENCES users(id),
          user_name TEXT NOT NULL,
          message TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """))

        # Expose the detected type globally
        global USER_ID_TYPE
        USER_ID_TYPE = user_id_type
        # Cache users table columns for conditional inserts
        try:
            cols = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='users'"))
            names = [r.column_name for r in cols]
            global USERS_COLS
            USERS_COLS = set(names)
        except Exception:
            USERS_COLS = set()

# ----------------------------
# Auth helpers
# ----------------------------
def make_token(sub: Any, role: str, name: str) -> str:
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
    # Optional in request; defaults to 'user' when omitted
    role: str = "user"  # "vendor" or "user"

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
    # Accept missing/blank role by defaulting to 'user'; validate strictly otherwise
    role_val = (body.role or "user").strip().lower()
    if role_val not in ("vendor", "user"):
        raise HTTPException(422, "role must be 'vendor' or 'user'")
    pw_hash = bcrypt.hash(body.password)
    # Prepare optional username/display_name depending on existing schema
    need_username = 'username' in USERS_COLS
    need_display = 'display_name' in USERS_COLS

    # Generate a base username from name or email (lowercase, alnum + underscore)
    def sanitize_username(s: str) -> str:
        s = (s or '').strip().lower()
        s = re.sub(r'\s+', '_', s)
        s = re.sub(r'[^a-z0-9_]+', '', s)
        return s

    base_user = sanitize_username(body.name) or sanitize_username(body.email.split('@')[0]) or 'user'
    # Ensure not blank due to table CHECK
    if not base_user:
        base_user = 'user'

    with engine.begin() as conn:
        # Enforce unique email at app level if column exists
        if 'email' in USERS_COLS:
            exists = conn.execute(text("SELECT 1 FROM users WHERE email=:e"), {"e": body.email}).first()
            if exists:
                raise HTTPException(400, "Email already registered")
        try:
            # Build dynamic insert
            columns = []
            params = {}
            if USER_ID_TYPE == "UUID":
                columns.append('id')
                params['id'] = str(uuid.uuid4())
            # Always include email/name/password_hash/role when present
            if 'email' in USERS_COLS:
                columns.append('email')
                params['email'] = body.email
            if 'name' in USERS_COLS:
                columns.append('name')
                params['name'] = body.name
            if 'password_hash' in USERS_COLS:
                columns.append('password_hash')
                params['password_hash'] = pw_hash
            if 'role' in USERS_COLS:
                columns.append('role')
                params['role'] = role_val
            # Optional display_name
            if need_display:
                columns.append('display_name')
                params['display_name'] = body.name
            # Optional username: ensure uniqueness
            if need_username:
                # Attempt up to 5 variants quickly
                username = base_user
                for _ in range(5):
                    taken = conn.execute(text("SELECT 1 FROM users WHERE username=:u"), {"u": username}).first()
                    if not taken:
                        break
                    username = f"{base_user}{secrets.randbelow(10000):04d}"
                columns.append('username')
                params['username'] = username

            placeholders = ','.join(':'+c for c in columns)
            cols_sql = ','.join(columns)
            sql = f"INSERT INTO users ({cols_sql}) VALUES ({placeholders}) RETURNING id"
            row = conn.execute(text(sql), params).first()
        except IntegrityError as e:
            msg = str(e.orig).lower() if getattr(e, 'orig', None) else ''
            if 'users_username_key' in msg or 'username' in msg:
                raise HTTPException(400, "Username unavailable")
            if 'users_email_key' in msg or 'email' in msg:
                raise HTTPException(400, "Email already registered")
            raise HTTPException(400, "Registration violates constraints")
        except Exception as e:
            # Surface error in dev to help diagnose
            raise HTTPException(500, f"Failed to create user: {type(e).__name__}: {e}")
    token = make_token(row[0], role_val, body.name)
    return {"access_token": token, "token_type": "Bearer", "user": {"id": str(row[0]), "email": body.email, "name": body.name, "role": role_val}}

@app.post("/auth/login")
def login(body: LoginIn):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, name, password_hash, role FROM users WHERE email = :e"),
            {"e": body.email}
        ).first()
        if not row:
            raise HTTPException(401, "Invalid credentials")
        if not getattr(row, "password_hash", None):
            raise HTTPException(401, "Invalid credentials")
        try:
            ok = bcrypt.verify(body.password, row.password_hash)
        except Exception:
            ok = False
        if not ok:
            raise HTTPException(401, "Invalid credentials")
    name = row.name if getattr(row, "name", None) else "User"
    token = make_token(row.id, row.role, name)
    return {"access_token": token, "token_type": "Bearer", "user": {"id": str(row.id), "email": body.email, "name": name, "role": row.role}}

@app.get("/me")
def me(
    authorization: Optional[str] = Header(None),
    authorization_query: Optional[str] = Query(None, alias="authorization"),
):
    token = bearer_to_token(authorization or authorization_query)
    if not token:
        raise HTTPException(401, "Missing token")
    claims = parse_token(token)
    uid = to_user_id(claims["sub"])  # coerce to DB type
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, email, name, role FROM users WHERE id=:i"), {"i": uid}).first()
        if not row:
            raise HTTPException(401, "User not found")
    return {"id": str(row.id), "email": row.email, "name": row.name, "role": row.role}

# ----------------------------
# REST: Live sessions
# ----------------------------
def new_session_id() -> str:
    return "sess_" + str(uuid.uuid4())

def _to_dt(val) -> Optional[datetime]:
    try:
        if isinstance(val, datetime):
            return val
    except Exception:
        pass
    return None

def _now() -> datetime:
    # Always use timezone-aware UTC to avoid naive comparisons
    return datetime.now(timezone.utc)

def live_duration_seconds(started_at: Optional[datetime], ended_at: Optional[datetime], is_live: Optional[bool] = None) -> int:
    """Compute elapsed seconds for a live session.

    If the session is live, measure from started_at to now; otherwise to ended_at.
    Returns 0 when started_at is missing or invalid.
    """
    s = _to_dt(started_at)
    if not s:
        return 0
    e = _to_dt(ended_at)
    if e is None and (is_live is True or (is_live is None)):
        e = _now()
    try:
        # Normalize to aware datetimes (assuming DB returns tz-aware)
        delta = (e - s) if e else timedelta(seconds=0)
        secs = int(max(0, delta.total_seconds()))
        return secs
    except Exception:
        return 0

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
            {"id": sid, "vendor": to_user_id(claims["sub"]), "title": body.title}
        ).first()
        vend = conn.execute(text("SELECT id, name FROM users WHERE id=:i"), {"i": to_user_id(claims["sub"]) }).first()
    started_iso = created.started_at.isoformat() if created and created.started_at else None
    return {
        "session_id": sid,
        "title": body.title,
        "vendor": {"id": str(vend.id), "name": vend.name},
        "is_live": True,
        "started_at": started_iso,
        "viewer_count": viewer_count(sid),
        "views_total": views_total(sid),
        "live_duration_seconds": live_duration_seconds(created.started_at if created else None, None, True),
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
                "vendor": {"id": str(r.vendor_id), "name": r.vendor_name},
                "is_live": r.is_live,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "viewer_count": viewer_count(r.id),
                "views_total": views_total(r.id),
                "live_duration_seconds": live_duration_seconds(r.started_at, None, True)
            })
    return {"items": out}

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
        "vendor": {"id": str(vend.id), "name": vend.name} if vend else None,
        "is_live": row.is_live,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "ended_at": row.ended_at.isoformat() if row.ended_at else None,
        "viewer_count": viewer_count(session_id),
        "views_total": views_total(session_id),
        "live_duration_seconds": live_duration_seconds(row.started_at, row.ended_at, row.is_live)
    }

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
    uid = to_user_id(claims["sub"])  # vendor/user id
    with engine.begin() as conn:
        row = conn.execute(text("SELECT vendor_id, is_live, started_at FROM live_sessions WHERE id=:i"), {"i": session_id}).first()
        if not row:
            raise HTTPException(404, "Session not found")
        if str(row.vendor_id) != str(uid) or claims.get("role") != "vendor":
            raise HTTPException(403, "Only session vendor can end")
        # Capture ended_at
        end_row = conn.execute(text("UPDATE live_sessions SET is_live=FALSE, ended_at=NOW() WHERE id=:i RETURNING ended_at"), {"i": session_id}).first()
        ended_at = end_row.ended_at if end_row else None
    # notify all connections
    final_dur = live_duration_seconds(row.started_at if row else None, ended_at, False)
    asyncio.create_task(broadcast_event(session_id, {"type":"session_ended", "ended_at": ended_at.isoformat() if ended_at else None, "live_duration_seconds": final_dur}))
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
            "user_id": str(r.user_id),
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
    uid = to_user_id(claims["sub"])  # commenter id (DB type)
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
    payload = {"type":"comment", "user_id": str(uid), "user_name": uname, "message": body.message, "ts": int(time.time()*1000)}
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
        # map chat websocket -> user_id (for selective broadcasts)
        self.peer_user_ids: dict[WebSocket, str] = {}
        # total unique viewers and set of seen viewer user IDs (exclude vendor)
        self.total_views: int = 0
        self.seen_viewer_ids: set[str] = set()

rooms: Dict[str, LiveRoom] = {}

def get_room(sid: str) -> LiveRoom:
    room = rooms.get(sid)
    if not room:
        room = LiveRoom()
        rooms[sid] = room
    return room

def viewer_count(sid: str) -> int:
    return get_room(sid).viewer_count

def views_total(sid: str) -> int:
    return getattr(get_room(sid), 'total_views', 0)

async def broadcast_event(sid: str, data: dict, *, skip_ws: Optional[WebSocket] = None, skip_user_id: Optional[str] = None):
    room = get_room(sid)
    dead = []
    msg = json.dumps(data)
    for ws in list(room.chat_peers):
        try:
            # skip sender when requested (by socket or by user id)
            if skip_ws is not None and ws is skip_ws:
                continue
            if skip_user_id is not None and room.peer_user_ids.get(ws) == skip_user_id:
                continue
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        room.chat_peers.discard(ws)
        try:
            room.peer_user_ids.pop(ws, None)
        except Exception:
            pass

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
        found = conn.execute(text("SELECT is_live, started_at, ended_at FROM live_sessions WHERE id=:s"), {"s": session_id}).first()
        if not found or not found.is_live:
            await websocket.close(code=4404, reason="Session not found or not live")
            return

    await websocket.accept()
    room = get_room(session_id)
    room.chat_peers.add(websocket)
    # track user id for this websocket for selective broadcasts and views
    try:
        uid_for_ws = str(to_user_id(claims["sub"]))
    except Exception:
        uid_for_ws = None
    if uid_for_ws is not None:
        room.peer_user_ids[websocket] = uid_for_ws

    # Increase viewer count for non-vendor (vendors also connect to see chat, but shouldn’t count as viewer)
    is_vendor = (claims.get("role") == "vendor")
    if not is_vendor:
        room.viewer_count += 1
        # first-time unique view per user_id
        if uid_for_ws is not None and uid_for_ws not in room.seen_viewer_ids:
            room.seen_viewer_ids.add(uid_for_ws)
            room.total_views += 1
            try:
                await broadcast_event(session_id, {"type":"views_total", "total": room.total_views})
            except Exception:
                pass
        # announce current viewer count
        try:
            await broadcast_event(session_id, {"type":"viewer_count", "count": room.viewer_count})
        except Exception:
            pass

    # On connect: optionally send recent comments and session info
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
        # also send current viewer + views snapshot
        await websocket.send_text(json.dumps({"type":"viewer_count", "count": room.viewer_count}))
        await websocket.send_text(json.dumps({"type":"views_total", "total": room.total_views}))
        # and session info (started_at, elapsed)
        started_at = found.started_at if hasattr(found, 'started_at') else None
        ended_at = found.ended_at if hasattr(found, 'ended_at') else None
        await websocket.send_text(json.dumps({
            "type": "session_info",
            "is_live": True,
            "started_at": started_at.isoformat() if started_at else None,
            "ended_at": ended_at.isoformat() if ended_at else None,
            "live_duration_seconds": live_duration_seconds(started_at, ended_at, True),
            "viewer_count": room.viewer_count,
            "views_total": room.total_views
        }))
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
                uid = to_user_id(claims["sub"])  # DB type
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
                    "type":"comment", "user_id": str(uid), "user_name": uname, "message": text_msg, "ts": int(time.time()*1000)
                })
    except WebSocketDisconnect:
        pass
    except Exception:
        # swallow to avoid crashing app; client saw close already by then
        pass
    finally:
        # cleanup
        room.chat_peers.discard(websocket)
        try:
            room.peer_user_ids.pop(websocket, None)
        except Exception:
            pass
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
    role = "vendor" if claims.get("role") == "vendor" and str(to_user_id(claims["sub"])) == str(row.vendor_id) else "viewer"

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
                    if not (claims.get("role") == "vendor" and str(to_user_id(claims["sub"])) == str(row.vendor_id)):
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
