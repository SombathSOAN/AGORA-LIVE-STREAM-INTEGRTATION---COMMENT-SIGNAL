# Streammeon (KMK Live) — Live Streaming APIs

FastAPI backend for a lightweight live streaming platform with:

- Auth (register/login + JWT)
- Live session lifecycle (create, list, fetch, end)
- Real‑time comments, presence viewer counts, and unique views via WebSocket
- WebRTC signaling relay WebSocket (vendor ↔ viewers)
- Example token server for Agora (Express) + sample web UIs


## Overview

This repo contains:

1) Python FastAPI service (`streammeon.py`)
   - PostgreSQL persistence for users, sessions, comments
   - REST APIs for auth and live sessions
   - WebSocket for real‑time comments/presence: `/ws/live/{session_id}`
   - WebSocket for WebRTC signaling relay: `/ws/signal/{session_id}`

2) Token server for Agora (Node/Express) under `server/`
   - Endpoints to mint RTC/RTM tokens for the web demos
   - Optional, only needed for the example frontends that use Agora

3) Frontend examples under `examples/`
   - `examples/app/*`: simple app pages (login, vendor go‑live, viewer)
   - `examples/web/*`: minimal mute/volume demo using Agora Web SDK


## Quick Start

Prerequisites
- Python 3.10+
- PostgreSQL 13+ (local or remote)
- Node 18+ (only if running the token server under `server/`)

1) Set environment

```
export DATABASE_URL="postgresql+psycopg2://admin@127.0.0.1:5432/streammeon"
export JWT_SECRET="change-me"
export ACCESS_TTL_MIN=120
export CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
```

Notes
- On first start, the app auto‑creates `users`, `live_sessions`, and `comments` tables if missing.
- If you already have a `users` table, the app detects its id type (UUID or INTEGER) and adapts.

2) Install and run the FastAPI service

```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run (dev)
uvicorn streammeon:app --host 0.0.0.0 --port 8000 --reload
# or
python streammeon.py
```

Health check
```
curl -s http://localhost:8000/health
```

3) (Optional) Run the token server (Agora) and demos

```
cd server
cp .env.example .env   # fill AGORA_APP_ID / AGORA_APP_CERTIFICATE
npm install
npm start

# Serve the example pages
cd ../examples/app
python3 -m http.server 5173
open http://localhost:5173
```

Tip: The examples expect the FastAPI API on `http://<host>:8000` and token server on the same origin as the page (configurable in UI/localStorage).


## Environment Variables

- `DATABASE_URL`: SQLAlchemy connection string, e.g. `postgresql+psycopg2://user:pass@host:5432/dbname`
- `JWT_SECRET`: HMAC secret for JWT signing
- `ACCESS_TTL_MIN`: JWT access token TTL in minutes (default 120)
- `CORS_ORIGINS`: Comma‑separated allowed origins, or `*`


## REST API

Auth
- `POST /auth/register`
  - Body: `{ email, name, password, role }` where `role` ∈ {`vendor`,`user`} (defaults to `user`)
  - Returns: `{ access_token, token_type, user }`
- `POST /auth/login`
  - Body: `{ email, password }`
  - Returns: `{ access_token, token_type, user }`
- `GET /me`
  - Header: `Authorization: Bearer <JWT>` or query `?authorization=Bearer%20<JWT>`
  - Returns current user

Live sessions
- `POST /live/sessions` (vendor)
  - Body: `{ title }`
  - Returns: `{ session_id, title, vendor, is_live, started_at, viewer_count, views_total, live_duration_seconds }`
- `GET /live/sessions/active`
  - Returns: `{ items: [{ session_id, title, vendor, is_live, started_at, viewer_count, views_total, live_duration_seconds }] }`
- `GET /live/sessions/{session_id}`
  - Returns: `{ session_id, title, vendor, is_live, started_at, ended_at, viewer_count, views_total, live_duration_seconds }`
- `POST /live/sessions/{session_id}/end` (vendor)
  - Ends the session; notifies WS peers with `session_ended`

Comments
- `GET /live/sessions/{session_id}/comments?limit=50`
  - Returns recent comments for a session
- `POST /live/sessions/{session_id}/comments` (auth required)
  - Body: `{ message }` (max 1000 chars)
  - Broadcasts a `comment` event to WS peers


## WebSocket Protocols

Chat + Presence: `ws://<api-host>/ws/live/{session_id}`
- Auth via `?token=<JWT>` or `Authorization: Bearer <JWT>` header
- Emits on connect:
  - `{ type: "viewer_count", count }`
  - `{ type: "views_total", total }` (unique viewers by user id, vendors excluded)
  - `{ type: "session_info", is_live, started_at, ended_at, live_duration_seconds, viewer_count, views_total }`
- Broadcasts during session:
  - Viewer joins/leaves: `{ type: "viewer_count", count }`
  - Comments: `{ type: "comment", user_id, user_name, message, ts }`
  - Ping/pong: client may send `{ type: "ping" }`, server replies `{ type: "pong" }`
- On end:
  - `{ type: "session_ended", ended_at, live_duration_seconds }`

WebRTC Signaling Relay: `ws://<api-host>/ws/signal/{session_id}`
- Auth via `?token=<JWT>` or bearer header, must reference an active session
- Optional first message: `{ type: "role", value: "vendor" | "viewer" }`
  - Vendor role requires JWT role `vendor` and to be the session vendor
- Relayed messages (opaque to server): `{ type: "offer" | "answer" | "candidate" | "bye", ... }`


## cURL Smoke Test

Quick E2E flow (also see `scripts/smoke.sh`):

```
# 1) Register/login vendor
curl -s "http://localhost:8000/auth/register" -H 'Content-Type: application/json' \
  -d '{"email":"vendor1@example.com","name":"vendor1","password":"123456789","role":"vendor"}'

VJWT=$(curl -s "http://localhost:8000/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"vendor1@example.com","password":"123456789"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 2) Create session
SID=$(curl -s -X POST "http://localhost:8000/live/sessions" \
  -H "Authorization: Bearer $VJWT" -H 'Content-Type: application/json' \
  -d '{"title":"My Live"}' | python -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')

# 3) Register/login a user, post a comment
curl -s "http://localhost:8000/auth/register" -H 'Content-Type: application/json' \
  -d '{"email":"user1@example.com","name":"user1","password":"p","role":"user"}' >/dev/null
UJWT=$(curl -s "http://localhost:8000/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"user1@example.com","password":"p"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST "http://localhost:8000/live/sessions/$SID/comments" \
  -H "Authorization: Bearer $UJWT" -H 'Content-Type: application/json' \
  -d '{"message":"hello"}'

# 4) List active and end
curl -s "http://localhost:8000/live/sessions/active"
curl -s -X POST "http://localhost:8000/live/sessions/$SID/end" -H "Authorization: Bearer $VJWT"
```


## Database Notes

- `users` table: created if missing with UUID `id`; if present, the service adapts to `id` type (UUID or INTEGER) and adds missing columns when possible.
- `live_sessions` and `comments` tables are created if missing.
- Session duration is computed server‑side (`live_duration_seconds`) from `started_at`/`ended_at`.


## Deployment

- Procfile included: `web: uvicorn streammeon:app --host 0.0.0.0 --port $PORT`
- Set `DATABASE_URL`, `JWT_SECRET`, `CORS_ORIGINS` in your platform (e.g., Railway/Heroku).
- Use HTTPS in production. For local HTTPS, see `server/README.md` (mkcert instructions).


## Limitations & Notes

- Viewer count is presence‑based (non‑vendor WS peers connected to `/ws/live/{session_id}`) and resets if the process restarts.
- `views_total` counts unique users (by user id) per session; vendors are excluded.
- WebRTC signaling is a simple relay — no TURN/STUN or media servers included.
- This is a demo‑oriented backend; harden auth, rate limiting, and persistence for production.
