# streammeon

Live streaming backend (FastAPI) with:
- Auth (register/login)
- Live session lifecycle (create, end, list active)
- Real‑time comments and presence via WebSocket
- Viewer count tracking and session duration info

Key APIs
- POST `/live/sessions` (vendor): creates a session
  - Response includes: `session_id`, `started_at`, `viewer_count`, `live_duration_seconds`
- GET `/live/sessions/{session_id}`: fetch session info
  - Response includes: `viewer_count`, `started_at`, `ended_at`, `live_duration_seconds`
- GET `/live/sessions/active`: list active sessions
  - Each item includes: `viewer_count`, `started_at`, `live_duration_seconds`
- POST `/live/sessions/{session_id}/end` (vendor): end session

WebSocket
- WS `/ws/live/{session_id}` with `?token=...` or `Authorization: Bearer ...`
  - Emits on connect:
    - `{ type: "viewer_count", count }`
    - `{ type: "session_info", is_live, started_at, ended_at, live_duration_seconds }`
  - Broadcasts when viewers join/leave:
    - `{ type: "viewer_count", count }`
  - Broadcasts when session ends:
    - `{ type: "session_ended", ended_at, live_duration_seconds }`

Note: Viewer count is presence-based (non‑vendor WS peers). Clients can derive a live timer from `started_at` or use `live_duration_seconds` directly.
