#!/usr/bin/env bash
set -euo pipefail

# Simple end-to-end smoke test for the FastAPI backend.
#
# Usage:
#   bash scripts/smoke.sh
#   BASE=https://192.168.102.133:8000 bash scripts/smoke.sh   # if running FastAPI with TLS
#
# It will:
#   - login (or register) a vendor
#   - create a live session
#   - register + login a temp user
#   - post a comment to the session
#   - list active sessions
#   - end the live session

BASE=${BASE:-https://192.168.102.133:8000}

CURL=(curl -sS)
if [[ "$BASE" == https:* ]]; then
  # allow local self-signed during dev
  CURL+=( -k )
fi

echo "[1/8] Health check -> $BASE/health"
"${CURL[@]}" "$BASE/health" | sed -e 's/.*/  &/'

vendor_email=${V_EMAIL:-vendor1@example.com}
vendor_pass=${V_PASS:-123456789}

extract() {
  key="$1"
  python - "$key" <<'PY'
import sys, json
key = sys.argv[1]
data = json.load(sys.stdin)
val = data
for p in key.split('.'):
    val = val[p]
if isinstance(val, (dict, list)):
    print(json.dumps(val))
else:
    print(val)
PY
}

echo "[2/8] Vendor login -> $vendor_email"
v_login=$( "${CURL[@]}" -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$vendor_email\",\"password\":\"$vendor_pass\"}" )

v_jwt=$(printf '%s' "$v_login" | extract 'access_token' || true)
v_id=$(printf '%s' "$v_login" | extract 'user.id' || true)

if [[ -z "${v_jwt:-}" || -z "${v_id:-}" ]]; then
  echo "  Vendor login failed. Trying to register vendor1@…"
  v_reg=$( "${CURL[@]}" -X POST "$BASE/auth/register" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$vendor_email\",\"name\":\"vendor1\",\"password\":\"$vendor_pass\",\"role\":\"vendor\"}" || true )
  v_login=$( "${CURL[@]}" -X POST "$BASE/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"$vendor_email\",\"password\":\"$vendor_pass\"}" )
  v_jwt=$(printf '%s' "$v_login" | extract 'access_token')
  v_id=$(printf '%s' "$v_login" | extract 'user.id')
fi
echo "  Vendor id: $v_id"

title="SMOKE-$(date +%H%M%S)"
echo "[3/8] Create live: $title"
created=$( "${CURL[@]}" -X POST "$BASE/live/sessions" \
  -H "Authorization: Bearer $v_jwt" \
  -H 'Content-Type: application/json' \
  -d "{\"title\":\"$title\"}" )
sid=$(printf '%s' "$created" | extract 'session_id')
echo "  Session id: $sid"

echo "[4/8] List active"
"${CURL[@]}" "$BASE/live/sessions/active" | sed -e 's/.*/  &/'

u_email=${U_EMAIL:-"smoke_user_$RANDOM@example.com"}
u_pass=${U_PASS:-"p$RANDOM$RANDOM"}
u_name=${U_NAME:-"user_smoke"}

echo "[5/8] Register + login temp user -> $u_email"
"${CURL[@]}" -X POST "$BASE/auth/register" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$u_email\",\"name\":\"$u_name\",\"password\":\"$u_pass\",\"role\":\"user\"}" >/dev/null || true
u_login=$( "${CURL[@]}" -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$u_email\",\"password\":\"$u_pass\"}" )
u_jwt=$(printf '%s' "$u_login" | extract 'access_token')
u_id=$(printf '%s' "$u_login" | extract 'user.id')
echo "  User id: $u_id"

echo "[6/8] Post comment as user"
"${CURL[@]}" -X POST "$BASE/live/sessions/$sid/comments" \
  -H "Authorization: Bearer $u_jwt" \
  -H 'Content-Type: application/json' \
  -d "{\"message\":\"hello from smoke test\"}" | sed -e 's/.*/  &/'

echo "[7/8] Fetch session"
"${CURL[@]}" "$BASE/live/sessions/$sid" | sed -e 's/.*/  &/'

echo "[8/8] End session"
"${CURL[@]}" -X POST "$BASE/live/sessions/$sid/end" -H "Authorization: Bearer $v_jwt" | sed -e 's/.*/  &/'

echo "Done. You can re-run to create another session."

