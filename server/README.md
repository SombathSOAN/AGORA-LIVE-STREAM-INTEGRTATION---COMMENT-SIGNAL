Agora Token Backend (Express)

Overview
- Purpose: Minimal backend to mint Agora RTC/RTM tokens for the Web Interactive Live Streaming quickstart.
- Endpoints: `/v1/rtc/token` and `/v1/rtm/token` with CORS and basic validation.

Setup
1) Create `.env` from example:
   - Copy `server/.env.example` to `server/.env`
   - Fill `AGORA_APP_ID` and `AGORA_APP_CERTIFICATE` from Agora Console.
   - Optionally set `ALLOWED_ORIGINS`, `PORT`, and `TOKEN_TTL_SECONDS`.

2) Install dependencies and run:
   - From `server/` directory:
     - npm install
     - npm start

Environment Variables
- `AGORA_APP_ID`: Your Agora project App ID (required)
- `AGORA_APP_CERTIFICATE`: Your Agora project App Certificate (required)
- `ALLOWED_ORIGINS`: Comma-separated allowed origins for CORS (default: http://localhost:5173)
- `PORT`: Server port (default: 4000)
- `TOKEN_TTL_SECONDS`: Default token lifetime in seconds (default: 3600)

Endpoints
- GET `/v1/health`
  - Returns a small JSON object to confirm the server is running.

- GET `/v1/rtc/token`
  - Query params:
    - `channelName` (required): Channel to join
    - `role` (optional): `host` or `audience` (default: `audience`)
    - `uid` (optional): Numeric or string user ID. If omitted or `0`, token uses numeric UID 0 (SDK can generate UID on join)
    - `expire` (optional): TTL in seconds (default from `TOKEN_TTL_SECONDS`)
  - Response JSON: `{ appId, channel, uid, role, expire, token }`

- GET `/v1/rtm/token`
  - Query params:
    - `uid` (required): User ID for RTM
    - `expire` (optional): TTL in seconds (default from `TOKEN_TTL_SECONDS`)
  - Response JSON: `{ appId, uid, expire, token }`

Frontend Usage (example)
```js
// Fetch RTC token before joining
async function fetchRtcToken({ channel, role = 'host', uid = 'alice' }) {
  const params = new URLSearchParams({ channelName: channel, role, uid });
  const res = await fetch(`http://localhost:4000/v1/rtc/token?${params}`);
  if (!res.ok) throw new Error('Failed to fetch RTC token');
  return res.json();
}

// Join as host using Agora Web SDK NG
import AgoraRTC from 'agora-rtc-sdk-ng';

const client = AgoraRTC.createClient({ mode: 'live', codec: 'vp8' });

async function joinAsHost(appId, channel, token, uid) {
  client.setClientRole('host');
  await client.join(appId, channel, token, uid);
  const micTrack = await AgoraRTC.createMicrophoneAudioTrack();
  const camTrack = await AgoraRTC.createCameraVideoTrack();
  await client.publish([micTrack, camTrack]);
}

// When you need a token:
const { appId, channel, uid, token } = await fetchRtcToken({ channel: 'demo', role: 'host', uid: 'alice' });
await joinAsHost(appId, channel, token, uid);
```

Notes
- Use HTTPS in production. Local testing works with `http://localhost`.
- Keep your App Certificate secret; never expose it to the client.
- Configure `ALLOWED_ORIGINS` to your web app origins for CORS.

See also
- `docs/agora-media-and-account.md`: Volume controls (local/remote), mute/unmute, and Agora account setup (App ID, Certificate, tokens).

Demo UIs
- Minimal web demo at `http://localhost:4000/demo`.
  - Join as host/audience, toggle mute, and adjust local/remote volumes.
  - Relaxed CSP allows Agora CDN scripts.
- App demo (vendor/user flows) at `http://localhost:4000/app`.
  - Simple auth, create live, join/watch pages without exposing tokens in UI.

LAN Testing (share with others on Wi‑Fi)
- Easiest: serve the demo from the same origin and share your LAN IP.
  1) Find your LAN IP (macOS): `ipconfig getifaddr en0` (or `ifconfig | grep inet`)
  2) Ensure firewall allows inbound connections to Node on port `4000`.
  3) Run the server: `cd server && npm start`.
  4) Others on the same Wi‑Fi open: `http://<LAN-IP>:4000/demo`
  - Tokens are minted same‑origin, so no extra CORS setup.
  - Note: Browsers generally require HTTPS for mic/camera on non-localhost. Audience can still view and chat over HTTP, but if you want remote hosts to publish over LAN, enable HTTPS (below).

Enable HTTPS locally (for mic/camera on LAN)
- Generate a locally‑trusted certificate with `mkcert` (recommended):
  1) Install mkcert (macOS): `brew install mkcert nss` (Firefox trust)
  2) Create a cert that includes your IP and localhost:
     - `mkdir -p server/certs`
     - `cd server/certs`
     - `mkcert -install`
     - `mkcert 127.0.0.1 localhost ::1 <LAN-IP>`
     - This creates e.g. `localhost+3-key.pem` and `localhost+3.pem`.
  3) Edit `server/.env`:
     - `USE_HTTPS=1`
     - `TLS_KEY_FILE=./certs/localhost+3-key.pem`
     - `TLS_CERT_FILE=./certs/localhost+3.pem`
  4) Restart the server. Share `https://<LAN-IP>:4000/demo`
  - Each client may need to trust your local CA (mkcert handles this on your machine; other devices may show a warning until trust is added).

Tip: if you do NOT enable HTTPS and testers need to publish mic/camera from their device, Chrome allows a dev flag (not for production):
- `chrome://flags/#unsafely-treat-insecure-origin-as-secure` → add `http://<LAN-IP>:4000`
