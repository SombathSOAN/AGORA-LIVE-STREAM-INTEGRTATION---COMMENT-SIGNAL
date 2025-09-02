# Web Demo: Mute + Volume Controls

Run a simple static server and open the page.

Prereqs
- Token server from `server/` running on `http://localhost:4000` (or adjust in UI).

Start a static server
- Python: `cd examples/web && python3 -m http.server 5173`
  - Open http://localhost:5173
- Or: `npx http-server examples/web -p 5173` (requires Node.js)

Usage
- Enter channel and uid. Choose role (Host publishes mic/camera; Audience subscribes).
- Click Join. If token server is running, it fetches a token automatically.
- Use controls:
  - Mute toggle: pause/resume local capture (`setEnabled(false|true)`).
  - Local capture volume slider: `localAudioTrack.setVolume(0–400)`.
  - Remote playback volume slider: `remoteAudioTrack.setVolume(0–100)` (enabled when a remote publishes audio).

Notes
- For manual testing without the token server, open “Manual token” in the form, fill App ID and paste a temp token from Agora Console.
- Browsers require a secure context; `http://localhost` is treated as secure for device access.
