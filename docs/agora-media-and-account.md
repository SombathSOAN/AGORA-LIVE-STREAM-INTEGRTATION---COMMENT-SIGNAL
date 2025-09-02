# Manage Media and Devices (Agora Web SDK NG)

This guide shows how to control audio capture and playback volume in the Agora Web SDK, and how to obtain your App ID/App Certificate and tokens from Agora Console.

Prerequisite
- Implement the SDK quickstart and join/publish successfully.
- Use the NG SDK: `agora-rtc-sdk-ng`.

Implement volume control
- Local capture volume: `ILocalAudioTrack.setVolume(0–400)` adjusts microphone signal gain.
- Remote playback volume: `IRemoteAudioTrack.setVolume(0–100)` adjusts speaker playback.
- Mute/unmute: `ILocalAudioTrack.setEnabled(false)` disables capture; `true` enables. Some SDK versions also support `setMuted(boolean)`.

Examples

Mute/unmute local audio
```js
// Mute the local audio capture (stop sending audio frames)
localAudioTrack.setEnabled(false);

// or, if available in your SDK version:
// localAudioTrack.setMuted(true);

// Unmute / resume capture
localAudioTrack.setEnabled(true);
// or: localAudioTrack.setMuted(false);
```

Adjust remote playback volume
```js
// remoteUser: a subscribed remote user object
// Typical range: 0 (mute) to 100 (original)
remoteUser.audioTrack.setVolume(50);   // 50% volume
remoteUser.audioTrack.setVolume(100);  // original volume
remoteUser.audioTrack.setVolume(0);    // mute playback (still subscribed)
```

Adjust local microphone capture volume
```js
// Typical range: 0–100; can exceed 100 up to 400 (software gain)
const localAudioTrack = await AgoraRTC.createMicrophoneAudioTrack();
localAudioTrack.setVolume(50);   // reduce mic capture to 50%
localAudioTrack.setVolume(200);  // boost mic capture (may distort)
localAudioTrack.setVolume(0);    // silence capture
```

Caution
- Very high volume/gain may cause clipping or distortion on some devices.
- `setVolume` affects signal gain (capture) or playback mix; it does not change the system device volume.

API reference
- `ILocalAudioTrack.setVolume`
- `IRemoteAudioTrack.setVolume`
- `ILocalAudioTrack.setEnabled` (or `setMuted` if supported)


# Agora Account Management

Get App ID and App Certificate, and generate temporary tokens for development.

Sign up and create a project
1) Sign up and log in to Agora Console.
2) Create a new project.
3) Choose authentication: Secured mode (App ID + Token) is recommended.

Get the App ID
- In Console → Projects, copy the App ID for your project.

Get the App Certificate
- In the same project, open settings (pencil icon) and copy the Primary Certificate.

Generate a temporary token (for testing)
- In project Security, click “Generate Temp Token”, input a channel name, generate and copy the token.

Use with this repo’s token server
- Put credentials in `server/.env`:
```
AGORA_APP_ID=YOUR_APP_ID
AGORA_APP_CERTIFICATE=YOUR_APP_CERTIFICATE
ALLOWED_ORIGINS=http://localhost:5173
```
- From `server/`: `npm install` then `npm start`.
- Fetch RTC token before joining on the client:
```js
async function fetchRtcToken({ channel, role = 'host', uid = 'alice' }) {
  const params = new URLSearchParams({ channelName: channel, role, uid });
  const res = await fetch(`http://localhost:4000/v1/rtc/token?${params}`);
  if (!res.ok) throw new Error('Failed to fetch RTC token');
  return res.json();
}
```

Notes
- Never expose the App Certificate in client code; keep token minting on the server.
- Use HTTPS in production and restrict `ALLOWED_ORIGINS` appropriately.

Example UI
- A minimal web demo with mute and volume sliders is in `examples/web/index.html`. Serve it locally (for example with `python3 -m http.server` from the `examples/web` folder) and point it at your token server.
