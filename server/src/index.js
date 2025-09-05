const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');
const https = require('https');
const os = require('os');

dotenv.config();

const {
  RtcTokenBuilder,
  RtcRole,
  RtmTokenBuilder,
  RtmRole
} = require('agora-access-token');

const app = express();

// Basic security headers
app.use(helmet());
app.use(express.json());

// CORS
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS || 'http://localhost:5173';
const allowedOrigins = allowedOriginsEnv.split(',').map(s => s.trim()).filter(Boolean);

// Allow same-origin by default (useful when serving /demo) and any origins listed in ALLOWED_ORIGINS.
// Use a dynamic delegate so we can compare with the current request's host/protocol.
app.use(cors((req, callback) => {
  const origin = req.headers.origin;
  // Always allow non-browser or same-origin requests
  let sameOrigin = false;
  try {
    const selfOrigin = `${req.protocol}://${req.get('host')}`; // e.g. https://127.0.0.1:4000
    sameOrigin = !!origin && origin === selfOrigin;
  } catch (_) { /* noop */ }

  const allowAll = allowedOrigins.includes('*');
  const isListed = !!origin && allowedOrigins.includes(origin);
  const allow = !origin || sameOrigin || allowAll || isListed;
  callback(null, { origin: allow, credentials: true });
}));

// Serve demo UI (optional)
try {
  const demoDir = path.resolve(__dirname, '../../examples/web');
  // Loosen CSP for the demo so CDN scripts work
  // Allow inline script in demo page and CDN SDK script. Demo only.
  // Allow WebAssembly for RTM SDK: include 'wasm-unsafe-eval' (and legacy 'unsafe-eval' for older engines)
  const demoCsp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval' https://cdn.jsdelivr.net https://fastly.jsdelivr.net https://download.agora.io https://unpkg.com; connect-src 'self' http://localhost:4000 http://127.0.0.1:4000 http://[::1]:4000 https: wss:; media-src 'self' blob: data:;";
  const demoCspMw = (_req, res, next) => {
    res.setHeader('Content-Security-Policy', demoCsp);
    next();
  };
  // Same-origin proxy for RTM SDK to avoid iOS cross-origin security issues with self-signed certs
  let rtmSdkCache = null; // Buffer
  async function fetchOverHttps(url) {
    const { URL } = require('url');
    const u = new URL(url);
    return new Promise((resolve, reject) => {
      const req = https.get({ hostname: u.hostname, path: u.pathname + u.search, protocol: u.protocol, headers: { 'User-Agent': 'token-server' } }, (resp) => {
        if (resp.statusCode !== 200) {
          resp.resume();
          return reject(new Error(`status ${resp.statusCode}`));
        }
        const chunks = [];
        resp.on('data', d => chunks.push(d));
        resp.on('end', () => resolve(Buffer.concat(chunks)));
      });
      req.on('error', reject);
    });
  }
  // Define proxy route BEFORE static middleware so it is not shadowed
  app.get('/demo/rtm/agora-rtm.js', demoCspMw, async (_req, res) => {
    try {
      if (!rtmSdkCache) {
        // Prefer a locally vendored copy if present
        const localVendor = path.resolve(demoDir, 'vendor/agora-rtm.js');
        if (fs.existsSync(localVendor)) {
          rtmSdkCache = fs.readFileSync(localVendor);
        }
        const candidates = [
          'https://cdn.jsdelivr.net/npm/agora-rtm-sdk@2.2.3/agora-rtm.js',
          'https://unpkg.com/agora-rtm-sdk@2.2.3/agora-rtm.js'
        ];
        let lastErr;
        if (!rtmSdkCache) {
          for (const u of candidates) {
            try { rtmSdkCache = await fetchOverHttps(u); break; } catch (e) { lastErr = e; console.warn('RTM SDK fetch failed:', u, e?.message || e); }
          }
        }
        if (!rtmSdkCache) throw lastErr || new Error('failed to fetch RTM SDK');
      }
      res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
      res.setHeader('Cache-Control', 'public, max-age=86400');
      res.end(rtmSdkCache);
    } catch (e) {
      console.warn('RTM SDK proxy error:', e?.message || e);
      res.status(502).send('// failed to load RTM SDK');
    }
  });
  // Serve static assets and HTML
  app.use('/demo', demoCspMw, express.static(demoDir));
  app.get('/demo', demoCspMw, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.join(demoDir, 'index.html'));
  });
  // eslint-disable-next-line no-console
  console.log(`Serving demo from ${demoDir} at /demo`);
} catch (e) {
  // eslint-disable-next-line no-console
  console.warn('Demo not served:', e?.message || e);
}

// Serve sample App UI (vendor/user flows)
try {
  const appDir = path.resolve(__dirname, '../../examples/app');
  const appCsp = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; connect-src 'self' http: https: ws: wss:; media-src 'self' blob: data:;";
  const appCspMw = (_req, res, next) => { res.setHeader('Content-Security-Policy', appCsp); next(); };
  app.use('/app', appCspMw, express.static(appDir));
  app.get('/app', appCspMw, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.join(appDir, 'index.html'));
  });
  // eslint-disable-next-line no-console
  console.log(`Serving app from ${appDir} at /app`);
} catch (e) {
  // eslint-disable-next-line no-console
  console.warn('App UI not served:', e?.message || e);
}

const PORT = parseInt(process.env.PORT || '4000', 10);
const USE_HTTPS = (process.env.USE_HTTPS || '').trim() === '1';
const TLS_KEY_FILE = process.env.TLS_KEY_FILE;
const TLS_CERT_FILE = process.env.TLS_CERT_FILE;
const TLS_CA_FILE = process.env.TLS_CA_FILE; // optional
const APP_ID = process.env.AGORA_APP_ID; // required
const APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE; // required
const DEFAULT_TTL = parseInt(process.env.TOKEN_TTL_SECONDS || '3600', 10);

function ensureCredentials(res) {
  if (!APP_ID || !APP_CERTIFICATE) {
    res.status(500).json({
      error: 'Missing AGORA_APP_ID or AGORA_APP_CERTIFICATE in environment.'
    });
    return false;
  }
  return true;
}

function parseExpireSeconds(value) {
  const n = parseInt(value, 10);
  if (Number.isFinite(n) && n > 0 && n <= 86400 * 7) return n; // up to 7 days
  return DEFAULT_TTL;
}

// Health
app.get('/v1/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// RTC token endpoint (GET)
// Query: channelName (required), role=host|audience (default: audience), uid (optional), expire (seconds, optional)
app.get('/v1/rtc/token', (req, res) => {
  if (!ensureCredentials(res)) return; // response already sent

  const channelName = (req.query.channelName || '').toString().trim();
  const roleParam = (req.query.role || 'audience').toString().toLowerCase();
  const uidParam = req.query.uid; // may be number or string
  const expire = parseExpireSeconds(req.query.expire);

  if (!channelName) {
    return res.status(400).json({ error: 'channelName is required' });
  }

  const role = roleParam === 'host' || roleParam === 'publisher' ? RtcRole.PUBLISHER : RtcRole.SUBSCRIBER;

  const currentTs = Math.floor(Date.now() / 1000);
  const expireTs = currentTs + expire;

  try {
    let token;
    let uid;
    if (uidParam === undefined || uidParam === null || uidParam === '' || uidParam === '0') {
      // Use numeric UID 0 (SDK will pick a random UID on join)
      uid = 0;
      token = RtcTokenBuilder.buildTokenWithUid(
        APP_ID,
        APP_CERTIFICATE,
        channelName,
        uid,
        role,
        expireTs
      );
    } else if (!Number.isNaN(Number(uidParam))) {
      // Numeric UID provided
      uid = Number(uidParam);
      token = RtcTokenBuilder.buildTokenWithUid(
        APP_ID,
        APP_CERTIFICATE,
        channelName,
        uid,
        role,
        expireTs
      );
    } else {
      // String account UID
      uid = String(uidParam);
      token = RtcTokenBuilder.buildTokenWithAccount(
        APP_ID,
        APP_CERTIFICATE,
        channelName,
        uid,
        role,
        expireTs
      );
    }

    return res.json({
      appId: APP_ID,
      channel: channelName,
      uid,
      role: role === RtcRole.PUBLISHER ? 'host' : 'audience',
      expire: expire,
      token
    });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to generate RTC token', details: e?.message });
  }
});

// RTM token endpoint (GET)
// Query: uid (required), expire (seconds, optional)
app.get('/v1/rtm/token', (req, res) => {
  if (!ensureCredentials(res)) return;

  const uidParam = (req.query.uid || '').toString().trim();
  const expire = parseExpireSeconds(req.query.expire);
  if (!uidParam) {
    return res.status(400).json({ error: 'uid is required for RTM' });
  }

  const currentTs = Math.floor(Date.now() / 1000);
  const expireTs = currentTs + expire;

  try {
    const token = RtmTokenBuilder.buildToken(
      APP_ID,
      APP_CERTIFICATE,
      uidParam,
      RtmRole.Rtm_User,
      expireTs
    );
    return res.json({ appId: APP_ID, uid: uidParam, expire, token });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to generate RTM token', details: e?.message });
  }
});

// Root
const pkg = (() => { try { return require('../package.json'); } catch (_) { return { name: 'agora-backend', version: '0.0.0' }; } })();
app.get('/', (_req, res) => {
  res.json({
    name: pkg.name || 'Agora Token Server',
    version: pkg.version || '0.1.0',
    endpoints: {
      health: '/v1/health',
      rtc: '/v1/rtc/token?channelName=demo&role=host&uid=alice&expire=3600',
      rtm: '/v1/rtm/token?uid=alice&expire=3600'
    }
  });
});

// Start server
function startServer() {
  try {
    const wantHttps = USE_HTTPS;
    const haveKey = !!TLS_KEY_FILE && fs.existsSync(TLS_KEY_FILE);
    const haveCert = !!TLS_CERT_FILE && fs.existsSync(TLS_CERT_FILE);
    if (wantHttps && haveKey && haveCert) {
      const httpsOpts = {
        key: fs.readFileSync(TLS_KEY_FILE),
        cert: fs.readFileSync(TLS_CERT_FILE)
      };
      if (TLS_CA_FILE && fs.existsSync(TLS_CA_FILE)) {
        httpsOpts.ca = fs.readFileSync(TLS_CA_FILE);
      }
      https.createServer(httpsOpts, app).listen(PORT, () => {
        // eslint-disable-next-line no-console
        console.log(`Agora token server (HTTPS) listening on :${PORT}`);
        printAccessUrls(true);
      });
    } else {
      if (wantHttps && (!haveKey || !haveCert)) {
        // eslint-disable-next-line no-console
        console.warn('USE_HTTPS=1 but TLS files not found. Falling back to HTTP.');
        // eslint-disable-next-line no-console
        console.warn(`TLS_KEY_FILE=${TLS_KEY_FILE} exists=${haveKey}`);
        // eslint-disable-next-line no-console
        console.warn(`TLS_CERT_FILE=${TLS_CERT_FILE} exists=${haveCert}`);
      }
      app.listen(PORT, () => {
        // eslint-disable-next-line no-console
        console.log(`Agora token server (HTTP) listening on :${PORT}`);
        printAccessUrls(false);
      });
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Failed to start server', e);
    process.exit(1);
  }
}

startServer();

function printAccessUrls(secure) {
  const scheme = secure ? 'https' : 'http';
  const ifaces = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(ifaces)) {
    for (const net of ifaces[name] || []) {
      if (net.family === 'IPv4' && !net.internal) ips.push(net.address);
    }
  }
  // eslint-disable-next-line no-console
  console.log('Access URLs:');
  // eslint-disable-next-line no-console
  console.log(`  Local:   ${scheme}://localhost:${PORT}/demo`);
  // eslint-disable-next-line no-console
  console.log(`  Local:   ${scheme}://localhost:${PORT}/app`);
  if (ips.length) {
    for (const ip of ips) {
      // eslint-disable-next-line no-console
      console.log(`  Network: ${scheme}://${ip}:${PORT}/demo`);
      // eslint-disable-next-line no-console
      console.log(`  Network: ${scheme}://${ip}:${PORT}/app`);
    }
  } else {
    // eslint-disable-next-line no-console
    console.log('  Network: (no non-internal IPv4 found)');
  }
}
