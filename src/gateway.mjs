import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';

const HOST = process.env.GATEWAY_HOST ?? '127.0.0.1';
const PORT = numberFromEnv('GATEWAY_PORT', 3000);
const BACKEND_HOST = process.env.BACKEND_HOST ?? '127.0.0.1';
const BACKEND_PORT = numberFromEnv('BACKEND_PORT', 4000);
const MAX_BODY_BYTES = 8 * 1024;
const MAX_TARGET_BYTES = 768;
const MIDDLEWARE_TOKEN = `auth-${crypto.randomBytes(6).toString('hex')}`;
const REQUIRED_RECURSION_DEPTH = 5;
const SESSION_SECRET = crypto.randomBytes(32);
const WINDOW_SIGNING_KEY_HEX = process.env.WINDOW_SIGNING_KEY ?? '';
if (!/^[a-f0-9]{64}$/i.test(WINDOW_SIGNING_KEY_HEX)) {
  throw new Error('WINDOW_SIGNING_KEY must be 64 hexadecimal characters');
}
const WINDOW_SIGNING_KEY = Buffer.from(WINDOW_SIGNING_KEY_HEX, 'hex');
const HONEY_FLAG = 'flag{stage_one_is_only_a_canary}';
const WINDOW_TTL_MS = 300_000;
const CONNECTION_WINDOWS = new WeakMap();

const pageStyle = `
  :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
  body { margin: 0; background: #090d18; color: #dbe7ff; }
  main { width: min(760px, calc(100% - 2rem)); margin: 8vh auto; }
  section { background: #11182a; border: 1px solid #263454; border-radius: 18px; padding: 1.4rem; margin: 1rem 0; }
  h1 { font-size: clamp(2.2rem, 7vw, 4rem); margin: 0; letter-spacing: -.05em; }
  h2 { margin-top: 0; }
  p, li { line-height: 1.6; color: #afbdd7; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
  code { color: #8ee6c2; }
  pre { padding: 1rem; overflow: auto; background: #070a12; border-radius: 12px; color: #b8f7df; }
  button, a.button { display: inline-block; border: 0; border-radius: 10px; padding: .75rem 1rem; background: #7c5cff; color: white; text-decoration: none; cursor: pointer; }
  .badge { display: inline-block; padding: .25rem .55rem; background: #173b31; color: #7ff0c2; border-radius: 999px; font-size: .8rem; }
  .muted { color: #71809e; }
`;

const homePage = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Baby Next Door</title><style>${pageStyle}</style><script src="/_next/static/chunks/app-baby.js" defer></script></head>
<body><main>
  <span class="badge">EASY · 100 pts</span>
  <h1>Baby Next Door</h1>
  <p>The intern put a tiny healthcheck in front of our private backend. Log in as an administrator and find the flag.</p>
  <section>
    <h2>Guest console</h2>
    <p>Public service: <code>online</code></p>
    <button id="ping">Run public ping</button>
    <pre id="out">No checks yet.</pre>
  </section>
  <section>
    <h2>Administrator</h2>
    <p>The deployment dashboard and relay diagnostics require an administrator session.</p>
    <a class="button" href="/dashboard">Open dashboard</a>
  </section>
  <section>
    <h2>Legacy JWT inspector</h2>
    <p>The old admin API still accepts an <code>HS256</code> bearer token.</p>
    <pre id="session">loading guest session…</pre>
    <button id="admin-api">Call admin flag API</button>
    <pre id="admin-out">Not called.</pre>
  </section>
  <p class="muted">Edge mesh: online</p>
</main><script>
let guestToken = '';
fetch('/api/session').then(r => r.json()).then(data => {
  guestToken = data.token;
  document.querySelector('#session').textContent = guestToken;
});
document.querySelector('#ping').addEventListener('click', async () => {
  const out = document.querySelector('#out');
  out.textContent = 'checking…';
  const response = await fetch('/api/public-ping');
  out.textContent = JSON.stringify(await response.json(), null, 2);
});
document.querySelector('#admin-api').addEventListener('click', async () => {
  const response = await fetch('/api/admin/flag', { headers: { Authorization: 'Bearer ' + guestToken } });
  document.querySelector('#admin-out').textContent = await response.text();
});
</script></body></html>`;

const loginPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign in</title><style>${pageStyle}</style></head>
<body><main><span class="badge">AUTH REQUIRED</span><h1>Administrator login</h1>
<section><p>SSO is unavailable in this training environment.</p><p class="muted">Password guessing is not part of this challenge.</p><a class="button" href="/">Back</a></section>
</main></body></html>`;

const dashboardPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Deployment dashboard</title><style>${pageStyle}</style></head>
<body><main><span class="badge">ADMIN</span><h1>Relay incident bundle</h1>
<p class="muted">Recovered after a failed rollback. Snapshot order and file timestamps are not trustworthy.</p>
<section><h2>client-compat.log</h2><pre>2026-10-27T03:14:11Z client=fetch
  GET /api/relay/window?ticket=5e37040d5d48ec91b8f04b551399a912
  final=204 metadata=0

2026-10-27T03:15:02Z client=wiretap
  conn=h1/9 GET /api/relay/window?ticket=5e37040d5d48ec91b8f04b551399a912
  recv=103 links=2
  recv=204 body=0</pre></section>
<section><h2>relay-v1.conf.old</h2><pre># schema=1 / retained for emergency rollback
method = POST
proof.source = header:x-relay-proof
worker.link = preload
digest = sha256(ticket || ":" || window)
result = /api/admin/flag</pre></section>
<section><h2>wire-v2.stderr</h2><pre>boot: ignored relay-v1.conf.old (schema 1)
boot: loaded wire schema 2

conn=h1/17 window=opened job=91bd...cc20
conn=h1/18 carrier=reject code=AFFINITY
conn=h1/17 method=POST carrier=reject code=SEMANTIC
conn=h1/17 method=OPTIONS framing=length carrier=idle
conn=h1/17 method=OPTIONS framing=chunked
  trailers=[x-relay-proof] carrier=armed

mac.init key=decodeHex(early[x-relay-window]) algorithm=sha256
mac.part[0]=ascii(job.ticket)
mac.part[1]=00
mac.part[2]=ascii(basename(link[preconnect]))
mac.output=hex-lower</pre></section>
<section><h2>dispatcher.audit</h2><pre>job=91bd...cc20 link[preload]    /internal/cache/28f...    -&gt; cache miss
job=91bd...cc20 link[preconnect] /internal/dispatch/f19... -&gt; 202 queued
job=91bd...cc20 inner.meta=[window,session,capability,proof]
conn=h1/21 GET /api/relay/result?ticket=91bd...cc20 read=1 -&gt; 200
conn=h1/21 GET /api/relay/result?ticket=91bd...cc20 read=2 -&gt; unavailable</pre>
<p class="muted">The public relay prefix was not changed during the rollback.</p></section>
<section><h2>Vault mirror</h2><p>The retired handler remains at <a href="/admin/flag"><code>/admin/flag</code></a>.</p></section>
</main></body></html>`;

function numberFromEnv(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isInteger(value) && value > 0 && value <= 65535 ? value : fallback;
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function issueGuestToken() {
  const header = base64UrlJson({ alg: 'HS256', typ: 'JWT', kid: 'session-v1' });
  const payload = base64UrlJson({ sub: 'guest', role: 'guest', aud: 'baby-dashboard' });
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function verifySessionToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (header.alg !== 'HS256' || header.typ !== 'JWT' || header.kid !== 'session-v1') return null;
    if (payload.aud !== 'baby-dashboard' || typeof payload.role !== 'string') return null;
    const expected = crypto.createHmac('sha256', SESSION_SECRET)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest();
    const supplied = Buffer.from(encodedSignature, 'base64url');
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
    return payload;
  } catch {
    return null;
  }
}

function setFrameworkHeaders(res) {
  res.setHeader('X-Powered-By', 'Next.js');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
}

function send(res, status, contentType, value, extraHeaders = {}) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(value ?? '', 'utf8');
  res.statusCode = status;
  setFrameworkHeaders(res);
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Length', String(body.length));
  for (const [name, headerValue] of Object.entries(extraHeaders)) {
    res.setHeader(name, headerValue);
  }
  res.end(body);
}

function sendJson(res, status, value, extraHeaders) {
  send(res, status, 'application/json; charset=utf-8', JSON.stringify(value), extraHeaders);
}

function redirectToLogin(res) {
  send(res, 302, 'text/plain; charset=utf-8', 'Authentication required.\n', {
    Location: '/login',
    'X-Route-Trace': `node=${MIDDLEWARE_TOKEN}; budget=${REQUIRED_RECURSION_DEPTH}`,
  });
}

function middlewareWasSkipped(req) {
  const raw = req.headers['x-middleware-subrequest'];
  if (typeof raw !== 'string') return false;
  const depth = raw.split(':').filter((part) => part === MIDDLEWARE_TOKEN).length;
  return depth >= REQUIRED_RECURSION_DEPTH;
}

function validTicket(ticket) {
  return /^[a-f0-9]{32}$/.test(ticket);
}

function workerSlug(windowNonce) {
  return crypto.createHash('sha256').update(`worker:${windowNonce}`).digest('hex').slice(0, 16);
}

function expectedRelayProof(state) {
  return crypto.createHmac('sha256', Buffer.from(state.windowNonce, 'hex'))
    .update(Buffer.concat([
      Buffer.from(state.ticket, 'utf8'),
      Buffer.from([0]),
      Buffer.from(state.slug, 'utf8'),
    ]))
    .digest('hex');
}

function windowCapability(windowNonce, session, ticket, slug) {
  return crypto.createHmac('sha256', WINDOW_SIGNING_KEY)
    .update(Buffer.concat([
      Buffer.from(windowNonce, 'utf8'), Buffer.from([0]),
      Buffer.from(session, 'utf8'), Buffer.from([0]),
      Buffer.from(ticket, 'utf8'), Buffer.from([0]),
      Buffer.from(slug, 'utf8'),
    ]))
    .digest('hex');
}

function activeConnectionWindow(req) {
  const state = CONNECTION_WINDOWS.get(req.socket);
  if (!state || state.expiresAt <= Date.now()) {
    if (state) CONNECTION_WINDOWS.delete(req.socket);
    return null;
  }
  return state;
}

function issueConnectionWindow(req, res, ticket) {
  const windowNonce = crypto.randomBytes(16).toString('hex');
  const session = crypto.randomBytes(18).toString('base64url');
  const slug = workerSlug(windowNonce);
  const worker = `/internal/dispatch/${slug}`;
  const decoy = `/internal/cache/${crypto.randomBytes(8).toString('hex')}`;
  const capability = windowCapability(windowNonce, session, ticket, slug);
  CONNECTION_WINDOWS.set(req.socket, {
    ticket,
    windowNonce,
    session,
    slug,
    worker,
    capability,
    expiresAt: Date.now() + WINDOW_TTL_MS,
    pending: false,
    used: false,
  });

  res.writeEarlyHints({
    'x-relay-window': windowNonce,
    'x-relay-session': session,
    'x-relay-capability': capability,
    link: [`<${decoy}>; rel=preload`, `<${worker}>; rel=preconnect`],
  });
  send(res, 204, 'text/plain; charset=utf-8', '');
}

function carrierState(req, target) {
  const state = activeConnectionWindow(req);
  if (!state || state.used || state.pending || target !== '/public/ping') return null;
  const transferEncoding = String(req.headers['transfer-encoding'] ?? '').toLowerCase();
  const chunked = transferEncoding.split(',').some((part) => part.trim() === 'chunked');
  const declaredTrailers = String(req.headers.trailer ?? '').toLowerCase().split(',').map((part) => part.trim());
  const declaresProof = declaredTrailers.includes('x-relay-proof');
  const vulnerableMethod = req.method === 'OPTIONS' || req.method === 'DELETE';
  const trailerProof = String(req.trailers['x-relay-proof'] ?? '').toLowerCase();
  if (!chunked || !declaresProof || !vulnerableMethod || trailerProof !== expectedRelayProof(state)) return null;
  return state;
}

function isProtectedPath(pathname) {
  return pathname === '/dashboard' || pathname.startsWith('/admin/') || pathname.startsWith('/api/admin/') ||
    pathname === '/api/relay' || pathname.startsWith('/api/relay/');
}

function safeUrl(req) {
  const raw = req.url ?? '/';
  if (Buffer.byteLength(raw) > MAX_TARGET_BYTES || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) {
    return null;
  }
  try {
    return { raw, parsed: new URL(raw, 'http://gateway.invalid') };
  } catch {
    return null;
  }
}

function relayTarget(rawTarget) {
  const question = rawTarget.indexOf('?');
  const rawPath = question === -1 ? rawTarget : rawTarget.slice(0, question);
  const rawQuery = question === -1 ? '' : rawTarget.slice(question);
  const prefix = '/api/relay/';

  if (!rawPath.startsWith(prefix)) return null;
  if (!/^\/api\/relay\/[a-z0-9][a-z0-9/_-]{0,127}$/i.test(rawPath)) return null;
  if (rawPath.includes('//') || rawPath.includes('..') || rawPath.includes('%')) return null;
  if (rawQuery && !/^\?[a-z0-9_=&%.-]{1,512}$/i.test(rawQuery)) return null;

  const suffix = rawPath.slice(prefix.length);
  return `/public/${suffix}${rawQuery}`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let failed = false;

    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        failed = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) reject(new Error('request body too large'));
      else resolve(Buffer.concat(chunks));
    });
    req.on('aborted', () => reject(new Error('request aborted')));
    req.on('error', reject);
  });
}

function buildBackendRequest(req, target, body, options = {}) {
  const declaredLength = options.allowDesync ? 0 : body.length;

  const lines = [
    `${req.method} ${target} HTTP/1.1`,
    'Host: backend',
    'Connection: keep-alive',
    `Content-Length: ${declaredLength}`,
    'X-Forwarded-By: baby-next-door',
  ];

  if (typeof options.session === 'string' && /^[A-Za-z0-9_-]{24}$/.test(options.session)) {
    lines.push(`X-Relay-Session: ${options.session}`);
  }

  const contentType = req.headers['content-type'];
  if (typeof contentType === 'string' && /^[\x20-\x7e]{1,128}$/.test(contentType)) {
    lines.push(`Content-Type: ${contentType}`);
  }

  // The desync branch is only armed by a valid, connection-local wire window.
  // It declares Content-Length: 0 while appending the decoded bytes, causing the
  // backend to interpret them as another request.
  return Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'), body]);
}

function parseOneResponse(buffer) {
  const headerEnd = buffer.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null;

  const headerText = buffer.subarray(0, headerEnd).toString('latin1');
  const lines = headerText.split('\r\n');
  const statusMatch = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/.exec(lines.shift() ?? '');
  if (!statusMatch) throw new Error('backend returned an invalid status line');

  const headers = {};
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Error('backend returned an invalid header');
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }

  const status = Number.parseInt(statusMatch[1], 10);
  const noBody = status < 200 || status === 204 || status === 304;
  const length = noBody ? 0 : Number.parseInt(headers['content-length'] ?? '', 10);
  if (!noBody && (!Number.isSafeInteger(length) || length < 0 || length > 64 * 1024)) {
    throw new Error('backend response requires a bounded Content-Length');
  }

  const total = headerEnd + 4 + length;
  if (buffer.length < total) return null;
  return {
    consumed: total,
    response: {
      status,
      headers,
      body: buffer.subarray(headerEnd + 4, total),
    },
  };
}

function proxyOnce(rawRequest) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: BACKEND_HOST, port: BACKEND_PORT });
    let buffer = Buffer.alloc(0);
    let settled = false;
    const timer = setTimeout(() => finish(new Error('backend timeout')), 2000);

    function finish(error, response) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        socket.destroy();
        reject(error);
        return;
      }
      resolve(response);
      // Keep the socket alive briefly so a pipelined, blind inner request can
      // finish its side effect. All later responses are intentionally ignored.
      setTimeout(() => socket.destroy(), 100);
    }

    socket.on('connect', () => socket.write(rawRequest));
    socket.on('data', (chunk) => {
      if (settled) return;
      buffer = Buffer.concat([buffer, chunk]);
      try {
        const parsed = parseOneResponse(buffer);
        if (parsed) finish(null, parsed.response);
      } catch (error) {
        finish(error);
      }
    });
    socket.on('error', (error) => finish(error));
    socket.on('end', () => {
      if (!settled) finish(new Error('backend closed before a complete response'));
    });
  });
}

function sendBackendResponse(res, upstream) {
  const contentType = upstream.headers['content-type'] ?? 'application/octet-stream';
  const allowedHeaders = {};
  if (upstream.headers['cache-control']) allowedHeaders['Cache-Control'] = upstream.headers['cache-control'];
  send(res, upstream.status, contentType, upstream.body, allowedHeaders);
}

const server = http.createServer(async (req, res) => {
  const target = safeUrl(req);
  if (!target) {
    sendJson(res, 400, { error: 'invalid request target' });
    return;
  }

  const pathname = target.parsed.pathname;
  if (isProtectedPath(pathname) && !middlewareWasSkipped(req)) {
    redirectToLogin(res);
    return;
  }

  if (req.method === 'GET' && pathname === '/') {
    send(res, 200, 'text/html; charset=utf-8', homePage);
    return;
  }
  if (req.method === 'GET' && pathname === '/login') {
    send(res, 200, 'text/html; charset=utf-8', loginPage);
    return;
  }
  if (req.method === 'GET' && pathname === '/dashboard') {
    send(res, 200, 'text/html; charset=utf-8', dashboardPage);
    return;
  }
  if (req.method === 'GET' && pathname === '/admin/flag') {
    sendJson(res, 200, { flag: HONEY_FLAG, source: 'vault-mirror' });
    return;
  }
  if (req.method === 'GET' && pathname === '/api/session') {
    sendJson(res, 200, { token: issueGuestToken(), role: 'guest', algorithm: 'HS256' });
    return;
  }
  if (req.method === 'GET' && pathname === '/api/admin/flag') {
    const authorization = String(req.headers.authorization ?? '');
    const session = authorization.startsWith('Bearer ') ? verifySessionToken(authorization.slice(7)) : null;
    if (!session) {
      sendJson(res, 401, { error: 'invalid bearer token' });
      return;
    }
    if (session.role !== 'admin') {
      sendJson(res, 403, { error: 'role mismatch', required: 'admin', got: session.role });
      return;
    }
    sendJson(res, 410, { error: 'admin API retired; use the deployment export workflow' });
    return;
  }
  if (req.method === 'GET' && pathname === '/robots.txt') {
    send(res, 200, 'text/plain; charset=utf-8', 'User-agent: *\nDisallow: /dashboard\nDisallow: /admin/flag\nDisallow: /api/admin/flag\n');
    return;
  }
  if (req.method === 'GET' && pathname === '/healthz') {
    sendJson(res, 200, { ok: true, service: 'gateway' });
    return;
  }
  if (req.method === 'GET' && pathname === '/api/public-ping') {
    sendJson(res, 200, { ok: true, scope: 'public', backend: 'hidden' });
    return;
  }
  if (req.method === 'GET' && pathname === '/_next/static/chunks/app-baby.js') {
    send(
      res,
      200,
      'application/javascript; charset=utf-8',
      'window.__BABY_BUILD__=Object.freeze({buildId:"prod-8e9a",adminApi:"/api/admin/flag",jwtAlg:"HS256"});\n//# sourceMappingURL=app-baby.js.map\n',
      { 'Cache-Control': 'public, max-age=300' },
    );
    return;
  }
  if (req.method === 'GET' && pathname === '/_next/static/chunks/app-baby.js.map') {
    sendJson(res, 200, {
      version: 3,
      file: 'app-baby.js',
      sources: ['webpack://baby/app/session.ts'],
      names: [],
      mappings: '',
      sourcesContent: [
        'export const jwtSecret = "baby-secret";\n' +
        'export const middlewareName = "middleware";\n' +
        'export const compatTargets = ["16.1.7", "15.5.13", "14.2.32"];\n' +
        'export const internalWorker = "/internal/export";\n' +
        'export const relayProof = (ticket, window) => sha256(ticket + ":" + window);\n' +
        'export const adminApi = "/api/admin/flag";\n',
      ],
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/relay/window') {
    const ticket = target.parsed.searchParams.get('ticket') ?? '';
    if (!validTicket(ticket)) {
      sendJson(res, 404, { error: 'not found' });
      return;
    }
    issueConnectionWindow(req, res, ticket);
    return;
  }

  if (pathname === '/api/relay' || pathname.startsWith('/api/relay/')) {
    const upstreamTarget = relayTarget(target.raw);
    if (!upstreamTarget) {
      sendJson(res, 400, { error: 'relay target rejected' });
      return;
    }

    try {
      const body = await readBody(req);
      const state = activeConnectionWindow(req);
      const carrier = carrierState(req, upstreamTarget);
      const isResult = upstreamTarget.startsWith('/public/result?');
      const resultTicket = isResult ? target.parsed.searchParams.get('ticket') ?? '' : '';
      const resultSession = state && state.used && state.ticket === resultTicket ? state.session : null;
      if (carrier) carrier.pending = true;
      const rawRequest = buildBackendRequest(req, upstreamTarget, body, {
        allowDesync: Boolean(carrier),
        session: resultSession,
      });
      const upstream = await proxyOnce(rawRequest);
      if (carrier) {
        carrier.pending = false;
        carrier.used = true;
      }
      sendBackendResponse(res, upstream);
    } catch (error) {
      const state = activeConnectionWindow(req);
      if (state) state.pending = false;
      const status = error.message === 'request body too large' ? 413 : 502;
      sendJson(res, status, { error: status === 413 ? error.message : 'backend unavailable' });
    }
    return;
  }

  sendJson(res, 404, { error: 'not found' });
});

server.maxHeadersCount = 64;
server.maxConnections = 256;
server.headersTimeout = 5_000;
server.requestTimeout = 5_000;
server.keepAliveTimeout = 305_000;
server.listen(PORT, HOST, () => {
  console.log(`baby-next-door gateway listening on ${HOST}:${PORT}`);
});
