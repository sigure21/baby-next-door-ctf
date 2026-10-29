import crypto from 'node:crypto';
import http from 'node:http';

const HOST = process.env.BACKEND_HOST ?? '127.0.0.1';
const PORT = numberFromEnv('BACKEND_PORT', 4000);
const FLAG = process.env.FLAG;
if (!FLAG || !/^flag\{[^\r\n}]{1,200}\}$/.test(FLAG)) {
  throw new Error('FLAG must be provided and use the format flag{...}');
}
const WINDOW_SIGNING_KEY_HEX = process.env.WINDOW_SIGNING_KEY ?? '';
if (!/^[a-f0-9]{64}$/i.test(WINDOW_SIGNING_KEY_HEX)) {
  throw new Error('WINDOW_SIGNING_KEY must be 64 hexadecimal characters');
}
const WINDOW_SIGNING_KEY = Buffer.from(WINDOW_SIGNING_KEY_HEX, 'hex');
const TICKET_PATTERN = /^[a-f0-9]{32}$/;
const WINDOW_PATTERN = /^[a-f0-9]{32}$/;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{24}$/;
const PROOF_PATTERN = /^[a-f0-9]{64}$/;
const CAPABILITY_PATTERN = /^[a-f0-9]{64}$/;
const ENTRY_TTL_MS = 90_000;
const MAX_MAILBOX_ENTRIES = 1024;
const mailbox = new Map();

function numberFromEnv(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isInteger(value) && value > 0 && value <= 65535 ? value : fallback;
}

function send(res, status, contentType, value, extraHeaders = {}) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(value ?? '', 'utf8');
  res.statusCode = status;
  res.setHeader('Server', 'baby-backend');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Length', String(body.length));
  for (const [name, headerValue] of Object.entries(extraHeaders)) res.setHeader(name, headerValue);
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, 'application/json; charset=utf-8', JSON.stringify(value));
}

function cleanupMailbox(now = Date.now()) {
  for (const [ticket, entry] of mailbox) {
    if (entry.expiresAt <= now) mailbox.delete(ticket);
  }
  while (mailbox.size > MAX_MAILBOX_ENTRIES) {
    const oldest = mailbox.keys().next().value;
    mailbox.delete(oldest);
  }
}

function validInternalHost(req) {
  const host = String(req.headers.host ?? '').toLowerCase();
  return host === 'backend' || host === 'backend:4000' || host === '127.0.0.1:4000' || host === 'localhost:4000';
}

function expectedWorkerSlug(windowNonce) {
  return crypto.createHash('sha256').update(`worker:${windowNonce}`).digest('hex').slice(0, 16);
}

function expectedProof(windowNonce, ticket, slug) {
  return crypto.createHmac('sha256', Buffer.from(windowNonce, 'hex'))
    .update(Buffer.concat([
      Buffer.from(ticket, 'utf8'),
      Buffer.from([0]),
      Buffer.from(slug, 'utf8'),
    ]))
    .digest('hex');
}

function expectedCapability(windowNonce, session, ticket, slug) {
  return crypto.createHmac('sha256', WINDOW_SIGNING_KEY)
    .update(Buffer.concat([
      Buffer.from(windowNonce, 'utf8'), Buffer.from([0]),
      Buffer.from(session, 'utf8'), Buffer.from([0]),
      Buffer.from(ticket, 'utf8'), Buffer.from([0]),
      Buffer.from(slug, 'utf8'),
    ]))
    .digest('hex');
}

function sameHex(left, right) {
  if (!PROOF_PATTERN.test(left) || !PROOF_PATTERN.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

const server = http.createServer((req, res) => {
  let url;
  try {
    url = new URL(req.url ?? '/', 'http://backend.invalid');
  } catch {
    sendJson(res, 400, { error: 'invalid target' });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/healthz') {
    sendJson(res, 200, { ok: true, service: 'backend' });
    return;
  }

  if (url.pathname === '/public/ping') {
    if (req.method === 'OPTIONS' || req.method === 'DELETE') {
      // The short delay makes the blind, pipelined side effect deterministic:
      // Node parses the second request before the first response is released.
      setTimeout(() => send(res, 204, 'text/plain; charset=utf-8', ''), 20);
      return;
    }
    if (req.method === 'GET') {
      sendJson(res, 200, { ok: true, service: 'private-backend', scope: 'public-relay' });
      return;
    }
    sendJson(res, 405, { error: 'method not allowed' });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/public/result') {
    cleanupMailbox();
    const ticket = url.searchParams.get('ticket') ?? '';
    const session = String(req.headers['x-relay-session'] ?? '');
    const key = `${ticket}:${session}`;
    const entry = TICKET_PATTERN.test(ticket) && SESSION_PATTERN.test(session) ? mailbox.get(key) : null;
    if (!entry) {
      sendJson(res, 404, { error: 'result unavailable' });
      return;
    }
    mailbox.delete(key);
    sendJson(res, 200, { ticket, status: 'complete', result: entry.value });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/internal/export') {
    sendJson(res, 202, { queued: true, worker: 'legacy' });
    return;
  }

  const dispatchMatch = /^\/internal\/dispatch\/([a-f0-9]{16})$/.exec(url.pathname);
  if (req.method === 'GET' && dispatchMatch) {
    const slug = dispatchMatch[1];
    const ticket = url.searchParams.get('ticket') ?? '';
    const windowNonce = String(req.headers['x-relay-window'] ?? '').toLowerCase();
    const session = String(req.headers['x-relay-session'] ?? '');
    const suppliedProof = String(req.headers['x-relay-proof'] ?? '').toLowerCase();
    const suppliedCapability = String(req.headers['x-relay-capability'] ?? '').toLowerCase();
    const capability = expectedCapability(windowNonce, session, ticket, slug);
    const valid = validInternalHost(req) && TICKET_PATTERN.test(ticket) && WINDOW_PATTERN.test(windowNonce) &&
      SESSION_PATTERN.test(session) && slug === expectedWorkerSlug(windowNonce) &&
      sameHex(suppliedProof, expectedProof(windowNonce, ticket, slug)) &&
      CAPABILITY_PATTERN.test(suppliedCapability) && sameHex(suppliedCapability, capability);
    if (!valid) {
      sendJson(res, 404, { error: 'worker unavailable' });
      return;
    }
    cleanupMailbox();
    mailbox.set(`${ticket}:${session}`, { value: FLAG, expiresAt: Date.now() + ENTRY_TTL_MS });
    cleanupMailbox();
    sendJson(res, 202, { queued: true });
    return;
  }

  sendJson(res, 404, { error: 'backend route not found' });
});

server.maxHeadersCount = 48;
server.maxConnections = 128;
server.headersTimeout = 4_000;
server.requestTimeout = 4_000;
server.keepAliveTimeout = 1_000;
server.listen(PORT, HOST, () => {
  console.log(`baby-next-door backend listening on ${HOST}:${PORT}`);
});
