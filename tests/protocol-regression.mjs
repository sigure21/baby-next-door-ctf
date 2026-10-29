import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { RawHttpConnection, requestHead } from '../solver/raw-http.mjs';

const host = process.env.CHALLENGE_HOST ?? '127.0.0.1';
const port = Number.parseInt(process.env.CHALLENGE_PORT ?? '8080', 10);
const authority = `${host}:${port}`;

function markerFromTrace(trace) {
  const match = /^node=([A-Za-z0-9_-]+); budget=(\d+)$/.exec(trace ?? '');
  assert.ok(match, 'missing route trace');
  return Array(Number.parseInt(match[2], 10)).fill(match[1]).join(':');
}

function linkByRel(linkHeader, rel) {
  for (const entry of String(linkHeader ?? '').split(',')) {
    const match = /<([^>]+)>\s*;\s*rel=([a-z]+)/i.exec(entry.trim());
    if (match && match[2].toLowerCase() === rel) return match[1];
  }
  throw new Error(`missing Link rel=${rel}`);
}

function proofFor(windowNonce, ticket, slug) {
  return crypto.createHmac('sha256', Buffer.from(windowNonce, 'hex'))
    .update(Buffer.concat([Buffer.from(ticket), Buffer.from([0]), Buffer.from(slug)]))
    .digest('hex');
}

function slugFor(windowNonce) {
  return crypto.createHash('sha256').update(`worker:${windowNonce}`).digest('hex').slice(0, 16);
}

async function openWindow() {
  const client = new RawHttpConnection(host, port);
  await client.connect();
  const denied = await client.exchange(requestHead('GET', '/dashboard', authority, { Connection: 'keep-alive' }));
  const marker = markerFromTrace(denied.final.headers['x-route-trace']);
  const ticket = crypto.randomBytes(16).toString('hex');
  const opened = await client.exchange(requestHead('GET', `/api/relay/window?ticket=${ticket}`, authority, {
    'X-Middleware-Subrequest': marker,
    Connection: 'keep-alive',
  }));
  const early = opened.informational.find((response) => response.status === 103);
  assert.ok(early);
  assert.equal(opened.final.status, 204);
  const windowNonce = early.headers['x-relay-window'];
  const session = early.headers['x-relay-session'];
  const capability = early.headers['x-relay-capability'];
  const worker = linkByRel(early.headers.link, 'preconnect');
  const decoy = linkByRel(early.headers.link, 'preload');
  const slug = worker.split('/').filter(Boolean).at(-1);
  const proof = proofFor(windowNonce, ticket, slug);
  assert.match(capability, /^[a-f0-9]{64}$/);
  return { client, marker, ticket, windowNonce, session, capability, worker, decoy, slug, proof };
}

function innerRequest(state, worker = state.worker, overrides = {}) {
  const windowNonce = overrides.windowNonce ?? state.windowNonce;
  const session = overrides.session ?? state.session;
  const proof = overrides.proof ?? state.proof;
  const capability = overrides.capability ?? state.capability;
  return Buffer.from(
    `GET ${worker}?ticket=${state.ticket} HTTP/1.1\r\n` +
    'Host: backend\r\n' +
    `X-Relay-Window: ${windowNonce}\r\n` +
    `X-Relay-Session: ${session}\r\n` +
    `X-Relay-Capability: ${capability}\r\n` +
    `X-Relay-Proof: ${proof}\r\n` +
    'Connection: keep-alive\r\n\r\n',
    'latin1',
  );
}

function chunkedCarrier(state, method, trailerProof, worker = state.worker, options = {}) {
  const inner = options.inner ?? innerRequest(state, worker);
  const trailerDeclaration = options.declareTrailer === false ? '' : 'Trailer: X-Relay-Proof\r\n';
  return Buffer.concat([
    Buffer.from(
      `${method} /api/relay/ping HTTP/1.1\r\n` +
      `Host: ${authority}\r\n` +
      `X-Middleware-Subrequest: ${state.marker}\r\n` +
      'Transfer-Encoding: chunked\r\n' +
      trailerDeclaration +
      'Connection: keep-alive\r\n\r\n' +
      `${inner.length.toString(16)}\r\n`,
      'latin1',
    ),
    inner,
    Buffer.from(`\r\n0\r\nX-Relay-Proof: ${trailerProof}\r\n\r\n`, 'latin1'),
  ]);
}

function lengthCarrier(state) {
  const inner = innerRequest(state);
  return Buffer.concat([
    Buffer.from(
      'OPTIONS /api/relay/ping HTTP/1.1\r\n' +
      `Host: ${authority}\r\n` +
      `X-Middleware-Subrequest: ${state.marker}\r\n` +
      `Content-Length: ${inner.length}\r\n` +
      'Connection: keep-alive\r\n\r\n',
      'latin1',
    ),
    inner,
  ]);
}

async function resultStatus(state) {
  const response = await state.client.exchange(requestHead('GET', `/api/relay/result?ticket=${state.ticket}`, authority, {
    'X-Middleware-Subrequest': state.marker,
    Connection: 'keep-alive',
  }));
  return response.final;
}

async function negativeCase(wireFactory, expectedCarrierStatuses) {
  const state = await openWindow();
  try {
    const carrier = await state.client.exchange(wireFactory(state));
    assert.ok(expectedCarrierStatuses.includes(carrier.final.status));
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal((await resultStatus(state)).status, 404);
  } finally {
    state.client.close();
  }
}

await negativeCase((state) => chunkedCarrier(state, 'POST', state.proof), [405]);
await negativeCase((state) => chunkedCarrier(state, 'GET', state.proof), [200]);
await negativeCase((state) => lengthCarrier(state), [204]);
await negativeCase((state) => chunkedCarrier(state, 'OPTIONS', '0'.repeat(64)), [204]);
await negativeCase(
  (state) => chunkedCarrier(state, 'OPTIONS', state.proof, state.worker, { declareTrailer: false }),
  [204],
);
await negativeCase((state) => chunkedCarrier(state, 'OPTIONS', state.proof, state.decoy), [204]);
await negativeCase((state) => {
  const alternateWindow = crypto.randomBytes(16).toString('hex');
  const alternateSlug = slugFor(alternateWindow);
  const alternateWorker = `/internal/dispatch/${alternateSlug}`;
  const alternateProof = proofFor(alternateWindow, state.ticket, alternateSlug);
  const inner = innerRequest(state, alternateWorker, {
    windowNonce: alternateWindow,
    proof: alternateProof,
  });
  return chunkedCarrier(state, 'OPTIONS', state.proof, alternateWorker, { inner });
}, [204]);

const intended = await openWindow();
const otherConnection = new RawHttpConnection(host, port);
await otherConnection.connect();
try {
  const crossCarrier = await otherConnection.exchange(chunkedCarrier(intended, 'OPTIONS', intended.proof));
  assert.equal(crossCarrier.final.status, 204);
  assert.equal((await resultStatus(intended)).status, 404);

  const carrier = await intended.client.exchange(chunkedCarrier(intended, 'OPTIONS', intended.proof));
  assert.equal(carrier.final.status, 204);

  const crossResult = await otherConnection.exchange(requestHead(
    'GET',
    `/api/relay/result?ticket=${intended.ticket}`,
    authority,
    { 'X-Middleware-Subrequest': intended.marker, Connection: 'keep-alive' },
  ));
  assert.equal(crossResult.final.status, 404);

  const result = await resultStatus(intended);
  assert.equal(result.status, 200);
  assert.match(JSON.parse(result.body.toString('utf8')).result, /^flag\{/);
  const replay = await resultStatus(intended);
  assert.equal(replay.status, 404);
} finally {
  intended.client.close();
  otherConnection.close();
}

const direct = new RawHttpConnection(host, port);
await direct.connect();
try {
  const absolute = await direct.exchange(
    `GET http://backend:4000/internal/export?ticket=${crypto.randomBytes(16).toString('hex')} HTTP/1.1\r\n` +
    `Host: ${authority}\r\nConnection: keep-alive\r\n\r\n`,
  );
  assert.equal(absolute.final.status, 400);
  const hostOnly = await direct.exchange(
    `GET /internal/export?ticket=${crypto.randomBytes(16).toString('hex')} HTTP/1.1\r\n` +
    'Host: backend\r\nConnection: close\r\n\r\n',
  );
  assert.equal(hostOnly.final.status, 404);
} finally {
  direct.close();
}

console.log('protocol regression: state machine, decoys, negative controls, and intended chain passed');
