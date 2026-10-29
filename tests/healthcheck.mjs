import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const baseUrl = process.env.CHALLENGE_URL ?? 'http://127.0.0.1:8080';
const marker = (node, count) => Array(count).fill(node).join(':');

async function request(path, options = {}) {
  return fetch(`${baseUrl}${path}`, { redirect: 'manual', ...options });
}

const health = await request('/healthz');
assert.equal(health.status, 200);
assert.equal((await health.json()).service, 'gateway');

const home = await request('/');
assert.equal(home.status, 200);
const homeText = await home.text();
assert.match(homeText, /Baby Next Door/);
assert.doesNotMatch(homeText, /flag\{/i);

const denied = await request('/dashboard');
assert.equal(denied.status, 302);
assert.equal(denied.headers.get('location'), '/login');
const traceMatch = /^node=([A-Za-z0-9_-]+); budget=(\d+)$/.exec(denied.headers.get('x-route-trace') ?? '');
assert.ok(traceMatch, 'denied response must expose an observable routing trace');
const routeNode = traceMatch[1];
const budget = Number.parseInt(traceMatch[2], 10);
const bypass = marker(routeNode, budget);

const cannedKnownPayload = await request('/dashboard', {
  headers: { 'x-middleware-subrequest': marker('middleware', 5) },
});
assert.equal(cannedKnownPayload.status, 302);

const fourTokens = await request('/dashboard', {
  headers: { 'x-middleware-subrequest': marker(routeNode, budget - 1) },
});
assert.equal(fourTokens.status, 302);

const fiveTokens = await request('/dashboard', {
  headers: { 'X-Middleware-Subrequest': bypass },
});
assert.equal(fiveTokens.status, 200);
const dashboardText = await fiveTokens.text();
assert.match(dashboardText, /Relay incident bundle/);
assert.match(dashboardText, /ignored relay-v1\.conf\.old \(schema 1\)/);
assert.match(dashboardText, /wire-v2\.stderr/);
assert.doesNotMatch(dashboardText, /window → carrier → result|HMAC-SHA256\(|only Link rel=preconnect/);
assert.doesNotMatch(dashboardText, /15\.2\.2|15\.5\.12|CVE-/);

const honeyWithoutBypass = await request('/admin/flag');
assert.equal(honeyWithoutBypass.status, 302);

const honey = await request('/admin/flag', {
  headers: { 'x-middleware-subrequest': bypass },
});
assert.equal(honey.status, 200);
assert.equal((await honey.json()).source, 'vault-mirror');

const sessionResponse = await request('/api/session');
assert.equal(sessionResponse.status, 200);
const session = await sessionResponse.json();
assert.equal(session.role, 'guest');
assert.equal(JSON.parse(Buffer.from(session.token.split('.')[0], 'base64url')).alg, 'HS256');

const guestAdmin = await request('/api/admin/flag', {
  headers: {
    'x-middleware-subrequest': bypass,
    authorization: `Bearer ${session.token}`,
  },
});
assert.equal(guestAdmin.status, 403);

const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: 'session-v1' })).toString('base64url');
const adminPayload = Buffer.from(JSON.stringify({ sub: 'guest', role: 'admin', aud: 'baby-dashboard' })).toString('base64url');
const noneAdmin = await request('/api/admin/flag', {
  headers: {
    'x-middleware-subrequest': bypass,
    authorization: `Bearer ${noneHeader}.${adminPayload}.`,
  },
});
assert.equal(noneAdmin.status, 401);

const weakHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'session-v1' })).toString('base64url');
const weakSigningInput = `${weakHeader}.${adminPayload}`;
const weakSignature = crypto.createHmac('sha256', 'baby-secret').update(weakSigningInput).digest('base64url');
const weakSecretAdmin = await request('/api/admin/flag', {
  headers: {
    'x-middleware-subrequest': bypass,
    authorization: `Bearer ${weakSigningInput}.${weakSignature}`,
  },
});
assert.equal(weakSecretAdmin.status, 401);

const sourceMap = await request('/_next/static/chunks/app-baby.js.map');
assert.equal(sourceMap.status, 200);
const sourceMapText = JSON.stringify(await sourceMap.json());
assert.match(sourceMapText, /baby-secret/);
assert.match(sourceMapText, /middleware/);
assert.doesNotMatch(sourceMapText, /15\.2\.2|15\.5\.12/);

const directInternal = await request('/internal/export?ticket=00000000000000000000000000000000', {
  headers: { 'x-middleware-subrequest': bypass },
});
assert.equal(directInternal.status, 404);

const relayWithoutBypass = await request('/api/relay/ping');
assert.equal(relayWithoutBypass.status, 302);

const relayPing = await request('/api/relay/ping', {
  headers: { 'x-middleware-subrequest': bypass },
});
assert.equal(relayPing.status, 200);
assert.equal((await relayPing.json()).scope, 'public-relay');

const hiddenInformational = await request('/api/relay/window?ticket=0123456789abcdef0123456789abcdef', {
  headers: { 'x-middleware-subrequest': bypass },
});
assert.equal(hiddenInformational.status, 204);
assert.equal(hiddenInformational.headers.get('x-relay-window'), null);
assert.equal(hiddenInformational.headers.get('x-relay-session'), null);
assert.equal(hiddenInformational.headers.get('x-relay-capability'), null);
assert.equal(hiddenInformational.headers.get('link'), null);

const traversal = await request('/api/relay/%2e%2e/internal/export', {
  headers: { 'x-middleware-subrequest': bypass },
});
assert.ok([400, 404].includes(traversal.status));

const uppercaseTicket = await request('/api/relay/result?ticket=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', {
  headers: { 'x-middleware-subrequest': bypass },
});
assert.equal(uppercaseTicket.status, 404);

const commaTokens = await request('/dashboard', {
  headers: { 'x-middleware-subrequest': Array(budget).fill(routeNode).join(',') },
});
assert.equal(commaTokens.status, 302);

console.log('healthcheck: core behavior and decoy traps passed');
