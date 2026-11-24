import './setup.js';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { openDb } from '../src/db.js';
import { createApp } from '../src/app.js';
import { isPrivateIp, checkOutboundUrl } from '../src/ssrf.js';
import { signJwtHS256, hashPassword, verifyPassword } from '../src/security.js';
import { toYaml } from '../src/openapi.js';

let app, base, db;
before(async () => {
  db = openDb(':memory:'); app = createApp(db);
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${app.server.address().port}`;
});
after(async () => { await app.close(); db.close(); });

const call = async (method, path, { token, body, headers } = {}) => {
  const res = await fetch(base + path, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, body: body !== undefined ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined });
  const text = await res.text(); let json; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text, headers: res.headers };
};
const signup = async (email) => {
  const r = await call('POST', '/v1/auth/register', { body: { email, password: 'Str0ngPassw0rd!', name: 'T' } });
  assert.equal(r.status, 201); return r.json;
};

test('auth: register, login, me, refresh rotation, logout, bad credentials', async () => {
  const u = await signup('a@test.io');
  assert.equal((await call('POST', '/v1/auth/register', { body: { email: 'a@test.io', password: 'Str0ngPassw0rd!' } })).status, 409);
  assert.equal((await call('POST', '/v1/auth/register', { body: { email: 'x@test.io', password: 'short' } })).status, 400);
  assert.equal((await call('POST', '/v1/auth/login', { body: { email: 'a@test.io', password: 'wrong-password1' } })).status, 401);
  assert.equal((await call('POST', '/v1/auth/login', { body: { email: 'nobody@test.io', password: 'wrong-password1' } })).status, 401);
  const l = await call('POST', '/v1/auth/login', { body: { email: 'a@test.io', password: 'Str0ngPassw0rd!' } });
  assert.equal(l.status, 200);
  const me = await call('GET', '/v1/auth/me', { token: l.json.accessToken });
  assert.equal(me.json.user.email, 'a@test.io'); assert.equal(me.json.workspaces[0].role, 'owner');
  const rf = await call('POST', '/v1/auth/refresh', { body: { refreshToken: l.json.refreshToken } });
  assert.equal(rf.status, 200);
  assert.equal((await call('POST', '/v1/auth/refresh', { body: { refreshToken: l.json.refreshToken } })).status, 401, 'refresh token is single use');
  assert.equal((await call('GET', '/v1/auth/me')).status, 401);
  assert.equal((await call('POST', '/v1/auth/logout', { token: rf.json.accessToken })).status, 200);
  assert.equal((await call('GET', '/v1/auth/me', { token: rf.json.accessToken })).status, 401);
  assert.ok(!JSON.stringify(db.prepare('SELECT password_hash FROM users').all()).includes('Str0ngPassw0rd'));
  assert.ok(u.accessToken);
});

test('access control: users cannot touch another user\'s data', async () => {
  const a = await signup('own@test.io'), b = await signup('other@test.io');
  const p = await call('POST', `/v1/workspaces/${a.workspaceId}/projects`, { token: a.accessToken, body: { name: 'Secret' } });
  assert.equal(p.status, 201);
  assert.equal((await call('GET', `/v1/projects/${p.json.id}`, { token: b.accessToken })).status, 404);
  assert.equal((await call('PUT', `/v1/projects/${p.json.id}`, { token: b.accessToken, body: { name: 'x' } })).status, 404);
  assert.equal((await call('DELETE', `/v1/projects/${p.json.id}`, { token: b.accessToken })).status, 404);
  assert.equal((await call('GET', `/v1/workspaces/${a.workspaceId}/projects`, { token: b.accessToken })).status, 404);
  assert.equal((await call('GET', `/v1/workspaces/${a.workspaceId}/stats`, { token: b.accessToken })).status, 404);
  assert.equal((await call('POST', `/v1/workspaces/${a.workspaceId}/keys`, { token: b.accessToken, body: { name: 'k' } })).status, 404);
});

test('roles: viewer is read-only, developer cannot delete, invitation flow', async () => {
  const o = await signup('owner2@test.io'), v = await signup('viewer@test.io');
  // upgrade plan check: payment not configured
  assert.equal((await call('POST', `/v1/workspaces/${o.workspaceId}/plan`, { token: o.accessToken, body: { plan: 'team' } })).status, 402);
  db.prepare("UPDATE workspaces SET plan = 'team' WHERE id = ?").run(o.workspaceId);
  const inv = await call('POST', `/v1/workspaces/${o.workspaceId}/invitations`, { token: o.accessToken, body: { email: 'viewer@test.io', role: 'viewer' } });
  assert.equal(inv.status, 201);
  assert.equal((await call('POST', '/v1/invitations/accept', { token: o.accessToken, body: { inviteToken: inv.json.inviteToken } })).status, 403, 'wrong email');
  assert.equal((await call('POST', '/v1/invitations/accept', { token: v.accessToken, body: { inviteToken: inv.json.inviteToken } })).status, 200);
  const proj = await call('POST', `/v1/workspaces/${o.workspaceId}/projects`, { token: o.accessToken, body: { name: 'Shared' } });
  assert.equal((await call('GET', `/v1/projects/${proj.json.id}`, { token: v.accessToken })).status, 200);
  assert.equal((await call('PUT', `/v1/projects/${proj.json.id}`, { token: v.accessToken, body: { name: 'hack' } })).status, 403);
  assert.equal((await call('POST', `/v1/workspaces/${o.workspaceId}/projects`, { token: v.accessToken, body: { name: 'nope' } })).status, 403);
  assert.equal((await call('GET', `/v1/workspaces/${o.workspaceId}/audit`, { token: v.accessToken })).status, 403);
});

test('projects: create, update with rev conflict, duplicate, archive, search, free-plan limit', async () => {
  const u = await signup('proj@test.io'); const t = u.accessToken, w = u.workspaceId;
  const p = (await call('POST', `/v1/workspaces/${w}/projects`, { token: t, body: { name: 'Alpha', color: '#112233' } })).json;
  assert.equal((await call('POST', `/v1/workspaces/${w}/projects`, { token: t, body: { name: 'Bad', color: 'red' } })).status, 400);
  const up = await call('PUT', `/v1/projects/${p.id}`, { token: t, body: { name: 'Alpha2', rev: p.rev } });
  assert.equal(up.status, 200); assert.equal(up.json.rev, 2);
  assert.equal((await call('PUT', `/v1/projects/${p.id}`, { token: t, body: { name: 'stale', rev: 1 } })).status, 409);
  const d = await call('POST', `/v1/projects/${p.id}/duplicate`, { token: t });
  assert.equal(d.status, 201); assert.equal(d.json.name, 'Alpha2 (copy)');
  assert.equal((await call('GET', `/v1/workspaces/${w}/projects?q=copy`, { token: t })).json.length, 1);
  await call('PUT', `/v1/projects/${d.json.id}`, { token: t, body: { archived: true } });
  assert.equal((await call('GET', `/v1/workspaces/${w}/projects`, { token: t })).json.length, 1);
  assert.equal((await call('GET', `/v1/workspaces/${w}/projects?archived=1`, { token: t })).json.length, 1);
  await call('POST', `/v1/workspaces/${w}/projects`, { token: t, body: { name: 'P3' } });
  await call('POST', `/v1/workspaces/${w}/projects`, { token: t, body: { name: 'P4' } });
  const lim = await call('POST', `/v1/workspaces/${w}/projects`, { token: t, body: { name: 'P5' } });
  assert.equal(lim.status, 402); assert.equal(lim.json.code, 'plan_limit');
});

async function setupApi(email, authType = 'none', authConfig = {}) {
  const u = await signup(email); const t = u.accessToken;
  const proj = (await call('POST', `/v1/workspaces/${u.workspaceId}/projects`, { token: t, body: { name: 'P' } })).json;
  const api = (await call('POST', `/v1/projects/${proj.id}/apis`, { token: t, body: { name: 'Users API', version: '2.0.0', authType, authConfig } })).json;
  return { u, t, proj, api };
}
const ep = (t, api, body) => call('POST', `/v1/apis/${api.id}/endpoints`, { token: t, body });

test('endpoint validation', async () => {
  const { t, api } = await setupApi('ev@test.io');
  assert.equal((await ep(t, api, { method: 'FOO', path: '/x' })).status, 400);
  assert.equal((await ep(t, api, { method: 'GET', path: '/a/../b' })).status, 400);
  assert.equal((await ep(t, api, { method: 'GET', path: '/x', respBody: '{bad json', respType: 'json' })).status, 400);
  assert.equal((await ep(t, api, { method: 'GET', path: '/x', respStatus: 999 })).status, 400);
  assert.equal((await ep(t, api, { method: 'GET', path: '/x', respHeaders: { 'Set-Cookie': 'a=b' } })).status, 400);
  assert.equal((await ep(t, api, { method: 'GET', path: '/x', respHeaders: { 'X-A': 'a\r\nInjected: 1' } })).status, 400);
  assert.equal((await ep(t, api, { method: 'GET', path: '/ok' })).status, 201);
  assert.equal((await ep(t, api, { method: 'GET', path: '/ok' })).status, 409);
  assert.equal((await call('POST', `/v1/apis/${api.id}/publish`, { token: t })).status, 200);
});

test('engine: routing, params, templates, conditions, validation, 404/405, OPTIONS, HEAD', async () => {
  const { t, api } = await setupApi('eng@test.io');
  await ep(t, api, { method: 'GET', path: '/users', respBody: '[{"id":1,"name":"Ada"}]', group: 'Users' });
  await ep(t, api, { method: 'GET', path: '/users/{id}', params: [{ name: 'id', in: 'path', type: 'integer' }], respBody: '{"id":"{{param.id}}","q":"{{query.x}}"}',
    conditions: [{ when: { source: 'param', name: 'id', op: 'eq', value: '404' }, status: 404, body: '{"error":"not found"}' }] });
  await ep(t, api, { method: 'POST', path: '/users', bodySchema: { required: ['name'], properties: { name: { type: 'string' }, age: { type: 'integer' } } }, respStatus: 201, respBody: '{"created":"{{body.name}}"}' });
  await ep(t, api, { method: 'DELETE', path: '/users/{id}', respType: 'empty', respStatus: 204 });
  await ep(t, api, { method: 'GET', path: '/text', respType: 'text', respBody: 'hello {{query.n}}', respHeaders: { 'X-Custom': 'yes' } });
  // unpublished => 404
  assert.equal((await call('GET', `/run/${api.slug}/users`)).status, 404);
  await call('POST', `/v1/apis/${api.id}/publish`, { token: t });
  const base_ = `/run/${api.slug}`;
  const l = await call('GET', `${base_}/users`); assert.equal(l.status, 200); assert.deepEqual(l.json, [{ id: 1, name: 'Ada' }]);
  assert.match(l.headers.get('content-type'), /application\/json/);
  const g = await call('GET', `${base_}/users/42?x=%22quoted%22`); assert.equal(g.status, 200); assert.equal(g.json.id, '42'); assert.equal(g.json.q, '"quoted"');
  assert.equal((await call('GET', `${base_}/users/abc`)).status, 400, 'integer path param validation');
  assert.equal((await call('GET', `${base_}/users/404`)).status, 404, 'conditional response');
  assert.equal((await call('POST', `${base_}/users`, { body: { name: 'Bob' } })).status, 201);
  assert.equal((await call('POST', `${base_}/users`, { body: { name: 'Bob' } })).json.created, 'Bob');
  const v = await call('POST', `${base_}/users`, { body: { age: 'x' } }); assert.equal(v.status, 422); assert.equal(v.json.details.length, 2);
  assert.equal((await call('POST', `${base_}/users`, { body: '{broken' })).status, 400);
  const inj = await call('POST', `${base_}/users`, { body: { name: 'a","admin":true,"x":"' } }); assert.equal(inj.status, 201); assert.equal(inj.json.admin, undefined, 'template injection prevented');
  const d = await call('DELETE', `${base_}/users/1`); assert.equal(d.status, 204); assert.equal(d.text, '');
  const tx = await call('GET', `${base_}/text?n=world`); assert.equal(tx.text, 'hello world'); assert.equal(tx.headers.get('x-custom'), 'yes'); assert.match(tx.headers.get('content-type'), /text\/plain/);
  assert.equal((await call('GET', `${base_}/nope`)).status, 404);
  const m = await call('PUT', `${base_}/users`); assert.equal(m.status, 405); assert.match(m.headers.get('allow'), /GET/);
  const o = await call('OPTIONS', `${base_}/users`); assert.equal(o.status, 204); assert.match(o.headers.get('allow'), /POST/);
  const hd = await call('HEAD', `${base_}/users`); assert.equal(hd.status, 200);
  assert.equal(l.headers.get('content-security-policy'), "default-src 'none'; sandbox");
  const cnt = db.prepare('SELECT COUNT(*) n FROM request_logs WHERE api_id = ?').get(api.id).n; assert.ok(cnt >= 10);
  const lg = db.prepare('SELECT path FROM request_logs WHERE api_id = ? AND path LIKE ?').get(api.id, '/users/%'); assert.equal(lg.path, '/users/{id}', 'logs store route template, not raw values');
});

test('engine auth: API key (hashed storage, perms, expiry, revoke), bearer, basic, jwt', async () => {
  const { u, t, api } = await setupApi('auth@test.io', 'apikey');
  await ep(t, api, { method: 'GET', path: '/secure', respBody: '{"ok":true}' });
  await ep(t, api, { method: 'POST', path: '/secure', respBody: '{"ok":true}', respStatus: 201 });
  await ep(t, api, { method: 'GET', path: '/open', authRequired: false, respBody: '{}' });
  await call('POST', `/v1/apis/${api.id}/publish`, { token: t });
  const R = `/run/${api.slug}`;
  assert.equal((await call('GET', `${R}/secure`)).status, 401);
  assert.equal((await call('GET', `${R}/open`)).status, 200);
  assert.equal((await call('GET', `${R}/secure`, { headers: { 'X-API-Key': 'ahk_fake_key' } })).status, 401);
  const k = await call('POST', `/v1/workspaces/${u.workspaceId}/keys`, { token: t, body: { name: 'ro', permissions: ['read'] } });
  assert.equal(k.status, 201); assert.match(k.json.key, /^ahk_[0-9a-f]{8}_/);
  assert.ok(!db.prepare('SELECT key_hash, prefix FROM api_keys').all().some((r) => k.json.key.includes(r.key_hash) || r.key_hash === k.json.key), 'raw key not stored');
  const list = await call('GET', `/v1/workspaces/${u.workspaceId}/keys`, { token: t }); assert.equal(list.json[0].key, undefined);
  assert.equal((await call('GET', `${R}/secure`, { headers: { 'X-API-Key': k.json.key } })).status, 200);
  assert.equal((await call('POST', `${R}/secure`, { headers: { 'X-API-Key': k.json.key }, body: {} })).status, 403, 'read-only key cannot write');
  assert.ok((await call('GET', `/v1/workspaces/${u.workspaceId}/keys`, { token: t })).json[0].lastUsedAt);
  await call('DELETE', `/v1/keys/${k.json.id}`, { token: t });
  assert.equal((await call('GET', `${R}/secure`, { headers: { 'X-API-Key': k.json.key } })).status, 401, 'revoked');
  const k2 = await call('POST', `/v1/workspaces/${u.workspaceId}/keys`, { token: t, body: { name: 'exp', expiresAt: Date.now() + 120000 } });
  db.prepare('UPDATE api_keys SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, k2.json.id);
  assert.equal((await call('GET', `${R}/secure`, { headers: { 'X-API-Key': k2.json.key } })).status, 401, 'expired');

  // basic
  const b = await setupApi('basic@test.io', 'basic', { username: 'bob', password: 'p4ssw0rd-long' });
  assert.equal(b.api.authConfig.passwordHash, undefined); assert.equal(b.api.authConfig.hasPassword, true);
  await ep(b.t, b.api, { method: 'GET', path: '/x', respBody: '{}' }); await call('POST', `/v1/apis/${b.api.id}/publish`, { token: b.t });
  const basic = (x) => ({ Authorization: 'Basic ' + Buffer.from(x).toString('base64') });
  assert.equal((await call('GET', `/run/${b.api.slug}/x`, { headers: basic('bob:wrong') })).status, 401);
  assert.equal((await call('GET', `/run/${b.api.slug}/x`, { headers: basic('bob:p4ssw0rd-long') })).status, 200);

  // jwt
  const secret = 'jwt-secret-1234567890';
  const j = await setupApi('jwt@test.io', 'jwt', { secret });
  assert.equal(j.api.authConfig.secretEnc, undefined);
  await ep(j.t, j.api, { method: 'GET', path: '/x', respBody: '{}' }); await call('POST', `/v1/apis/${j.api.id}/publish`, { token: j.t });
  const good = signJwtHS256({ sub: '1', exp: Math.floor(Date.now() / 1000) + 60 }, secret);
  const expired = signJwtHS256({ sub: '1', exp: Math.floor(Date.now() / 1000) - 60 }, secret);
  const forged = signJwtHS256({ sub: '1' }, 'other-secret-1234567890');
  const none = Buffer.from('{"alg":"none"}').toString('base64url') + '.' + Buffer.from('{"sub":"1"}').toString('base64url') + '.';
  for (const [tok, st] of [[good, 200], [expired, 401], [forged, 401], [none, 401]]) assert.equal((await call('GET', `/run/${j.api.slug}/x`, { headers: { Authorization: 'Bearer ' + tok } })).status, st);
});

test('engine: rate limiting and body size limit', async () => {
  const { t, api } = await setupApi('rl@test.io');
  await ep(t, api, { method: 'POST', path: '/x', respBody: '{}' }); await call('POST', `/v1/apis/${api.id}/publish`, { token: t });
  const big = await call('POST', `/run/${api.slug}/x`, { body: JSON.stringify({ a: 'x'.repeat(1_100_000) }) });
  assert.equal(big.status, 413);
  let last; for (let i = 0; i < 70; i++) last = await call('POST', `/run/${api.slug}/x`, { body: {} });
  assert.equal(last.status, 429, 'free plan: 60 req/min per API');
  assert.ok(last.headers.get('retry-after'));
});

test('documentation: OpenAPI 3.1 json/yaml/html matches endpoints; public docs gating', async () => {
  const { t, api } = await setupApi('doc@test.io', 'bearer');
  await ep(t, api, { method: 'GET', path: '/users/{id}', name: 'Get user', params: [{ name: 'id', in: 'path', type: 'integer' }], respBody: '{"id":1}', group: 'Users' });
  await ep(t, api, { method: 'POST', path: '/users', bodySchema: { required: ['name'], properties: { name: { type: 'string' } } }, respStatus: 201, respBody: '{"id":2}' });
  const j = await call('GET', `/v1/apis/${api.id}/openapi`, { token: t });
  assert.equal(j.json.openapi, '3.1.0'); assert.equal(j.json.info.version, '2.0.0');
  assert.deepEqual(Object.keys(j.json.paths).sort(), ['/users', '/users/{id}']);
  assert.equal(j.json.paths['/users/{id}'].get.parameters[0].schema.type, 'integer');
  assert.ok(j.json.paths['/users'].post.requestBody.content['application/json'].schema.required.includes('name'));
  assert.ok(j.json.components.securitySchemes.bearer);
  const y = await call('GET', `/v1/apis/${api.id}/openapi?format=yaml`, { token: t });
  assert.match(y.text, /^openapi: "?3\.1\.0"?/m); assert.match(y.text, /\/users\/\{id\}:/);
  const hm = await call('GET', `/v1/apis/${api.id}/openapi?format=html`, { token: t }); assert.match(hm.text, /<h1>Users API/);
  assert.equal((await call('GET', `/public/docs/${api.slug}`)).status, 404, 'private by default');
  await call('POST', `/v1/apis/${api.id}/publish`, { token: t });
  await call('PUT', `/v1/apis/${api.id}`, { token: t, body: { docsPublic: true } });
  assert.equal((await call('GET', `/public/docs/${api.slug}`)).status, 200);
  assert.equal((await call('GET', `/v1/apis/${api.id}/openapi`)).status, 401);
  assert.match(toYaml({ a: 'x: y', b: [1, { c: 'd' }], e: {} }), /a: "x: y"/);
});

test('stats, logs, alerts, retention come from real collected data', async () => {
  const { u, t, api } = await setupApi('stat@test.io');
  const w = u.workspaceId;
  const empty = await call('GET', `/v1/workspaces/${w}/stats?range=7d`, { token: t });
  assert.equal(empty.json.requests, 0); assert.equal(empty.json.successRate, null); assert.equal(empty.json.avgResponseMs, null);
  await ep(t, api, { method: 'GET', path: '/ok', authRequired: false, respBody: '{}' });
  await ep(t, api, { method: 'GET', path: '/boom', authRequired: false, respStatus: 500, respBody: '{}' });
  await call('POST', `/v1/apis/${api.id}/publish`, { token: t });
  for (let i = 0; i < 6; i++) await call('GET', `/run/${api.slug}/ok`);
  for (let i = 0; i < 4; i++) await call('GET', `/run/${api.slug}/boom`);
  await call('GET', `/run/${api.slug}/missing`);
  const s = (await call('GET', `/v1/workspaces/${w}/stats?range=today`, { token: t })).json;
  assert.equal(s.requests, 11); assert.equal(s.serverErrors, 4); assert.equal(s.clientErrors, 1);
  assert.ok(Math.abs(s.successRate - (6 / 11) * 100) < 0.01); assert.equal(s.topEndpoints[0].path, '/ok'); assert.ok(s.series.length >= 1);
  assert.equal(s.counts.endpoints, 2);
  const logs = (await call('GET', `/v1/workspaces/${w}/logs?status=5xx&limit=2`, { token: t })).json; assert.equal(logs.total, 4); assert.equal(logs.items.length, 2);
  const csv = await call('GET', `/v1/workspaces/${w}/logs/export`, { token: t }); assert.match(csv.text, /^timestamp,method,path/); assert.equal(csv.text.split('\n').length, 12);
  const al = await call('POST', `/v1/workspaces/${w}/alerts`, { token: t, body: { apiId: api.id, kind: 'error_rate', threshold: 30, windowMin: 15 } });
  assert.equal(al.status, 201);
  await app.monitor.run();
  const ev = (await call('GET', `/v1/workspaces/${w}/alert-events`, { token: t })).json; assert.equal(ev.length, 1); assert.match(ev[0].message, /Error rate/);
  await app.monitor.run(); assert.equal((await call('GET', `/v1/workspaces/${w}/alert-events`, { token: t })).json.length, 1, 'no duplicate alert inside window');
  assert.equal((await call('DELETE', `/v1/workspaces/${w}/logs`, { token: t })).json.deleted, 11);
  assert.equal((await call('GET', `/v1/workspaces/${w}/stats?range=today`, { token: t })).json.requests, 0);
});

test('sync from mobile: upsert, no silent overwrite of newer data, foreign id rejected', async () => {
  const a = await signup('sync@test.io'), b = await signup('sync2@test.io');
  const pid = crypto.randomUUID(), aid = crypto.randomUUID();
  const payload = (name, ts) => ({ projects: [{ id: pid, name, updatedAt: ts, apis: [{ id: aid, name: 'S API', authType: 'none', published: true,
    endpoints: [{ method: 'GET', path: '/ping', respBody: '{"pong":true}' }] }] }] });
  const r1 = await call('POST', `/v1/workspaces/${a.workspaceId}/sync`, { token: a.accessToken, body: payload('P1', Date.now()) });
  assert.equal(r1.status, 200); assert.equal(r1.json.endpoints, 1); assert.equal(r1.json.published[0].published, true);
  const slug = r1.json.published[0].slug;
  assert.equal((await call('GET', `/run/${slug}/ping`)).json.pong, true);
  const r2 = await call('POST', `/v1/workspaces/${a.workspaceId}/sync`, { token: a.accessToken, body: payload('OLD', 1000) });
  assert.equal(r2.json.conflicts[0].reason, 'newer_on_server');
  assert.equal(db.prepare('SELECT name FROM projects WHERE id = ?').get(pid).name, 'P1');
  assert.equal((await call('POST', `/v1/workspaces/${b.workspaceId}/sync`, { token: b.accessToken, body: payload('steal', Date.now()) })).status, 409);
  assert.equal((await call('POST', `/v1/workspaces/${a.workspaceId}/sync`, { token: a.accessToken, body: { projects: [{ id: 'not-uuid', name: 'x' }] } })).status, 400);
});

test('automated tests: plan gating, pass/fail/skipped/error results', async () => {
  const { u, t, api } = await setupApi('at@test.io');
  await ep(t, api, { method: 'GET', path: '/user', authRequired: true, respBody: '{"user":{"id":7,"name":"A"}}' });
  await call('POST', `/v1/apis/${api.id}/publish`, { token: t });
  const cases = [
    { name: 'status 200', path: '/user', expect: { status: 200, jsonHas: ['user', 'user.id'], jsonType: { 'user.id': 'integer' }, jsonEquals: { 'user.name': 'A' }, headers: { 'content-type': '' }, maxMs: 2000 } },
    { name: 'wrong status', path: '/user', expect: { status: 201 } },
    { name: 'missing field', path: '/user', expect: { jsonHas: ['user.email'] } },
    { name: 'skipped', path: '/user', enabled: false, expect: {} },
    { name: 'unknown route -> 404 expected', path: '/nope', expect: { status: 404 } },
  ];
  assert.equal((await call('POST', `/v1/apis/${api.id}/test-suites`, { token: t, body: { name: 's', cases } })).status, 402, 'free plan');
  db.prepare("UPDATE workspaces SET plan = 'pro' WHERE id = ?").run(u.workspaceId);
  const s = await call('POST', `/v1/apis/${api.id}/test-suites`, { token: t, body: { name: 's', cases } });
  assert.equal(s.status, 201);
  const run = (await call('POST', `/v1/test-suites/${s.json.id}/run`, { token: t })).json;
  assert.deepEqual([run.passed, run.failed, run.skipped, run.errored], [2, 2, 1, 0]);
  assert.equal(run.details[1].checks[0].detail, 'got 200');
});

test('environments: secrets are encrypted at rest and masked in responses', async () => {
  const { t, proj } = await setupApi('env@test.io');
  const e = await call('POST', `/v1/projects/${proj.id}/environments`, { token: t, body: { name: 'Prod', kind: 'production', baseUrl: 'https://x.io', variables: { region: 'eu' }, secrets: { token: 'sup3r-s3cret' } } });
  assert.equal(e.status, 201); assert.equal(e.json.secrets.token, '••••••••'); assert.ok(!e.text.includes('sup3r-s3cret'));
  assert.ok(!db.prepare('SELECT secrets_enc FROM environments').get().secrets_enc.includes('sup3r'));
  const u = await call('PUT', `/v1/environments/${e.json.id}`, { token: t, body: { name: 'Prod2' } });
  assert.equal(u.json.secrets.token, '••••••••', 'secrets kept when not provided');
  assert.equal((await call('POST', `/v1/projects/${proj.id}/environments`, { token: t, body: { name: 'x', variables: { 'bad name': 'v' } } })).status, 400);
});

test('collections: optimistic concurrency', async () => {
  const u = await signup('col@test.io'); const w = u.workspaceId, t = u.accessToken;
  const c = (await call('POST', `/v1/workspaces/${w}/collections`, { token: t, body: { name: 'C', data: { folders: [], requests: [] } } })).json;
  assert.equal((await call('PUT', `/v1/collections/${c.id}`, { token: t, body: { name: 'C2' } })).status, 400);
  assert.equal((await call('PUT', `/v1/collections/${c.id}`, { token: t, body: { name: 'C2', rev: c.rev } })).status, 200);
  assert.equal((await call('PUT', `/v1/collections/${c.id}`, { token: t, body: { name: 'C3', rev: c.rev } })).status, 409);
});

test('SSRF guard blocks private, loopback, link-local and metadata targets', async () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1']) assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34']) assert.equal(isPrivateIp(ip), false, ip);
  for (const u of ['http://localhost/x', 'http://127.0.0.1:8080', 'http://169.254.169.254/latest/meta-data', 'http://metadata.google.internal', 'ftp://example.com', 'http://user:pw@8.8.8.8/', 'http://[::1]/', 'http://2130706433/']) assert.equal((await checkOutboundUrl(u)).ok, false, u);
  assert.equal((await checkOutboundUrl('http://8.8.8.8/')).ok, true);
});

test('password hashing and security headers', async () => {
  const hsh = hashPassword('correct horse 123'); assert.ok(hsh.startsWith('scrypt$')); assert.ok(verifyPassword('correct horse 123', hsh)); assert.ok(!verifyPassword('nope', hsh));
  const r = await call('GET', '/health'); assert.equal(r.headers.get('x-content-type-options'), 'nosniff'); assert.equal(r.json.status, 'ok');
  assert.equal((await call('GET', '/does-not-exist')).status, 404);
});
