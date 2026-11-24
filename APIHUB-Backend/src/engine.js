import { randomUUID } from 'node:crypto';
import { readBody, send, HttpError } from './http.js';
import { J, now, METHODS } from './util.js';
import { sha256, safeEqual, verifyPassword, verifyJwtHS256, decrypt } from './security.js';
import { PLANS } from './config.js';

const esc = (s) => s.replace(/[.*+?^$()|[\]\\]/g, '\\$&');
function compile(path) {
  const keys = [];
  const src = path.split(/(\{[^}]+\})/).map((part) => {
    const m = /^\{([^}]+)\}$/.exec(part);
    if (m) { keys.push(m[1]); return '([^/]+)'; }
    return esc(part);
  }).join('');
  return { re: new RegExp('^' + src + '$'), keys, dyn: keys.length };
}

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Expose-Headers': '*' };
const SAFE_HEADERS = { 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };

function getPath(obj, dotted) {
  let cur = obj;
  for (const k of dotted.split('.')) { if (cur === null || typeof cur !== 'object' || !Object.prototype.hasOwnProperty.call(cur, k)) return undefined; cur = cur[k]; }
  return cur;
}
const typeOk = (v, t) => (t === 'integer' ? Number.isInteger(v) : t === 'number' ? typeof v === 'number' && Number.isFinite(v) : t === 'array' ? Array.isArray(v)
  : t === 'object' ? v !== null && typeof v === 'object' && !Array.isArray(v) : typeof v === t);
const paramTypeOk = (s, t) => (t === 'integer' ? /^-?\d+$/.test(s) : t === 'number' ? s !== '' && Number.isFinite(Number(s)) : t === 'boolean' ? s === 'true' || s === 'false' : true);

export function createEngine({ db, limiter }) {
  const quotaCache = new Map();
  const touch = new Map();

  function monthlyUsage(wid) {
    const c = quotaCache.get(wid);
    if (c && c.exp > Date.now()) return c;
    const d = new Date(); d.setUTCDate(1); d.setUTCHours(0, 0, 0, 0);
    const n = db.prepare('SELECT COUNT(*) n FROM request_logs WHERE workspace_id = ? AND ts >= ?').get(wid, d.getTime()).n;
    const e = { n, exp: Date.now() + 15000 };
    quotaCache.set(wid, e); return e;
  }

  function checkAuth(api, method, headers) {
    const cfg = J(api.auth_config, {});
    const need = ['GET', 'HEAD', 'OPTIONS'].includes(method) ? 'read' : 'write';
    const unauth = (m, scheme) => ({ status: 401, error: m, headers: { 'WWW-Authenticate': scheme } });
    if (api.auth_type === 'apikey' || api.auth_type === 'bearer') {
      let provided;
      if (api.auth_type === 'apikey') provided = headers[(cfg.header || 'X-API-Key').toLowerCase()];
      else { const m = /^Bearer (.+)$/i.exec(headers['authorization'] || ''); provided = m && m[1]; }
      if (!provided) return unauth('Missing credentials', api.auth_type === 'bearer' ? 'Bearer' : 'ApiKey');
      const k = db.prepare('SELECT * FROM api_keys WHERE key_hash = ?').get(sha256(String(provided)));
      if (!k || k.revoked || k.workspace_id !== api.workspace_id || (k.expires_at && k.expires_at < now()) || (k.api_id && k.api_id !== api.id)) return unauth('Invalid credentials', api.auth_type === 'bearer' ? 'Bearer' : 'ApiKey');
      if (!J(k.permissions, []).includes(need)) return { status: 403, error: `Key lacks '${need}' permission` };
      const last = touch.get(k.id) || 0;
      if (Date.now() - last > 60000) { touch.set(k.id, Date.now()); db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(now(), k.id); }
      return null;
    }
    if (api.auth_type === 'basic') {
      const m = /^Basic (.+)$/i.exec(headers['authorization'] || '');
      if (!m) return unauth('Missing credentials', 'Basic realm="api"');
      const [u, ...rest] = Buffer.from(m[1], 'base64').toString('utf8').split(':');
      const okUser = cfg.username && safeEqual(u, cfg.username);
      const okPass = cfg.passwordHash && verifyPassword(rest.join(':'), cfg.passwordHash);
      if (!okUser || !okPass) return unauth('Invalid credentials', 'Basic realm="api"');
      return null;
    }
    if (api.auth_type === 'jwt') {
      const m = /^Bearer (.+)$/i.exec(headers['authorization'] || '');
      if (!m || !cfg.secretEnc) return unauth('Missing credentials', 'Bearer');
      const payload = verifyJwtHS256(m[1], decrypt(cfg.secretEnc));
      if (!payload) return unauth('Invalid or expired token', 'Bearer error="invalid_token"');
      if (cfg.audience && ![].concat(payload.aud ?? []).includes(cfg.audience)) return unauth('Invalid audience', 'Bearer error="invalid_token"');
      return null;
    }
    return null;
  }

  function validateBody(ep, method, rawBuf, contentType) {
    const bs = J(ep.body_schema, {});
    const hasSchema = (bs.required && bs.required.length) || (bs.properties && Object.keys(bs.properties).length);
    if (!['POST', 'PUT', 'PATCH'].includes(method)) return { body: undefined };
    if (!rawBuf.length) {
      if (hasSchema && bs.required?.length) return { error: { status: 422, error: 'Request body is required', details: bs.required.map((f) => ({ field: f, message: 'required' })) } };
      return { body: undefined };
    }
    let parsed;
    if (/json/i.test(contentType || '') || hasSchema) {
      try { parsed = JSON.parse(rawBuf.toString('utf8')); } catch { return { error: { status: 400, error: 'Invalid JSON body' } }; }
    }
    if (hasSchema) {
      const errors = [];
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) errors.push({ field: '(root)', message: 'must be an object' });
      else {
        for (const f of bs.required || []) if (!(f in parsed)) errors.push({ field: f, message: 'required' });
        for (const [f, d] of Object.entries(bs.properties || {})) if (f in parsed && d?.type && !typeOk(parsed[f], d.type)) errors.push({ field: f, message: `must be ${d.type}` });
      }
      if (errors.length) return { error: { status: 422, error: 'Validation failed', details: errors } };
    }
    return { body: parsed };
  }

  function render(tpl, ctx, isJson) {
    return tpl.replace(/\{\{\s*(?:(param|query|header|body)\.([A-Za-z0-9_.\-]+)|(now|uuid|timestamp))\s*\}\}/g, (_, src, name, fn) => {
      let v;
      if (fn) v = fn === 'uuid' ? randomUUID() : fn === 'now' ? new Date().toISOString() : Date.now();
      else v = src === 'body' ? getPath(ctx.body, name) : ctx[src]?.[name.toLowerCase() === name || src !== 'header' ? name : name.toLowerCase()];
      if (v === undefined || v === null) return '';
      const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
      return isJson ? JSON.stringify(s).slice(1, -1) : s;
    });
  }

  function condMatch(c, ctx) {
    const { source, name, op, value } = c.when;
    const v = source === 'body' ? getPath(ctx.body, name) : ctx[source]?.[source === 'header' ? name.toLowerCase() : name];
    const has = v !== undefined && v !== null;
    if (op === 'exists') return has;
    if (op === 'missing') return !has;
    if (op === 'eq') return has && String(v) === value;
    if (op === 'neq') return !has || String(v) !== value;
    return false;
  }

  /** Core execution. Returns { status, headers, body, endpointId, error } and never throws for user errors. */
  async function execute({ api, method, path, query, headers, bodyBuf, ip, skipAuth = false, skipLimits = false }) {
    const plan = PLANS[db.prepare('SELECT plan FROM workspaces WHERE id = ?').get(api.workspace_id)?.plan] || PLANS.free;
    const fail = (status, error, extra = {}, endpointId = null) => ({ status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...(extra.headers || {}) }, body: JSON.stringify({ error, ...(extra.details ? { details: extra.details } : {}) }), endpointId, error });
    if (!skipLimits) {
      if (!limiter.hit('eng:ip:' + ip, 300, 60000).allowed) return fail(429, 'Too many requests from this address');
      const l = limiter.hit('eng:api:' + api.id, plan.ratePerMin, 60000);
      if (!l.allowed) return fail(429, 'API rate limit exceeded', { headers: { 'Retry-After': String(Math.ceil(l.resetMs / 1000)) } });
      if (monthlyUsage(api.workspace_id).n >= plan.requestsPerMonth) return fail(429, 'Monthly request quota exceeded');
    }
    const eps = db.prepare('SELECT * FROM endpoints WHERE api_id = ?').all(api.id).map((e) => ({ e, c: compile(e.path) }));
    eps.sort((a, b) => a.c.dyn - b.c.dyn || b.e.path.length - a.e.path.length);
    const matches = eps.map((x) => ({ ...x, m: x.c.re.exec(path) })).filter((x) => x.m);
    if (!matches.length) return fail(404, 'No such endpoint');
    if (method === 'OPTIONS' && !matches.some((x) => x.e.method === 'OPTIONS')) {
      const allow = [...new Set(matches.flatMap((x) => [x.e.method, ...(x.e.method === 'GET' ? ['HEAD'] : [])]).concat('OPTIONS'))].join(', ');
      return { status: 204, headers: { Allow: allow, 'Access-Control-Allow-Methods': allow }, body: '', endpointId: null };
    }
    const hit = matches.find((x) => x.e.method === method) || (method === 'HEAD' ? matches.find((x) => x.e.method === 'GET') : null);
    if (!hit) {
      const allow = [...new Set(matches.map((x) => x.e.method))].join(', ');
      return fail(405, 'Method not allowed', { headers: { Allow: allow } });
    }
    const ep = hit.e;
    if (!skipAuth && api.auth_type !== 'none' && ep.auth_required) {
      const a = checkAuth(api, ep.method === 'GET' && method === 'HEAD' ? 'HEAD' : method, headers);
      if (a) return fail(a.status, a.error, { headers: a.headers }, ep.id);
    }
    const pathParams = {}; hit.c.keys.forEach((k, i) => { try { pathParams[k] = decodeURIComponent(hit.m[i + 1]); } catch { pathParams[k] = hit.m[i + 1]; } });
    const q = Object.fromEntries(query.entries());
    const details = [];
    for (const p of J(ep.params, [])) {
      const val = p.in === 'path' ? pathParams[p.name] : p.in === 'query' ? q[p.name] : headers[p.name.toLowerCase()];
      if (val === undefined) { if (p.required) details.push({ field: p.name, in: p.in, message: 'required' }); continue; }
      if (!paramTypeOk(String(val), p.type)) details.push({ field: p.name, in: p.in, message: `must be ${p.type}` });
    }
    for (const hd of J(ep.headers, [])) if (hd.required && headers[hd.name.toLowerCase()] === undefined) details.push({ field: hd.name, in: 'header', message: 'required' });
    if (details.length) return fail(400, 'Invalid parameters', { details }, ep.id);
    const vb = validateBody(ep, method === 'HEAD' ? 'HEAD' : ep.method === method ? method : method, bodyBuf, headers['content-type']);
    if (vb.error) return fail(vb.error.status, vb.error.error, { details: vb.error.details }, ep.id);
    const rc = { param: pathParams, query: q, header: headers, body: vb.body };
    let status = ep.resp_status, body = ep.resp_body;
    for (const c of J(ep.conditions, [])) { if (condMatch(c, rc)) { status = c.status; body = c.body; break; } }
    const out = { 'Content-Type': ep.resp_type === 'json' ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8', ...J(ep.resp_headers, {}) };
    let payload = ep.resp_type === 'empty' ? '' : render(body, rc, ep.resp_type === 'json');
    if (ep.resp_type === 'json' && payload.trim()) { try { JSON.parse(payload); } catch { return fail(500, 'Rendered response is not valid JSON', {}, ep.id); } }
    if (ep.resp_type === 'empty' || status === 204 || status === 304) { payload = ''; delete out['Content-Type']; }
    return { status, headers: out, body: payload, endpointId: ep.id, endpointPath: ep.path };
  }

  const logStmt = db.prepare('INSERT INTO request_logs (workspace_id,api_id,endpoint_id,ts,method,path,status,duration_ms,size,error) VALUES (?,?,?,?,?,?,?,?,?,?)');

  async function handle(req, res, url, ip) {
    const started = Date.now();
    const m = /^\/run\/([a-z0-9-]{1,60})(\/.*)?$/.exec(url.pathname);
    if (!m) return false;
    const method = req.method;
    if (!METHODS.includes(method)) { send(res, 405, { error: 'Method not allowed' }, { ...CORS, ...SAFE_HEADERS }); return true; }
    const api = db.prepare('SELECT * FROM apis WHERE slug = ?').get(m[1]);
    if (!api || !api.published) { send(res, 404, { error: 'API not found or not published' }, { ...CORS, ...SAFE_HEADERS }); return true; }
    let path = m[2] || '/'; if (path.length > 1) path = path.replace(/\/+$/, '');
    let bodyBuf = Buffer.alloc(0);
    try { bodyBuf = await readBody(req); } catch (e) {
      const status = e instanceof HttpError ? e.status : 400;
      send(res, status, { error: e.message }, { ...CORS, ...SAFE_HEADERS }); return true;
    }
    const headers = {}; for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
    let r;
    try { r = await execute({ api, method, path, query: url.searchParams, headers, bodyBuf, ip }); }
    catch (e) { r = { status: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'Internal error' }), endpointId: null, error: 'internal' }; }
    const size = send(res, r.status, r.body === '' ? undefined : r.body, { ...CORS, ...SAFE_HEADERS, ...r.headers });
    try { logStmt.run(api.workspace_id, api.id, r.endpointId || null, now(), method, r.endpointPath || '(unmatched)', r.status, Date.now() - started, size, r.status >= 500 ? String(r.error || '').slice(0, 200) : ''); } catch { /* logging must never break requests */ }
    return true;
  }

  return { handle, execute };
}
