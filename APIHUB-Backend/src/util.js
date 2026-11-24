import { bad, forbidden, notFound, unauthorized } from './http.js';
import { sha256, uid } from './security.js';
import { PLANS } from './config.js';

export const now = () => Date.now();
export const J = (s, d) => { try { const v = JSON.parse(s); return v ?? d; } catch { return d; } };
export const camel = (o) => (o ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.replace(/_([a-z])/g, (_, c) => c.toUpperCase()), v])) : o);
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const ROLE_RANK = { viewer: 1, developer: 2, admin: 3, owner: 4 };
export const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

export function str(v, name, { min = 0, max = 200, required = false, def = '' } = {}) {
  if (v === undefined || v === null) { if (required) throw bad(`${name} is required`); return def; }
  if (typeof v !== 'string') throw bad(`${name} must be a string`);
  const t = v.trim();
  if (required && t.length === 0) throw bad(`${name} is required`);
  if (t.length < min) throw bad(`${name} must be at least ${min} characters`);
  if (t.length > max) throw bad(`${name} must be at most ${max} characters`);
  return t;
}
export function oneOf(v, name, list, def) {
  if (v === undefined || v === null) { if (def !== undefined) return def; throw bad(`${name} is required`); }
  if (!list.includes(v)) throw bad(`${name} must be one of: ${list.join(', ')}`);
  return v;
}
export function int(v, name, { min = 0, max = 1e9, def } = {}) {
  if (v === undefined || v === null) { if (def !== undefined) return def; throw bad(`${name} is required`); }
  if (!Number.isInteger(v) || v < min || v > max) throw bad(`${name} must be an integer between ${min} and ${max}`);
  return v;
}
export function obj(v, name, def = {}) {
  if (v === undefined || v === null) return def;
  if (typeof v !== 'object' || Array.isArray(v)) throw bad(`${name} must be an object`);
  return v;
}
export function arr(v, name, max = 100, def = []) {
  if (v === undefined || v === null) return def;
  if (!Array.isArray(v)) throw bad(`${name} must be an array`);
  if (v.length > max) throw bad(`${name} has too many items (max ${max})`);
  return v;
}
export function slugify(s) {
  const base = s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30) || 'api';
  return base;
}

export function makeHelpers(db) {
  const h = {};
  h.audit = (wid, userId, action, entity, entityId) =>
    db.prepare('INSERT INTO audit_log (workspace_id,user_id,action,entity,entity_id,ts) VALUES (?,?,?,?,?,?)').run(wid, userId || null, action, entity, entityId || null, now());

  h.authenticate = (req) => {
    const hdr = req.headers['authorization'] || '';
    const m = /^Bearer (.+)$/i.exec(hdr);
    if (!m) throw unauthorized();
    const s = db.prepare('SELECT s.id, s.user_id, s.access_expires_at, s.revoked, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.access_hash = ?').get(sha256(m[1]));
    if (!s || s.revoked) throw unauthorized('Invalid session');
    if (s.access_expires_at < now()) throw unauthorized('Session expired');
    return { userId: s.user_id, sessionId: s.id, email: s.email, name: s.name };
  };

  /** Returns membership or throws 404 (do not reveal existence of other workspaces). */
  h.member = (userId, wid, minRole = 'viewer') => {
    const m = db.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?').get(wid, userId);
    if (!m) throw notFound('Workspace not found');
    if (ROLE_RANK[m.role] < ROLE_RANK[minRole]) throw forbidden(`Requires role ${minRole} or higher`);
    return m.role;
  };
  h.workspace = (wid) => db.prepare('SELECT * FROM workspaces WHERE id = ?').get(wid);
  h.plan = (wid) => PLANS[h.workspace(wid)?.plan] || PLANS.free;

  h.project = (userId, pid, minRole = 'viewer') => {
    const p = db.prepare('SELECT * FROM projects WHERE id = ?').get(pid);
    if (!p) throw notFound('Project not found');
    h.member(userId, p.workspace_id, minRole);
    return p;
  };
  h.api = (userId, aid, minRole = 'viewer') => {
    const a = db.prepare('SELECT * FROM apis WHERE id = ?').get(aid);
    if (!a) throw notFound('API not found');
    h.member(userId, a.workspace_id, minRole);
    return a;
  };
  h.endpoint = (userId, eid, minRole = 'viewer') => {
    const e = db.prepare('SELECT e.*, a.workspace_id AS ws FROM endpoints e JOIN apis a ON a.id = e.api_id WHERE e.id = ?').get(eid);
    if (!e) throw notFound('Endpoint not found');
    h.member(userId, e.ws, minRole);
    return e;
  };
  h.limit = (wid, what, current) => {
    const max = h.plan(wid)[what];
    if (current >= max) {
      const e = new Error(`Plan limit reached for ${what} (${max}). Upgrade your plan.`);
      e.status = 402; e.code = 'plan_limit';
      throw e;
    }
  };
  return h;
}

export function serializeProject(p, extra = {}) {
  return { id: p.id, workspaceId: p.workspace_id, name: p.name, description: p.description, icon: p.icon, color: p.color,
    environment: p.environment, archived: !!p.archived, rev: p.rev, createdAt: p.created_at, updatedAt: p.updated_at, ...extra };
}
export function serializeApi(a) {
  const cfg = J(a.auth_config, {});
  const safe = { ...cfg };
  if (safe.secretEnc) { safe.hasSecret = true; delete safe.secretEnc; }
  if (safe.passwordHash) { safe.hasPassword = true; delete safe.passwordHash; }
  return { id: a.id, workspaceId: a.workspace_id, projectId: a.project_id, slug: a.slug, name: a.name, description: a.description,
    version: a.version, baseUrl: a.base_url, authType: a.auth_type, authConfig: safe, published: !!a.published, docsPublic: !!a.docs_public,
    healthUrl: a.health_url, rev: a.rev, createdAt: a.created_at, updatedAt: a.updated_at };
}
export function serializeEndpoint(e) {
  return { id: e.id, apiId: e.api_id, name: e.name, description: e.description, group: e.group_name, method: e.method, path: e.path,
    params: J(e.params, []), headers: J(e.headers, []), bodySchema: J(e.body_schema, {}), authRequired: !!e.auth_required,
    respStatus: e.resp_status, respHeaders: J(e.resp_headers, {}), respType: e.resp_type, respBody: e.resp_body,
    conditions: J(e.conditions, []), sort: e.sort, createdAt: e.created_at, updatedAt: e.updated_at };
}

const FORBIDDEN_RESP_HEADERS = new Set(['content-length', 'transfer-encoding', 'connection', 'set-cookie', 'keep-alive', 'upgrade', 'content-encoding', 'host', 'content-type', 'content-security-policy']);
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;

export function normalizePath(p) {
  let path = str(p, 'path', { required: true, max: 200 });
  if (!path.startsWith('/')) path = '/' + path;
  if (path.length > 1) path = path.replace(/\/+$/, '');
  if (!/^\/[A-Za-z0-9_\-./{}~:]*$/.test(path) || path.includes('..') || path.includes('//')) throw bad('path contains invalid characters');
  const names = [...path.matchAll(/\{([^}]*)\}/g)].map((m) => m[1]);
  if (names.some((n) => !/^[A-Za-z_][A-Za-z0-9_]{0,40}$/.test(n))) throw bad('invalid path parameter name');
  if (new Set(names).size !== names.length) throw bad('duplicate path parameter');
  return path;
}

export function parseEndpointInput(b, existing = null) {
  const g = (k, k2) => (b[k] !== undefined ? b[k] : existing ? existing[k2 ?? k] : undefined);
  const method = oneOf(b.method ?? existing?.method, 'method', METHODS);
  const path = normalizePath(b.path ?? existing?.path);
  const respType = oneOf(b.respType ?? existing?.resp_type, 'respType', ['json', 'text', 'empty'], 'json');
  const respStatus = int(b.respStatus ?? existing?.resp_status, 'respStatus', { min: 100, max: 599, def: 200 });
  if (respStatus === 101 || respStatus === 100) throw bad('respStatus must not be an informational status');
  let respBody = typeof b.respBody === 'string' ? b.respBody : (existing?.resp_body ?? '');
  if (respBody.length > 100_000) throw bad('respBody too large (max 100KB)');
  if (respType === 'empty') respBody = '';
  if (respType === 'json' && respBody.trim()) { try { JSON.parse(respBody); } catch (e) { throw bad('respBody is not valid JSON: ' + e.message, 'invalid_json'); } }
  const respHeaders = obj(b.respHeaders ?? (existing ? J(existing.resp_headers, {}) : {}), 'respHeaders');
  const rh = Object.entries(respHeaders);
  if (rh.length > 20) throw bad('too many response headers (max 20)');
  for (const [k, v] of rh) {
    if (!HEADER_NAME_RE.test(k) || FORBIDDEN_RESP_HEADERS.has(k.toLowerCase())) throw bad(`response header not allowed: ${k}`);
    if (typeof v !== 'string' || v.length > 500 || /[\r\n]/.test(v)) throw bad(`invalid value for header ${k}`);
  }
  const conditions = arr(b.conditions ?? (existing ? J(existing.conditions, []) : []), 'conditions', 20).map((c, i) => {
    if (!c || typeof c !== 'object') throw bad(`conditions[${i}] invalid`);
    const w = obj(c.when, `conditions[${i}].when`);
    return {
      when: { source: oneOf(w.source, 'when.source', ['query', 'header', 'param', 'body']), name: str(w.name, 'when.name', { required: true, max: 100 }),
        op: oneOf(w.op, 'when.op', ['eq', 'neq', 'exists', 'missing']), value: w.value === undefined ? '' : String(w.value).slice(0, 500) },
      status: int(c.status, 'conditions.status', { min: 200, max: 599, def: 200 }),
      body: typeof c.body === 'string' ? c.body.slice(0, 50_000) : '',
    };
  });
  const params = arr(b.params ?? (existing ? J(existing.params, []) : []), 'params', 50).map((p) => ({
    name: str(p?.name, 'param.name', { required: true, max: 60 }), in: oneOf(p?.in, 'param.in', ['path', 'query', 'header']),
    required: !!p?.required, type: oneOf(p?.type, 'param.type', ['string', 'integer', 'number', 'boolean'], 'string'), description: str(p?.description, 'param.description', { max: 300 }) }));
  const headers = arr(b.headers ?? (existing ? J(existing.headers, []) : []), 'headers', 30).map((p) => ({
    name: str(p?.name, 'header.name', { required: true, max: 60 }), required: !!p?.required, description: str(p?.description, 'header.description', { max: 300 }) }));
  const bodySchema = obj(b.bodySchema ?? (existing ? J(existing.body_schema, {}) : {}), 'bodySchema');
  if (JSON.stringify(bodySchema).length > 20_000) throw bad('bodySchema too large');
  return {
    name: str(g('name'), 'name', { max: 120 }), description: str(g('description'), 'description', { max: 1000 }),
    group_name: str(b.group ?? existing?.group_name, 'group', { max: 60 }), method, path, params: JSON.stringify(params), headers: JSON.stringify(headers),
    body_schema: JSON.stringify(bodySchema), auth_required: (b.authRequired ?? (existing ? !!existing.auth_required : true)) ? 1 : 0,
    resp_status: respStatus, resp_headers: JSON.stringify(respHeaders), resp_type: respType, resp_body: respBody, conditions: JSON.stringify(conditions),
    sort: int(b.sort ?? existing?.sort, 'sort', { min: 0, max: 100000, def: 0 }),
  };
}
export { uid };
