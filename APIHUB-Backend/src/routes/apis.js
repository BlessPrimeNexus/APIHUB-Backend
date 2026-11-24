import { readJson, bad, conflict, notFound } from '../http.js';
import { str, oneOf, int, arr, obj, now, uid, serializeApi, serializeEndpoint, J, parseEndpointInput } from '../util.js';
import { generateApiKey } from '../security.js';
import { processAuthConfig, insertApi, insertEndpoint } from './projects.js';

export function register(r, ctx) {
  const { db, h } = ctx;

  r.get('/v1/projects/:pid/apis', async (req, res, c) => {
    const a = h.authenticate(req); h.project(a.userId, c.params.pid);
    return db.prepare(`SELECT a.*, (SELECT COUNT(*) FROM endpoints WHERE api_id = a.id) AS endpoint_count FROM apis a WHERE a.project_id = ? ORDER BY a.updated_at DESC`).all(c.params.pid)
      .map((x) => ({ ...serializeApi(x), endpointCount: x.endpoint_count }));
  });

  r.post('/v1/projects/:pid/apis', async (req, res, c) => {
    const a = h.authenticate(req); const p = h.project(a.userId, c.params.pid, 'developer');
    h.limit(p.workspace_id, 'apis', db.prepare('SELECT COUNT(*) n FROM apis WHERE workspace_id = ?').get(p.workspace_id).n);
    const id = insertApi(db, p.workspace_id, p.id, await readJson(req));
    db.prepare('UPDATE projects SET updated_at = ? WHERE id = ?').run(now(), p.id);
    h.audit(p.workspace_id, a.userId, 'create', 'api', id);
    return [201, serializeApi(db.prepare('SELECT * FROM apis WHERE id = ?').get(id))];
  });

  r.get('/v1/apis/:aid', async (req, res, c) => {
    const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid);
    return { ...serializeApi(api), endpoints: db.prepare('SELECT * FROM endpoints WHERE api_id = ? ORDER BY sort, created_at').all(api.id).map(serializeEndpoint) };
  });

  r.put('/v1/apis/:aid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = h.api(a.userId, c.params.aid, 'developer');
    const b = await readJson(req);
    if (b.rev !== undefined && b.rev !== ex.rev) throw conflict('API was modified by someone else. Reload and retry.', 'rev_conflict');
    const type = oneOf(b.authType ?? ex.auth_type, 'authType', ['none', 'apikey', 'bearer', 'basic', 'jwt']);
    const cfg = processAuthConfig(type, b.authConfig, type === ex.auth_type ? J(ex.auth_config, {}) : {});
    db.prepare('UPDATE apis SET name=?,description=?,version=?,base_url=?,auth_type=?,auth_config=?,docs_public=?,health_url=?,rev=rev+1,updated_at=? WHERE id=?').run(
      str(b.name ?? ex.name, 'name', { required: true, max: 80 }), str(b.description ?? ex.description, 'description', { max: 1000 }),
      str(b.version ?? ex.version, 'version', { max: 30 }) || '1.0.0', str(b.baseUrl ?? ex.base_url, 'baseUrl', { max: 300 }), type, JSON.stringify(cfg),
      (b.docsPublic ?? !!ex.docs_public) ? 1 : 0, str(b.healthUrl ?? ex.health_url, 'healthUrl', { max: 300 }), now(), ex.id);
    h.audit(ex.workspace_id, a.userId, 'update', 'api', ex.id);
    return serializeApi(db.prepare('SELECT * FROM apis WHERE id = ?').get(ex.id));
  });

  r.del('/v1/apis/:aid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = h.api(a.userId, c.params.aid, 'admin');
    db.prepare('DELETE FROM apis WHERE id = ?').run(ex.id); h.audit(ex.workspace_id, a.userId, 'delete', 'api', ex.id);
    return { ok: true };
  });

  const setPublished = (v) => async (req, res, c) => {
    const a = h.authenticate(req); const ex = h.api(a.userId, c.params.aid, 'admin');
    if (v) {
      const n = db.prepare('SELECT COUNT(*) n FROM endpoints WHERE api_id = ?').get(ex.id).n;
      if (n === 0) throw bad('Add at least one endpoint before publishing', 'no_endpoints');
    }
    db.prepare('UPDATE apis SET published = ?, updated_at = ? WHERE id = ?').run(v ? 1 : 0, now(), ex.id);
    h.audit(ex.workspace_id, a.userId, v ? 'publish' : 'unpublish', 'api', ex.id);
    return { ok: true, published: v, runUrlPath: `/run/${ex.slug}` };
  };
  r.post('/v1/apis/:aid/publish', setPublished(true));
  r.post('/v1/apis/:aid/unpublish', setPublished(false));

  // ---- Endpoints ----
  r.get('/v1/apis/:aid/endpoints', async (req, res, c) => {
    const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid);
    return db.prepare('SELECT * FROM endpoints WHERE api_id = ? ORDER BY sort, created_at').all(api.id).map(serializeEndpoint);
  });
  r.post('/v1/apis/:aid/endpoints', async (req, res, c) => {
    const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid, 'developer');
    h.limit(api.workspace_id, 'endpointsPerApi', db.prepare('SELECT COUNT(*) n FROM endpoints WHERE api_id = ?').get(api.id).n);
    const b = await readJson(req);
    let id;
    try { id = insertEndpoint(db, api.id, b); }
    catch (e) { if (String(e.message).includes('UNIQUE')) throw conflict('An endpoint with this method and path already exists', 'duplicate_endpoint'); throw e; }
    db.prepare('UPDATE apis SET rev = rev + 1, updated_at = ? WHERE id = ?').run(now(), api.id);
    h.audit(api.workspace_id, a.userId, 'create', 'endpoint', id);
    return [201, serializeEndpoint(db.prepare('SELECT * FROM endpoints WHERE id = ?').get(id))];
  });
  r.get('/v1/endpoints/:eid', async (req, res, c) => {
    const a = h.authenticate(req); return serializeEndpoint(h.endpoint(a.userId, c.params.eid));
  });
  r.put('/v1/endpoints/:eid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = h.endpoint(a.userId, c.params.eid, 'developer');
    const p = parseEndpointInput(await readJson(req), ex);
    try {
      db.prepare(`UPDATE endpoints SET name=?,description=?,group_name=?,method=?,path=?,params=?,headers=?,body_schema=?,auth_required=?,resp_status=?,resp_headers=?,resp_type=?,resp_body=?,conditions=?,sort=?,updated_at=? WHERE id=?`)
        .run(p.name, p.description, p.group_name, p.method, p.path, p.params, p.headers, p.body_schema, p.auth_required, p.resp_status, p.resp_headers, p.resp_type, p.resp_body, p.conditions, p.sort, now(), ex.id);
    } catch (e) { if (String(e.message).includes('UNIQUE')) throw conflict('An endpoint with this method and path already exists', 'duplicate_endpoint'); throw e; }
    db.prepare('UPDATE apis SET rev = rev + 1, updated_at = ? WHERE id = ?').run(now(), ex.api_id);
    h.audit(ex.ws, a.userId, 'update', 'endpoint', ex.id);
    return serializeEndpoint(db.prepare('SELECT * FROM endpoints WHERE id = ?').get(ex.id));
  });
  r.del('/v1/endpoints/:eid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = h.endpoint(a.userId, c.params.eid, 'developer');
    db.prepare('DELETE FROM endpoints WHERE id = ?').run(ex.id);
    db.prepare('UPDATE apis SET rev = rev + 1, updated_at = ? WHERE id = ?').run(now(), ex.api_id);
    h.audit(ex.ws, a.userId, 'delete', 'endpoint', ex.id);
    return { ok: true };
  });

  // ---- API keys (engine access tokens). Only a SHA-256 hash is stored; full key shown once. ----
  const serializeKey = (k) => ({ id: k.id, apiId: k.api_id, name: k.name, prefix: k.prefix, permissions: J(k.permissions, []), expiresAt: k.expires_at, revoked: !!k.revoked, lastUsedAt: k.last_used_at, createdAt: k.created_at });
  r.get('/v1/workspaces/:wid/keys', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid, 'developer');
    return db.prepare('SELECT * FROM api_keys WHERE workspace_id = ? ORDER BY created_at DESC').all(c.params.wid).map(serializeKey);
  });
  r.post('/v1/workspaces/:wid/keys', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid, 'admin');
    const b = await readJson(req);
    const name = str(b.name, 'name', { required: true, max: 60 });
    const perms = arr(b.permissions ?? ['read', 'write'], 'permissions', 5);
    if (perms.some((p) => !['read', 'write'].includes(p)) || perms.length === 0) throw bad('permissions must be read and/or write');
    let apiId = null;
    if (b.apiId) { const api = db.prepare('SELECT workspace_id FROM apis WHERE id = ?').get(b.apiId); if (!api || api.workspace_id !== c.params.wid) throw notFound('API not found'); apiId = b.apiId; }
    let exp = null;
    if (b.expiresAt !== undefined && b.expiresAt !== null) { exp = int(b.expiresAt, 'expiresAt', { min: now() + 60000, max: 4102444800000 }); }
    const k = generateApiKey(); const id = uid();
    db.prepare('INSERT INTO api_keys (id,workspace_id,api_id,name,prefix,key_hash,permissions,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(id, c.params.wid, apiId, name, k.prefix, k.hash, JSON.stringify(perms), exp, now());
    h.audit(c.params.wid, a.userId, 'create', 'api_key', id);
    return [201, { ...serializeKey(db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id)), key: k.full, notice: 'Store this key now. It cannot be shown again.' }];
  });
  r.del('/v1/keys/:kid', async (req, res, c) => {
    const a = h.authenticate(req);
    const k = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(c.params.kid);
    if (!k) throw notFound('Key not found');
    h.member(a.userId, k.workspace_id, 'admin');
    db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ?').run(k.id);
    h.audit(k.workspace_id, a.userId, 'revoke', 'api_key', k.id);
    return { ok: true };
  });

  // ---- Collections (shared, optimistic concurrency) ----
  const serializeCol = (x) => ({ id: x.id, name: x.name, data: J(x.data, {}), rev: x.rev, updatedAt: x.updated_at });
  const colData = (d) => { const o = obj(d, 'data', { folders: [], requests: [] }); if (JSON.stringify(o).length > 2_000_000) throw bad('Collection too large'); return JSON.stringify(o); };
  r.get('/v1/workspaces/:wid/collections', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid);
    return db.prepare('SELECT * FROM collections WHERE workspace_id = ? ORDER BY updated_at DESC').all(c.params.wid).map(serializeCol);
  });
  r.post('/v1/workspaces/:wid/collections', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid, 'developer');
    const b = await readJson(req); const id = uid(), t = now();
    db.prepare('INSERT INTO collections (id,workspace_id,name,data,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(id, c.params.wid, str(b.name, 'name', { required: true, max: 80 }), colData(b.data), t, t);
    return [201, serializeCol(db.prepare('SELECT * FROM collections WHERE id = ?').get(id))];
  });
  const colRow = (userId, id, role) => { const x = db.prepare('SELECT * FROM collections WHERE id = ?').get(id); if (!x) throw notFound('Collection not found'); h.member(userId, x.workspace_id, role); return x; };
  r.get('/v1/collections/:cid', async (req, res, c) => { const a = h.authenticate(req); return serializeCol(colRow(a.userId, c.params.cid)); });
  r.put('/v1/collections/:cid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = colRow(a.userId, c.params.cid, 'developer'); const b = await readJson(req);
    if (b.rev === undefined) throw bad('rev is required to prevent overwriting changes');
    if (b.rev !== ex.rev) throw conflict('Collection was modified by someone else. Reload and retry.', 'rev_conflict');
    db.prepare('UPDATE collections SET name=?, data=?, rev=rev+1, updated_at=? WHERE id=?').run(str(b.name ?? ex.name, 'name', { required: true, max: 80 }), b.data !== undefined ? colData(b.data) : ex.data, now(), ex.id);
    return serializeCol(db.prepare('SELECT * FROM collections WHERE id = ?').get(ex.id));
  });
  r.del('/v1/collections/:cid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = colRow(a.userId, c.params.cid, 'developer');
    db.prepare('DELETE FROM collections WHERE id = ?').run(ex.id); return { ok: true };
  });
}
