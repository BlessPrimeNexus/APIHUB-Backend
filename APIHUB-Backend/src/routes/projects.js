import { readJson, bad, conflict, notFound } from '../http.js';
import { str, oneOf, int, obj, arr, now, uid, UUID_RE, serializeProject, serializeApi, serializeEndpoint, J, slugify, parseEndpointInput } from '../util.js';
import { encrypt, hashPassword, token } from '../security.js';

const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
const ENVS = ['development', 'testing', 'staging', 'production', 'custom'];

export function processAuthConfig(type, input, existing = {}) {
  const cfg = { ...existing };
  const i = obj(input, 'authConfig');
  if (type === 'apikey') cfg.header = str(i.header ?? cfg.header ?? 'X-API-Key', 'authConfig.header', { max: 60 }) || 'X-API-Key';
  if (type === 'basic') {
    if (i.username !== undefined) cfg.username = str(i.username, 'authConfig.username', { required: true, max: 80 });
    if (i.password) cfg.passwordHash = hashPassword(str(i.password, 'authConfig.password', { min: 8, max: 200 }));
  }
  if (type === 'jwt' && i.secret) cfg.secretEnc = encrypt(str(i.secret, 'authConfig.secret', { min: 16, max: 200 }));
  if (type === 'jwt' && i.audience !== undefined) cfg.audience = str(i.audience, 'authConfig.audience', { max: 200 });
  for (const k of Object.keys(cfg)) { if (!['header', 'username', 'passwordHash', 'secretEnc', 'audience'].includes(k)) delete cfg[k]; }
  return cfg;
}

export function newSlug(db, name) {
  for (let i = 0; i < 10; i++) {
    const s = `${slugify(name)}-${token(3).toLowerCase().replace(/[^a-z0-9]/g, 'x').slice(0, 5)}`;
    if (!db.prepare('SELECT 1 FROM apis WHERE slug = ?').get(s)) return s;
  }
  throw new Error('slug generation failed');
}

export function insertApi(db, wid, pid, a, id = uid()) {
  const t = now();
  const type = oneOf(a.authType, 'authType', ['none', 'apikey', 'bearer', 'basic', 'jwt'], 'none');
  db.prepare(`INSERT INTO apis (id,workspace_id,project_id,slug,name,description,version,base_url,auth_type,auth_config,docs_public,health_url,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, wid, pid, newSlug(db, str(a.name, 'name', { required: true, max: 80 })), str(a.name, 'name', { required: true, max: 80 }),
    str(a.description, 'description', { max: 1000 }), str(a.version, 'version', { max: 30, def: '1.0.0' }) || '1.0.0', str(a.baseUrl, 'baseUrl', { max: 300 }),
    type, JSON.stringify(processAuthConfig(type, a.authConfig)), a.docsPublic ? 1 : 0, str(a.healthUrl, 'healthUrl', { max: 300 }), t, t);
  return id;
}
export function insertEndpoint(db, apiId, e) {
  const p = parseEndpointInput(e);
  const t = now();
  const id = e.id && UUID_RE.test(e.id) ? e.id : uid();
  db.prepare(`INSERT INTO endpoints (id,api_id,name,description,group_name,method,path,params,headers,body_schema,auth_required,resp_status,resp_headers,resp_type,resp_body,conditions,sort,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, apiId, p.name, p.description, p.group_name, p.method, p.path, p.params, p.headers, p.body_schema,
    p.auth_required, p.resp_status, p.resp_headers, p.resp_type, p.resp_body, p.conditions, p.sort, t, t);
  return id;
}

export function register(r, ctx) {
  const { db, h } = ctx;

  const projectInput = (b, ex) => ({
    name: str(b.name ?? ex?.name, 'name', { required: true, max: 80 }),
    description: str(b.description ?? ex?.description, 'description', { max: 500 }),
    icon: str(b.icon ?? ex?.icon, 'icon', { max: 30, def: 'folder' }) || 'folder',
    color: (() => { const c = b.color ?? ex?.color ?? '#2F5BFF'; if (!COLOR_RE.test(c)) throw bad('color must be #RRGGBB'); return c; })(),
    environment: oneOf(b.environment ?? ex?.environment, 'environment', ENVS, 'development'),
  });

  r.get('/v1/workspaces/:wid/projects', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid);
    const q = (c.query.get('q') || '').toLowerCase();
    const archived = c.query.get('archived') === '1' ? 1 : 0;
    const rows = db.prepare(`SELECT p.*, (SELECT COUNT(*) FROM apis WHERE project_id = p.id) AS api_count,
      (SELECT COUNT(*) FROM endpoints e JOIN apis a ON a.id = e.api_id WHERE a.project_id = p.id) AS endpoint_count
      FROM projects p WHERE p.workspace_id = ? AND p.archived = ? ORDER BY p.updated_at DESC`).all(c.params.wid, archived);
    return rows.filter((p) => !q || p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q)).map((p) => serializeProject(p, { apiCount: p.api_count, endpointCount: p.endpoint_count }));
  });

  r.post('/v1/workspaces/:wid/projects', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid, 'developer');
    const b = await readJson(req);
    h.limit(c.params.wid, 'projects', db.prepare('SELECT COUNT(*) n FROM projects WHERE workspace_id = ? AND archived = 0').get(c.params.wid).n);
    const p = projectInput(b);
    const id = b.id && UUID_RE.test(b.id) && !db.prepare('SELECT 1 FROM projects WHERE id = ?').get(b.id) ? b.id : uid();
    const t = now();
    db.prepare('INSERT INTO projects (id,workspace_id,name,description,icon,color,environment,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)').run(id, c.params.wid, p.name, p.description, p.icon, p.color, p.environment, t, t);
    h.audit(c.params.wid, a.userId, 'create', 'project', id);
    return [201, serializeProject(db.prepare('SELECT * FROM projects WHERE id = ?').get(id))];
  });

  r.get('/v1/projects/:pid', async (req, res, c) => {
    const a = h.authenticate(req);
    return serializeProject(h.project(a.userId, c.params.pid));
  });

  r.put('/v1/projects/:pid', async (req, res, c) => {
    const a = h.authenticate(req);
    const ex = h.project(a.userId, c.params.pid, 'developer');
    const b = await readJson(req);
    if (b.rev !== undefined && b.rev !== ex.rev) throw conflict('Project was modified by someone else. Reload and retry.', 'rev_conflict');
    const p = projectInput(b, ex);
    const archived = b.archived !== undefined ? (b.archived ? 1 : 0) : ex.archived;
    db.prepare('UPDATE projects SET name=?,description=?,icon=?,color=?,environment=?,archived=?,rev=rev+1,updated_at=? WHERE id=?').run(p.name, p.description, p.icon, p.color, p.environment, archived, now(), ex.id);
    h.audit(ex.workspace_id, a.userId, 'update', 'project', ex.id);
    return serializeProject(db.prepare('SELECT * FROM projects WHERE id = ?').get(ex.id));
  });

  r.del('/v1/projects/:pid', async (req, res, c) => {
    const a = h.authenticate(req);
    const ex = h.project(a.userId, c.params.pid, 'admin');
    db.prepare('DELETE FROM projects WHERE id = ?').run(ex.id);
    h.audit(ex.workspace_id, a.userId, 'delete', 'project', ex.id);
    return { ok: true };
  });

  r.post('/v1/projects/:pid/duplicate', async (req, res, c) => {
    const a = h.authenticate(req);
    const ex = h.project(a.userId, c.params.pid, 'developer');
    h.limit(ex.workspace_id, 'projects', db.prepare('SELECT COUNT(*) n FROM projects WHERE workspace_id = ? AND archived = 0').get(ex.workspace_id).n);
    const id = uid(), t = now();
    db.exec('BEGIN');
    try {
      db.prepare('INSERT INTO projects (id,workspace_id,name,description,icon,color,environment,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)').run(id, ex.workspace_id, (ex.name + ' (copy)').slice(0, 80), ex.description, ex.icon, ex.color, ex.environment, t, t);
      for (const api of db.prepare('SELECT * FROM apis WHERE project_id = ?').all(ex.id)) {
        const nid = uid();
        db.prepare(`INSERT INTO apis (id,workspace_id,project_id,slug,name,description,version,base_url,auth_type,auth_config,published,docs_public,health_url,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,0,0,?,?,?)`).run(nid, api.workspace_id, id, newSlug(db, api.name), api.name, api.description, api.version, api.base_url, api.auth_type, api.auth_config, api.health_url, t, t);
        for (const e of db.prepare('SELECT * FROM endpoints WHERE api_id = ?').all(api.id)) {
          db.prepare(`INSERT INTO endpoints (id,api_id,name,description,group_name,method,path,params,headers,body_schema,auth_required,resp_status,resp_headers,resp_type,resp_body,conditions,sort,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(uid(), nid, e.name, e.description, e.group_name, e.method, e.path, e.params, e.headers, e.body_schema, e.auth_required, e.resp_status, e.resp_headers, e.resp_type, e.resp_body, e.conditions, e.sort, t, t);
        }
      }
      for (const en of db.prepare('SELECT * FROM environments WHERE project_id = ?').all(ex.id)) {
        // secrets are NOT duplicated
        db.prepare('INSERT INTO environments (id,workspace_id,project_id,name,kind,base_url,variables,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)').run(uid(), en.workspace_id, id, en.name, en.kind, en.base_url, en.variables, t, t);
      }
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    h.audit(ex.workspace_id, a.userId, 'duplicate', 'project', id);
    return [201, serializeProject(db.prepare('SELECT * FROM projects WHERE id = ?').get(id))];
  });

  // ---- Environments ----
  const maskSecrets = (e) => {
    let names = [];
    try { names = Object.keys(JSON.parse(e.secrets_enc ? ctx.decrypt(e.secrets_enc) : '{}')); } catch { /* ignore */ }
    return { id: e.id, projectId: e.project_id, name: e.name, kind: e.kind, baseUrl: e.base_url, variables: J(e.variables, {}),
      secrets: Object.fromEntries(names.map((n) => [n, '••••••••'])), updatedAt: e.updated_at };
  };
  const envInput = (b, ex) => {
    const vars = obj(b.variables ?? (ex ? J(ex.variables, {}) : {}), 'variables');
    if (Object.keys(vars).length > 100) throw bad('too many variables');
    for (const [k, v] of Object.entries(vars)) { if (!/^[A-Za-z_][A-Za-z0-9_]{0,60}$/.test(k) || typeof v !== 'string' || v.length > 2000) throw bad(`invalid variable ${k}`); }
    let secretsEnc = ex ? ex.secrets_enc : '';
    if (b.secrets !== undefined) {
      const cur = ex && ex.secrets_enc ? JSON.parse(ctx.decrypt(ex.secrets_enc)) : {};
      const inc = obj(b.secrets, 'secrets');
      for (const [k, v] of Object.entries(inc)) {
        if (!/^[A-Za-z_][A-Za-z0-9_]{0,60}$/.test(k)) throw bad(`invalid secret name ${k}`);
        if (v === null) delete cur[k]; else if (v !== '••••••••') cur[k] = str(String(v), 'secret', { max: 2000 });
      }
      secretsEnc = Object.keys(cur).length ? ctx.encrypt(JSON.stringify(cur)) : '';
    }
    return { name: str(b.name ?? ex?.name, 'name', { required: true, max: 60 }), kind: oneOf(b.kind ?? ex?.kind, 'kind', ENVS, 'development'),
      base_url: str(b.baseUrl ?? ex?.base_url, 'baseUrl', { max: 300 }), variables: JSON.stringify(vars), secrets_enc: secretsEnc };
  };

  r.get('/v1/projects/:pid/environments', async (req, res, c) => {
    const a = h.authenticate(req); h.project(a.userId, c.params.pid);
    return db.prepare('SELECT * FROM environments WHERE project_id = ? ORDER BY created_at').all(c.params.pid).map(maskSecrets);
  });
  r.post('/v1/projects/:pid/environments', async (req, res, c) => {
    const a = h.authenticate(req); const p = h.project(a.userId, c.params.pid, 'developer');
    h.limit(p.workspace_id, 'environments', db.prepare('SELECT COUNT(*) n FROM environments WHERE project_id = ?').get(p.id).n);
    const e = envInput(await readJson(req)); const id = uid(), t = now();
    db.prepare('INSERT INTO environments (id,workspace_id,project_id,name,kind,base_url,variables,secrets_enc,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').run(id, p.workspace_id, p.id, e.name, e.kind, e.base_url, e.variables, e.secrets_enc, t, t);
    return [201, maskSecrets(db.prepare('SELECT * FROM environments WHERE id = ?').get(id))];
  });
  const envRow = (userId, id, role) => {
    const e = db.prepare('SELECT * FROM environments WHERE id = ?').get(id);
    if (!e) throw notFound('Environment not found');
    h.member(userId, e.workspace_id, role); return e;
  };
  r.put('/v1/environments/:eid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = envRow(a.userId, c.params.eid, 'developer');
    const e = envInput(await readJson(req), ex);
    db.prepare('UPDATE environments SET name=?,kind=?,base_url=?,variables=?,secrets_enc=?,updated_at=? WHERE id=?').run(e.name, e.kind, e.base_url, e.variables, e.secrets_enc, now(), ex.id);
    return maskSecrets(db.prepare('SELECT * FROM environments WHERE id = ?').get(ex.id));
  });
  r.del('/v1/environments/:eid', async (req, res, c) => {
    const a = h.authenticate(req); const ex = envRow(a.userId, c.params.eid, 'developer');
    db.prepare('DELETE FROM environments WHERE id = ?').run(ex.id); return { ok: true };
  });

  // ---- Sync (offline-first mobile client pushes local projects/APIs; server never overwrites newer data silently) ----
  r.post('/v1/workspaces/:wid/sync', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid, 'developer');
    const b = await readJson(req);
    const projects = arr(b.projects, 'projects', 100);
    const result = { projects: 0, apis: 0, endpoints: 0, conflicts: [], published: [] };
    db.exec('BEGIN');
    try {
      for (const p of projects) {
        if (!p || !UUID_RE.test(p.id || '')) throw bad('project.id must be a UUID');
        const pin = projectInput(p);
        const exP = db.prepare('SELECT * FROM projects WHERE id = ?').get(p.id);
        if (exP && exP.workspace_id !== c.params.wid) throw conflict('Project id belongs to another workspace', 'id_conflict');
        const clientTs = Number.isFinite(p.updatedAt) ? Math.min(p.updatedAt, now() + 300000) : now();
        if (!exP) {
          h.limit(c.params.wid, 'projects', db.prepare('SELECT COUNT(*) n FROM projects WHERE workspace_id = ? AND archived = 0').get(c.params.wid).n);
          db.prepare('INSERT INTO projects (id,workspace_id,name,description,icon,color,environment,archived,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').run(p.id, c.params.wid, pin.name, pin.description, pin.icon, pin.color, pin.environment, p.archived ? 1 : 0, now(), clientTs);
          result.projects++;
        } else if (clientTs >= exP.updated_at) {
          db.prepare('UPDATE projects SET name=?,description=?,icon=?,color=?,environment=?,archived=?,rev=rev+1,updated_at=? WHERE id=?').run(pin.name, pin.description, pin.icon, pin.color, pin.environment, p.archived ? 1 : 0, clientTs, p.id);
          result.projects++;
        } else { result.conflicts.push({ type: 'project', id: p.id, reason: 'newer_on_server' }); continue; }
        for (const api of arr(p.apis, 'apis', 100)) {
          if (!api || !UUID_RE.test(api.id || '')) throw bad('api.id must be a UUID');
          const exA = db.prepare('SELECT * FROM apis WHERE id = ?').get(api.id);
          if (exA && exA.workspace_id !== c.params.wid) throw conflict('API id belongs to another workspace', 'id_conflict');
          const type = oneOf(api.authType, 'authType', ['none', 'apikey', 'bearer', 'basic', 'jwt'], 'none');
          if (!exA) {
            h.limit(c.params.wid, 'apis', db.prepare('SELECT COUNT(*) n FROM apis WHERE workspace_id = ?').get(c.params.wid).n);
            insertApi(db, c.params.wid, p.id, api, api.id);
          } else {
            db.prepare('UPDATE apis SET name=?,description=?,version=?,base_url=?,auth_type=?,auth_config=?,health_url=?,docs_public=?,rev=rev+1,updated_at=? WHERE id=?').run(
              str(api.name, 'name', { required: true, max: 80 }), str(api.description, 'description', { max: 1000 }), str(api.version, 'version', { max: 30, def: '1.0.0' }) || '1.0.0',
              str(api.baseUrl, 'baseUrl', { max: 300 }), type, JSON.stringify(processAuthConfig(type, api.authConfig, J(exA.auth_config, {}))), str(api.healthUrl, 'healthUrl', { max: 300 }), api.docsPublic ? 1 : 0, now(), api.id);
            db.prepare('DELETE FROM endpoints WHERE api_id = ?').run(api.id);
          }
          result.apis++;
          const eps = arr(api.endpoints, 'endpoints', h.plan(c.params.wid).endpointsPerApi);
          const seen = new Set();
          for (const e of eps) {
            const key = `${e.method} ${e.path}`;
            if (seen.has(key)) throw bad(`Duplicate endpoint ${key} in API ${api.name}`);
            seen.add(key); insertEndpoint(db, api.id, e); result.endpoints++;
          }
          if (api.published === true) { db.prepare('UPDATE apis SET published = 1 WHERE id = ?').run(api.id); }
          if (api.published === false) { db.prepare('UPDATE apis SET published = 0 WHERE id = ?').run(api.id); }
          const row = db.prepare('SELECT slug, published FROM apis WHERE id = ?').get(api.id);
          result.published.push({ apiId: api.id, slug: row.slug, published: !!row.published });
        }
      }
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    h.audit(c.params.wid, a.userId, 'sync', 'workspace', c.params.wid);
    return result;
  });
}
