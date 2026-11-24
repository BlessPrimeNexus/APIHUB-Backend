import { readJson, bad, notFound, send, HttpError } from '../http.js';
import { str, oneOf, int, arr, obj, now, uid, J, serializeEndpoint } from '../util.js';
import { buildOpenApi, toYaml, toHtml } from '../openapi.js';
import { probe } from '../ssrf.js';

const RANGES = { today: null, '7d': 7, '30d': 30, '90d': 90 };

function parseRange(q) {
  let to = Number(q.get('to')) || Date.now(); let from = Number(q.get('from'));
  const r = q.get('range');
  if (r === 'today') { const d = new Date(); d.setUTCHours(0, 0, 0, 0); from = d.getTime(); }
  else if (RANGES[r]) from = to - RANGES[r] * 86400000;
  if (!Number.isFinite(from) || !from) from = to - 7 * 86400000;
  if (from >= to) throw bad('Invalid time range');
  if (to - from > 400 * 86400000) throw bad('Time range too large');
  return { from, to };
}

export function evalAssertions(expect, res) {
  const results = [];
  const add = (name, ok, detail) => results.push({ name, ok, detail: ok ? '' : detail });
  const e = expect || {};
  if (e.status !== undefined) add(`status = ${e.status}`, res.status === e.status, `got ${res.status}`);
  if (e.maxMs !== undefined) add(`time < ${e.maxMs}ms`, res.ms <= e.maxMs, `took ${res.ms}ms`);
  let json; let parsed = false;
  const getJson = () => { if (!parsed) { parsed = true; try { json = JSON.parse(res.body); } catch { json = undefined; } } return json; };
  const at = (p) => { let c = getJson(); for (const k of String(p).split('.')) { if (c === null || typeof c !== 'object' || !(k in c)) return { found: false }; c = c[k]; } return { found: true, value: c }; };
  for (const p of e.jsonHas || []) add(`json has ${p}`, at(p).found, 'field missing');
  for (const [p, v] of Object.entries(e.jsonEquals || {})) { const r = at(p); add(`${p} = ${JSON.stringify(v)}`, r.found && JSON.stringify(r.value) === JSON.stringify(v), r.found ? `got ${JSON.stringify(r.value)}` : 'field missing'); }
  for (const [p, t] of Object.entries(e.jsonType || {})) { const r = at(p); const ok = r.found && (t === 'array' ? Array.isArray(r.value) : t === 'integer' ? Number.isInteger(r.value) : t === 'null' ? r.value === null : typeof r.value === t); add(`${p} is ${t}`, ok, r.found ? 'wrong type' : 'field missing'); }
  for (const [n, v] of Object.entries(e.headers || {})) { const g = res.headers[n.toLowerCase()]; add(`header ${n}`, g !== undefined && (v === '' || String(g) === String(v)), g === undefined ? 'header missing' : `got ${g}`); }
  return results;
}

export function register(r, ctx) {
  const { db, h, engine, config } = ctx;
  const apiWs = (userId, aid, role) => h.api(userId, aid, role);

  // ---- Docs ----
  const publicBase = (req) => {
    const proto = ctx.config.trustProxy && req.headers['x-forwarded-proto'] ? String(req.headers['x-forwarded-proto']).split(',')[0] : 'http';
    return `${proto}://${req.headers.host || 'localhost'}`;
  };
  const docResponse = (req, res, api, format) => {
    const eps = db.prepare('SELECT * FROM endpoints WHERE api_id = ? ORDER BY sort, created_at').all(api.id);
    const doc = buildOpenApi(api, eps, publicBase(req));
    if (format === 'yaml') return send(res, 200, toYaml(doc) + '\n', { 'Content-Type': 'application/yaml; charset=utf-8' }), null;
    if (format === 'html') return send(res, 200, toHtml(doc), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'" }), null;
    return doc;
  };
  r.get('/v1/apis/:aid/openapi', async (req, res, c) => {
    const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid);
    const out = docResponse(req, res, api, c.query.get('format') || 'json');
    return out === null ? { __sent: true } : out;
  });
  r.get('/public/docs/:slug', async (req, res, c) => {
    const api = db.prepare('SELECT * FROM apis WHERE slug = ?').get(c.params.slug);
    if (!api || !api.docs_public || !api.published) throw notFound('Documentation not found');
    const out = docResponse(req, res, api, c.query.get('format') || 'html');
    return out === null ? { __sent: true } : out;
  });

  // ---- Stats ----
  r.get('/v1/workspaces/:wid/stats', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid);
    const { from, to } = parseRange(c.query);
    const apiId = c.query.get('apiId');
    const wid = c.params.wid;
    const where = 'workspace_id = ? AND ts >= ? AND ts <= ?' + (apiId ? ' AND api_id = ?' : '');
    const args = apiId ? [wid, from, to, apiId] : [wid, from, to];
    const t = db.prepare(`SELECT COUNT(*) n, COALESCE(SUM(status < 400),0) ok, COALESCE(SUM(status >= 400 AND status < 500),0) c4, COALESCE(SUM(status >= 500),0) c5, AVG(duration_ms) avg FROM request_logs WHERE ${where}`).get(...args);
    const bucket = to - from <= 2 * 86400000 ? 3600000 : 86400000;
    const series = db.prepare(`SELECT (ts / ${bucket}) * ${bucket} AS t, COUNT(*) count, SUM(status >= 400) errors, AVG(duration_ms) avgMs FROM request_logs WHERE ${where} GROUP BY 1 ORDER BY 1`).all(...args).map((x) => ({ ...x, avgMs: Math.round(x.avgMs) }));
    const top = db.prepare(`SELECT l.method, l.path, l.api_id AS apiId, a.name AS apiName, COUNT(*) count FROM request_logs l LEFT JOIN apis a ON a.id = l.api_id WHERE ${where.replace(/workspace_id|ts|api_id/g, (m) => 'l.' + m)} GROUP BY l.api_id, l.method, l.path ORDER BY count DESC LIMIT 5`).all(...args).map((x) => ({ ...x }));
    const codes = db.prepare(`SELECT status, COUNT(*) count FROM request_logs WHERE ${where} GROUP BY status ORDER BY count DESC LIMIT 10`).all(...args).map((x) => ({ ...x }));
    const recent = db.prepare(`SELECT id, ts, method, path, status, duration_ms AS durationMs, size, api_id AS apiId FROM request_logs WHERE ${where} ORDER BY id DESC LIMIT 10`).all(...args).map((x) => ({ ...x }));
    const apis = db.prepare('SELECT id, name, slug, published, health_url FROM apis WHERE workspace_id = ?').all(wid);
    const services = apis.map((x) => {
      const hc = db.prepare('SELECT ts, ok, status, duration_ms FROM health_checks WHERE api_id = ? ORDER BY id DESC LIMIT 1').get(x.id);
      return { apiId: x.id, name: x.name, slug: x.slug, published: !!x.published, lastCheck: hc ? { ts: hc.ts, ok: !!hc.ok, status: hc.status, ms: hc.duration_ms } : null, monitored: !!x.health_url };
    });
    const counts = { projects: db.prepare('SELECT COUNT(*) n FROM projects WHERE workspace_id = ? AND archived = 0').get(wid).n, apis: apis.length,
      endpoints: db.prepare('SELECT COUNT(*) n FROM endpoints e JOIN apis a ON a.id = e.api_id WHERE a.workspace_id = ?').get(wid).n };
    return { range: { from, to, bucketMs: bucket }, counts, requests: t.n, successRate: t.n ? (t.ok / t.n) * 100 : null, errorRate: t.n ? ((t.c4 + t.c5) / t.n) * 100 : null,
      clientErrors: t.c4, serverErrors: t.c5, avgResponseMs: t.n ? Math.round(t.avg) : null, series, topEndpoints: top, statusCodes: codes, recent, services };
  });

  // ---- Logs ----
  const logQuery = (c) => {
    const { from, to } = c.query.get('from') || c.query.get('range') ? parseRange(c.query) : { from: 0, to: Date.now() + 1000 };
    let where = 'workspace_id = ? AND ts >= ? AND ts <= ?'; const args = [c.params.wid, from, to];
    const st = c.query.get('status'); if (st) { if (/^[1-5]xx$/.test(st)) { where += ' AND status >= ? AND status < ?'; args.push(+st[0] * 100, +st[0] * 100 + 100); } else if (/^\d{3}$/.test(st)) { where += ' AND status = ?'; args.push(+st); } }
    const m = c.query.get('method'); if (m && /^[A-Z]+$/.test(m)) { where += ' AND method = ?'; args.push(m); }
    const q = c.query.get('q'); if (q) { where += " AND path LIKE ? ESCAPE '\\'"; args.push('%' + q.replace(/[\\%_]/g, '\\$&').slice(0, 100) + '%'); }
    const api = c.query.get('apiId'); if (api) { where += ' AND api_id = ?'; args.push(api); }
    return { where, args };
  };
  r.get('/v1/workspaces/:wid/logs', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid);
    const { where, args } = logQuery(c);
    const limit = Math.min(Math.max(Number(c.query.get('limit')) || 50, 1), 200); const offset = Math.max(Number(c.query.get('offset')) || 0, 0);
    const total = db.prepare(`SELECT COUNT(*) n FROM request_logs WHERE ${where}`).get(...args).n;
    const items = db.prepare(`SELECT id, ts, method, path, status, duration_ms AS durationMs, size, api_id AS apiId, endpoint_id AS endpointId, error FROM request_logs WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).all(...args, limit, offset).map((x) => ({ ...x }));
    return { total, limit, offset, items };
  });
  r.get('/v1/workspaces/:wid/logs/export', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid, 'developer');
    const { where, args } = logQuery(c);
    const rows = db.prepare(`SELECT ts, method, path, status, duration_ms, size FROM request_logs WHERE ${where} ORDER BY id DESC LIMIT 10000`).all(...args);
    const cell = (v) => { let s = String(v); if (/^[=+\-@]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const csv = ['timestamp,method,path,status,duration_ms,size', ...rows.map((x) => [new Date(x.ts).toISOString(), x.method, x.path, x.status, x.duration_ms, x.size].map(cell).join(','))].join('\n');
    send(res, 200, csv, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="apihub-logs.csv"' });
    return { __sent: true };
  });
  r.del('/v1/workspaces/:wid/logs', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid, 'admin');
    const n = db.prepare('DELETE FROM request_logs WHERE workspace_id = ?').run(c.params.wid).changes;
    h.audit(c.params.wid, a.userId, 'clear_logs', 'logs', null);
    return { deleted: Number(n) };
  });

  // ---- Alerts ----
  const serializeAlert = (x) => ({ id: x.id, apiId: x.api_id, kind: x.kind, threshold: x.threshold, windowMin: x.window_min, enabled: !!x.enabled, lastTriggeredAt: x.last_triggered_at, createdAt: x.created_at });
  r.get('/v1/workspaces/:wid/alerts', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid);
    return db.prepare('SELECT * FROM alerts WHERE workspace_id = ? ORDER BY created_at DESC').all(c.params.wid).map(serializeAlert);
  });
  r.post('/v1/workspaces/:wid/alerts', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid, 'developer');
    const b = await readJson(req);
    const api = db.prepare('SELECT workspace_id FROM apis WHERE id = ?').get(b.apiId);
    if (!api || api.workspace_id !== c.params.wid) throw notFound('API not found');
    const kind = oneOf(b.kind, 'kind', ['error_rate', 'down', 'latency', 'request_count']);
    const threshold = typeof b.threshold === 'number' && b.threshold >= 0 ? b.threshold : kind === 'down' ? 1 : (() => { throw bad('threshold must be a non-negative number'); })();
    const id = uid();
    db.prepare('INSERT INTO alerts (id,workspace_id,api_id,kind,threshold,window_min,created_at) VALUES (?,?,?,?,?,?,?)').run(id, c.params.wid, b.apiId, kind, threshold, int(b.windowMin, 'windowMin', { min: 1, max: 1440, def: 15 }), now());
    return [201, serializeAlert(db.prepare('SELECT * FROM alerts WHERE id = ?').get(id))];
  });
  const alertRow = (userId, id, role) => { const x = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id); if (!x) throw notFound('Alert not found'); h.member(userId, x.workspace_id, role); return x; };
  r.put('/v1/alerts/:id', async (req, res, c) => {
    const a = h.authenticate(req); const ex = alertRow(a.userId, c.params.id, 'developer'); const b = await readJson(req);
    db.prepare('UPDATE alerts SET threshold=?, window_min=?, enabled=? WHERE id=?').run(typeof b.threshold === 'number' && b.threshold >= 0 ? b.threshold : ex.threshold, int(b.windowMin, 'windowMin', { min: 1, max: 1440, def: ex.window_min }), (b.enabled ?? !!ex.enabled) ? 1 : 0, ex.id);
    return serializeAlert(db.prepare('SELECT * FROM alerts WHERE id = ?').get(ex.id));
  });
  r.del('/v1/alerts/:id', async (req, res, c) => { const a = h.authenticate(req); const ex = alertRow(a.userId, c.params.id, 'developer'); db.prepare('DELETE FROM alerts WHERE id = ?').run(ex.id); return { ok: true }; });
  r.get('/v1/workspaces/:wid/alert-events', async (req, res, c) => {
    const a = h.authenticate(req); h.member(a.userId, c.params.wid);
    return db.prepare('SELECT e.id, e.alert_id AS alertId, e.ts, e.message, al.kind, al.api_id AS apiId FROM alert_events e JOIN alerts al ON al.id = e.alert_id WHERE al.workspace_id = ? ORDER BY e.id DESC LIMIT 100').all(c.params.wid).map((x) => ({ ...x }));
  });

  // ---- Health ----
  r.get('/v1/apis/:aid/health', async (req, res, c) => {
    const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid);
    const since = Date.now() - 86400000;
    const s = db.prepare('SELECT COUNT(*) n, COALESCE(SUM(ok),0) ok, AVG(duration_ms) avg FROM health_checks WHERE api_id = ? AND ts >= ?').get(api.id, since);
    const recent = db.prepare('SELECT ts, ok, status, duration_ms AS ms, error FROM health_checks WHERE api_id = ? ORDER BY id DESC LIMIT 30').all(api.id).map((x) => ({ ...x, ok: !!x.ok }));
    return { monitored: !!api.health_url, checks24h: s.n, uptime24h: s.n ? (s.ok / s.n) * 100 : null, avgMs: s.n ? Math.round(s.avg) : null, recent };
  });
  r.post('/v1/apis/:aid/check', async (req, res, c) => {
    const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid, 'developer');
    if (!api.health_url) throw bad('No health URL configured for this API', 'no_health_url');
    const p = await probe(api.health_url);
    db.prepare('INSERT INTO health_checks (api_id,ts,ok,status,duration_ms,error) VALUES (?,?,?,?,?,?)').run(api.id, now(), p.ok ? 1 : 0, p.status, p.ms, p.error || '');
    return { ok: p.ok, status: p.status, ms: p.ms, error: p.error || '' };
  });

  // ---- Automated tests ----
  const serializeSuite = (x) => ({ id: x.id, apiId: x.api_id, name: x.name, cases: J(x.cases, []), updatedAt: x.updated_at });
  const parseCases = (v) => arr(v, 'cases', 100).map((cs, i) => {
    if (!cs || typeof cs !== 'object') throw bad(`cases[${i}] invalid`);
    return { name: str(cs.name, 'case.name', { required: true, max: 120 }), enabled: cs.enabled !== false, method: oneOf(cs.method, 'case.method', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], 'GET'),
      path: str(cs.path, 'case.path', { required: true, max: 300 }), headers: obj(cs.headers, 'case.headers'), body: typeof cs.body === 'string' ? cs.body.slice(0, 100000) : cs.body === undefined ? '' : JSON.stringify(cs.body),
      useAuth: !!cs.useAuth, expect: obj(cs.expect, 'case.expect') };
  });
  const needTests = (wid) => { if (!h.plan(wid).automatedTests) throw new HttpError(402, 'Automated tests require the Pro plan or higher', 'plan_limit'); };
  r.get('/v1/apis/:aid/test-suites', async (req, res, c) => { const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid); return db.prepare('SELECT * FROM test_suites WHERE api_id = ? ORDER BY created_at').all(api.id).map(serializeSuite); });
  r.post('/v1/apis/:aid/test-suites', async (req, res, c) => {
    const a = h.authenticate(req); const api = h.api(a.userId, c.params.aid, 'developer'); needTests(api.workspace_id);
    const b = await readJson(req); const id = uid(), t = now();
    db.prepare('INSERT INTO test_suites (id,workspace_id,api_id,name,cases,created_at,updated_at) VALUES (?,?,?,?,?,?,?)').run(id, api.workspace_id, api.id, str(b.name, 'name', { required: true, max: 80 }), JSON.stringify(parseCases(b.cases)), t, t);
    return [201, serializeSuite(db.prepare('SELECT * FROM test_suites WHERE id = ?').get(id))];
  });
  const suiteRow = (userId, id, role) => { const x = db.prepare('SELECT * FROM test_suites WHERE id = ?').get(id); if (!x) throw notFound('Suite not found'); h.member(userId, x.workspace_id, role); return x; };
  r.put('/v1/test-suites/:id', async (req, res, c) => {
    const a = h.authenticate(req); const ex = suiteRow(a.userId, c.params.id, 'developer'); const b = await readJson(req);
    db.prepare('UPDATE test_suites SET name=?, cases=?, updated_at=? WHERE id=?').run(str(b.name ?? ex.name, 'name', { required: true, max: 80 }), b.cases !== undefined ? JSON.stringify(parseCases(b.cases)) : ex.cases, now(), ex.id);
    return serializeSuite(db.prepare('SELECT * FROM test_suites WHERE id = ?').get(ex.id));
  });
  r.del('/v1/test-suites/:id', async (req, res, c) => { const a = h.authenticate(req); const ex = suiteRow(a.userId, c.params.id, 'developer'); db.prepare('DELETE FROM test_suites WHERE id = ?').run(ex.id); return { ok: true }; });
  r.post('/v1/test-suites/:id/run', async (req, res, c) => {
    const a = h.authenticate(req); const suite = suiteRow(a.userId, c.params.id, 'developer'); needTests(suite.workspace_id);
    const api = db.prepare('SELECT * FROM apis WHERE id = ?').get(suite.api_id);
    const details = []; let passed = 0, failed = 0, skipped = 0, errored = 0;
    for (const cs of J(suite.cases, [])) {
      if (!cs.enabled) { skipped++; details.push({ name: cs.name, result: 'skipped', checks: [] }); continue; }
      if (!api.published) { errored++; details.push({ name: cs.name, result: 'error', error: 'API is not published', checks: [] }); continue; }
      try {
        const u = new URL('http://x' + (cs.path.startsWith('/') ? cs.path : '/' + cs.path));
        const hdrs = {}; for (const [k, v] of Object.entries(cs.headers || {})) hdrs[k.toLowerCase()] = String(v);
        const t0 = Date.now();
        const rr = await engine.execute({ api, method: cs.method, path: u.pathname.length > 1 ? u.pathname.replace(/\/+$/, '') : '/', query: u.searchParams, headers: hdrs,
          bodyBuf: Buffer.from(cs.body || ''), ip: 'test', skipAuth: !cs.useAuth, skipLimits: true });
        const out = { status: rr.status, body: rr.body, ms: Date.now() - t0, headers: Object.fromEntries(Object.entries(rr.headers).map(([k, v]) => [k.toLowerCase(), v])) };
        const checks = evalAssertions(cs.expect, out);
        const ok = checks.every((x) => x.ok);
        ok ? passed++ : failed++;
        details.push({ name: cs.name, result: ok ? 'passed' : 'failed', status: out.status, ms: out.ms, checks });
      } catch (e) { errored++; details.push({ name: cs.name, result: 'error', error: String(e.message).slice(0, 200), checks: [] }); }
    }
    db.prepare('INSERT INTO test_runs (suite_id,ts,passed,failed,skipped,errored,details) VALUES (?,?,?,?,?,?,?)').run(suite.id, now(), passed, failed, skipped, errored, JSON.stringify(details));
    return { passed, failed, skipped, errored, details };
  });
  r.get('/v1/test-suites/:id/runs', async (req, res, c) => {
    const a = h.authenticate(req); const s = suiteRow(a.userId, c.params.id);
    return db.prepare('SELECT id, ts, passed, failed, skipped, errored FROM test_runs WHERE suite_id = ? ORDER BY id DESC LIMIT 30').all(s.id).map((x) => ({ ...x }));
  });
}
