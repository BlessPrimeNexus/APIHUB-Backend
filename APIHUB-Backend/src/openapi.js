import { J } from './util.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function buildOpenApi(api, endpoints, publicBase) {
  const cfg = J(api.auth_config, {});
  const paths = {};
  const schemes = {};
  if (api.auth_type === 'apikey') schemes.apiKey = { type: 'apiKey', in: 'header', name: cfg.header || 'X-API-Key' };
  if (api.auth_type === 'bearer') schemes.bearer = { type: 'http', scheme: 'bearer' };
  if (api.auth_type === 'basic') schemes.basic = { type: 'http', scheme: 'basic' };
  if (api.auth_type === 'jwt') schemes.jwt = { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' };
  const schemeName = Object.keys(schemes)[0];

  for (const e of endpoints) {
    const path = e.path;
    const op = {
      summary: e.name || `${e.method} ${path}`, operationId: `${e.method.toLowerCase()}_${path.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'root'}`,
      parameters: [], responses: {},
    };
    if (e.description) op.description = e.description;
    if (e.group_name) op.tags = [e.group_name];
    const params = J(e.params, []);
    const pathNames = [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
    for (const n of pathNames) {
      const d = params.find((p) => p.in === 'path' && p.name === n);
      op.parameters.push({ name: n, in: 'path', required: true, description: d?.description || undefined, schema: { type: d?.type || 'string' } });
    }
    for (const p of params) if (p.in !== 'path') op.parameters.push({ name: p.name, in: p.in, required: !!p.required, description: p.description || undefined, schema: { type: p.type || 'string' } });
    for (const hd of J(e.headers, [])) op.parameters.push({ name: hd.name, in: 'header', required: !!hd.required, description: hd.description || undefined, schema: { type: 'string' } });
    const bs = J(e.body_schema, {});
    if (['POST', 'PUT', 'PATCH'].includes(e.method) && (bs.properties || bs.required)) {
      const schema = { type: 'object', properties: {}, required: Array.isArray(bs.required) ? bs.required : undefined };
      for (const [k, v] of Object.entries(bs.properties || {})) schema.properties[k] = { type: v?.type || 'string' };
      op.requestBody = { required: !!(bs.required && bs.required.length), content: { 'application/json': { schema } } };
    }
    const mk = (status, body, type) => {
      const r = { description: `HTTP ${status}` };
      if (type === 'json' && body && body.trim()) { try { r.content = { 'application/json': { example: JSON.parse(body) } }; } catch { /* skip */ } }
      else if (type === 'text' && body) r.content = { 'text/plain': { example: body } };
      return r;
    };
    op.responses[String(e.resp_status)] = mk(e.resp_status, e.resp_body, e.resp_type);
    for (const c of J(e.conditions, [])) { if (!op.responses[String(c.status)]) op.responses[String(c.status)] = { ...mk(c.status, c.body, e.resp_type), description: `HTTP ${c.status} (when ${c.when.source}.${c.when.name} ${c.when.op}${c.when.op === 'eq' || c.when.op === 'neq' ? ' ' + c.when.value : ''})` }; }
    if (e.auth_required && schemeName) { op.security = [{ [schemeName]: [] }]; op.responses['401'] = op.responses['401'] || { description: 'Authentication required' }; }
    if (op.requestBody) op.responses['422'] = op.responses['422'] || { description: 'Request body failed validation' };
    if (!op.parameters.length) delete op.parameters;
    paths[path] = paths[path] || {};
    paths[path][e.method.toLowerCase()] = op;
  }
  const servers = [{ url: `${publicBase}/run/${api.slug}`, description: 'APIHUB execution engine' }];
  if (api.base_url) servers.push({ url: api.base_url, description: 'Configured base URL' });
  const doc = { openapi: '3.1.0', info: { title: api.name, version: api.version || '1.0.0' }, servers, paths };
  if (api.description) doc.info.description = api.description;
  if (schemeName) doc.components = { securitySchemes: schemes };
  return doc;
}

export function toYaml(v, indent = 0) {
  const pad = '  '.repeat(indent);
  const scalar = (x) => {
    if (x === null) return 'null';
    if (typeof x === 'number' || typeof x === 'boolean') return String(x);
    const s = String(x);
    if (s === '' || /^[\s]|[\s]$|^[-?:,\[\]{}#&*!|>'"%@`]|: | #|^(true|false|null|yes|no|on|off|~)$|^[\d.+-]+$/i.test(s) || /[\n\r\t]/.test(s)) return JSON.stringify(s);
    return s;
  };
  if (Array.isArray(v)) {
    if (!v.length) return '[]';
    return v.map((i) => (i !== null && typeof i === 'object' && (Array.isArray(i) ? i.length : Object.keys(i).length)
      ? `${pad}- ${toYaml(i, indent + 1).replace(/^\s+/, '')}` : `${pad}- ${typeof i === 'object' && i !== null ? (Array.isArray(i) ? '[]' : '{}') : scalar(i)}`)).join('\n');
  }
  if (v !== null && typeof v === 'object') {
    const ent = Object.entries(v).filter(([, x]) => x !== undefined);
    if (!ent.length) return '{}';
    return ent.map(([k, x]) => {
      const key = /^[A-Za-z0-9_\-./{}$]+$/.test(k) ? k : JSON.stringify(k);
      if (x !== null && typeof x === 'object' && (Array.isArray(x) ? x.length : Object.keys(x).length)) return `${pad}${key}:\n${toYaml(x, indent + 1)}`;
      return `${pad}${key}: ${typeof x === 'object' && x !== null ? (Array.isArray(x) ? '[]' : '{}') : scalar(x)}`;
    }).join('\n');
  }
  return pad + scalar(v);
}

export function toHtml(doc) {
  const rows = [];
  for (const [path, ops] of Object.entries(doc.paths)) {
    for (const [method, op] of Object.entries(ops)) {
      const params = (op.parameters || []).map((p) => `<li><code>${esc(p.name)}</code> <small>(${esc(p.in)}${p.required ? ', required' : ''}, ${esc(p.schema?.type)})</small> ${esc(p.description || '')}</li>`).join('');
      const resp = Object.entries(op.responses).map(([c, r]) => `<li><b>${esc(c)}</b> ${esc(r.description)}${r.content ? `<pre>${esc(JSON.stringify(Object.values(r.content)[0].example, null, 2))}</pre>` : ''}</li>`).join('');
      const body = op.requestBody ? `<h4>Request body</h4><pre>${esc(JSON.stringify(op.requestBody.content['application/json'].schema, null, 2))}</pre>` : '';
      rows.push(`<section class="op" data-s="${esc((method + ' ' + path + ' ' + (op.summary || '') + ' ' + (op.description || '')).toLowerCase())}"><h3><span class="m ${esc(method)}">${esc(method.toUpperCase())}</span> <code>${esc(path)}</code></h3><p>${esc(op.summary || '')}</p>${op.description ? `<p>${esc(op.description)}</p>` : ''}${op.security ? '<p><small>🔒 Authentication required</small></p>' : ''}${params ? `<h4>Parameters</h4><ul>${params}</ul>` : ''}${body}<h4>Responses</h4><ul>${resp}</ul></section>`);
    }
  }
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(doc.info.title)} – API docs</title>
<style>:root{color-scheme:light dark;--bg:#fff;--fg:#14171f;--mut:#6b7280;--bd:#e5e7eb;--ac:#2f5bff}@media(prefers-color-scheme:dark){:root{--bg:#0e1117;--fg:#e6e9f0;--mut:#8b93a5;--bd:#232a37}}
body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:820px;margin:0 auto;padding:16px}code,pre{font-family:ui-monospace,Menlo,monospace}pre{background:rgba(127,127,127,.12);padding:10px;border-radius:8px;overflow:auto;font-size:13px}
.op{border:1px solid var(--bd);border-radius:12px;padding:12px 16px;margin:12px 0}.m{font-size:12px;font-weight:700;padding:2px 8px;border-radius:6px;color:#fff;background:#2f5bff}.POST{background:#12a150}.PUT{background:#e08a00}.PATCH{background:#8a4fff}.DELETE{background:#e5484d}
input{width:100%;box-sizing:border-box;padding:10px;border-radius:10px;border:1px solid var(--bd);background:transparent;color:inherit}small,.mut{color:var(--mut)}</style></head><body>
<h1>${esc(doc.info.title)} <small>v${esc(doc.info.version)}</small></h1><p>${esc(doc.info.description || '')}</p><p class="mut">Server: <code>${esc(doc.servers[0].url)}</code></p>
<input id="q" placeholder="Search endpoints…" oninput="var v=this.value.toLowerCase();document.querySelectorAll('.op').forEach(function(e){e.style.display=e.dataset.s.indexOf(v)>=0?'':'none'})">
${rows.join('') || '<p class="mut">No endpoints.</p>'}</body></html>`;
}
