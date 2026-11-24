import { config } from './config.js';

export class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code || 'error'; }
}
export const bad = (m, c) => new HttpError(400, m, c || 'bad_request');
export const unauthorized = (m = 'Authentication required') => new HttpError(401, m, 'unauthorized');
export const forbidden = (m = 'Forbidden') => new HttpError(403, m, 'forbidden');
export const notFound = (m = 'Not found') => new HttpError(404, m, 'not_found');
export const conflict = (m, c) => new HttpError(409, m, c || 'conflict');

export async function readBody(req, limit = config.maxBodyBytes) {
  const chunks = []; let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw new HttpError(413, 'Payload too large', 'payload_too_large');
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}
export async function readJson(req) {
  const buf = await readBody(req);
  if (!buf.length) return {};
  try { const v = JSON.parse(buf.toString('utf8')); return v; } catch { throw bad('Invalid JSON body', 'invalid_json'); }
}

export function send(res, status, body, headers = {}) {
  const isBuf = Buffer.isBuffer(body);
  const payload = body === undefined || body === null ? '' : isBuf || typeof body === 'string' ? body : JSON.stringify(body);
  const h = { 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', ...headers };
  if (!h['Content-Type'] && !h['content-type'] && payload !== '') h['Content-Type'] = typeof body === 'string' || isBuf ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8';
  h['Content-Length'] = Buffer.byteLength(payload);
  res.writeHead(status, h);
  res.end(payload);
  return Buffer.byteLength(payload);
}

/** Tiny router: "/a/:id/b" patterns. */
export class Router {
  constructor() { this.routes = []; }
  add(method, pattern, handler) {
    const keys = [];
    const re = new RegExp('^' + pattern.replace(/\/:([A-Za-z_]+)/g, (_, k) => { keys.push(k); return '/([^/]+)'; }) + '/?$');
    this.routes.push({ method, re, keys, handler });
  }
  get(p, h) { this.add('GET', p, h); } post(p, h) { this.add('POST', p, h); }
  put(p, h) { this.add('PUT', p, h); } del(p, h) { this.add('DELETE', p, h); } patch(p, h) { this.add('PATCH', p, h); }
  match(method, path) {
    let pathMatched = false;
    for (const r of this.routes) {
      const m = r.re.exec(path);
      if (!m) continue;
      pathMatched = true;
      if (r.method !== method) continue;
      const params = {};
      r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
      return { handler: r.handler, params };
    }
    return { pathMatched };
  }
}
