import { createServer } from 'node:http';
import { config } from './config.js';
import { Router, send, HttpError } from './http.js';
import { makeHelpers } from './util.js';
import { RateLimiter } from './ratelimit.js';
import { encrypt, decrypt } from './security.js';
import { createEngine } from './engine.js';
import { startMonitor } from './monitor.js';
import * as auth from './routes/auth.js';
import * as workspaces from './routes/workspaces.js';
import * as projects from './routes/projects.js';
import * as apis from './routes/apis.js';
import * as monitoring from './routes/monitoring.js';

export function createApp(db) {
  const limiter = new RateLimiter();
  const h = makeHelpers(db);
  const engine = createEngine({ db, limiter });
  const ctx = { db, h, limiter, engine, config, encrypt, decrypt };
  const router = new Router();
  for (const m of [auth, workspaces, projects, apis, monitoring]) m.register(router, ctx);

  router.get('/health', async () => ({ status: 'ok', version: '1.0.0', time: Date.now() }));

  const clientIp = (req) => {
    if (config.trustProxy) { const x = req.headers['x-forwarded-for']; if (x) return String(x).split(',').pop().trim(); }
    return req.socket.remoteAddress || 'unknown';
  };

  const server = createServer(async (req, res) => {
    const ip = clientIp(req);
    try {
      if (config.requireHttps && config.trustProxy && String(req.headers['x-forwarded-proto'] || '').split(',')[0] !== 'https' && !req.url.startsWith('/health')) {
        return void send(res, 426, { error: 'HTTPS required', code: 'https_required' });
      }
      const url = new URL(req.url, 'http://localhost');
      if (await engine.handle(req, res, url, ip)) return;
      if (!limiter.hit('mgmt:' + ip, 600, 60000).allowed) return void send(res, 429, { error: 'Too many requests', code: 'rate_limited' });
      const m = router.match(req.method, url.pathname);
      if (!m.handler) return void send(res, m.pathMatched ? 405 : 404, { error: m.pathMatched ? 'Method not allowed' : 'Not found' });
      const out = await m.handler(req, res, { params: m.params, query: url.searchParams, ip, url });
      if (res.writableEnded || res.headersSent) return;
      if (Array.isArray(out) && out.length === 2 && Number.isInteger(out[0])) send(res, out[0], out[1]); else send(res, 200, out);
    } catch (e) {
      if (res.headersSent) return void res.end();
      if (e instanceof HttpError || (e && e.status && e.code)) return void send(res, e.status, { error: e.message, code: e.code });
      console.error('Unhandled error:', e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e);
      send(res, 500, { error: 'Internal server error', code: 'internal' });
    }
  });
  server.requestTimeout = 30000; server.headersTimeout = 15000; server.keepAliveTimeout = 5000; server.maxHeadersCount = 100;
  const monitor = startMonitor({ db, config });
  const close = () => new Promise((r) => { monitor.stop(); limiter.stop(); server.close(() => r()); server.closeAllConnections?.(); });
  return { server, close, monitor, ctx };
}
