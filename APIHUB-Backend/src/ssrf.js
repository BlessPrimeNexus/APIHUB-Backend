import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { config } from './config.js';

function ipv4ToInt(ip) { return ip.split('.').reduce((a, o) => (a << 8) + Number(o), 0) >>> 0; }
const V4_BLOCKS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], // incl. cloud metadata 169.254.169.254
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([ip, bits]) => ({ base: ipv4ToInt(ip), mask: bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0 }));

export function isPrivateIp(ip) {
  const v = isIP(ip);
  if (v === 4) { const n = ipv4ToInt(ip); return V4_BLOCKS.some((b) => ((n & b.mask) >>> 0) === b.base); }
  if (v === 6) {
    const l = ip.toLowerCase();
    if (l === '::' || l === '::1') return true;
    if (l.startsWith('::ffff:')) { const t = l.slice(7); return isIP(t) === 4 ? isPrivateIp(t) : true; }
    return l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb') || l.startsWith('ff');
  }
  return true; // unknown format: block
}

/** Validates an outbound target URL. Returns { ok, url?, address?, reason? }. Resolves DNS and blocks private/metadata ranges. */
export async function checkOutboundUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { return { ok: false, reason: 'Invalid URL' }; }
  if (!['http:', 'https:'].includes(u.protocol)) return { ok: false, reason: 'Only http/https allowed' };
  if (u.username || u.password) return { ok: false, reason: 'Credentials in URL not allowed' };
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (config.allowPrivateTargets) return { ok: true, url: u };
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host === 'metadata.google.internal') return { ok: false, reason: 'Internal host blocked' };
  let addrs;
  try { addrs = isIP(host) ? [{ address: host }] : await lookup(host, { all: true }); } catch { return { ok: false, reason: 'DNS resolution failed' }; }
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) return { ok: false, reason: 'Target resolves to a private or reserved address' };
  return { ok: true, url: u, address: addrs[0].address };
}

import http from 'node:http';
import https from 'node:https';

/** Safe outbound probe: validates target, pins the resolved IP (anti DNS-rebinding), no redirects, short timeout, tiny read cap. */
export async function probe(rawUrl, { timeoutMs = 5000, method = 'GET' } = {}) {
  const chk = await checkOutboundUrl(rawUrl);
  if (!chk.ok) return { ok: false, status: 0, ms: 0, error: chk.reason };
  const u = chk.url; const lib = u.protocol === 'https:' ? https : http;
  const started = Date.now();
  return new Promise((resolve) => {
    const finish = (o) => resolve({ ms: Date.now() - started, ...o });
    const opts = { method, timeout: timeoutMs, headers: { 'User-Agent': 'APIHUB-Monitor/1.0' } };
    if (chk.address) opts.lookup = (_h, _o, cb) => cb(null, chk.address, isIP(chk.address));
    const req = lib.request(u, opts, (res) => {
      let n = 0;
      res.on('data', (c) => { n += c.length; if (n > 65536) req.destroy(); });
      res.on('end', () => finish({ ok: res.statusCode >= 200 && res.statusCode < 400, status: res.statusCode, error: '' }));
      res.on('error', () => finish({ ok: false, status: res.statusCode || 0, error: 'response error' }));
      res.on('close', () => finish({ ok: res.statusCode >= 200 && res.statusCode < 400, status: res.statusCode || 0, error: '' }));
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, status: 0, error: 'timeout' }); });
    req.on('error', (e) => finish({ ok: false, status: 0, error: e.code || 'network error' }));
    req.end();
  });
}
