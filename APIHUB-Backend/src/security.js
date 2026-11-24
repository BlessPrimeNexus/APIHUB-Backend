import { randomBytes, randomUUID, scryptSync, timingSafeEqual, createHash, createHmac, createCipheriv, createDecipheriv } from 'node:crypto';
import { config } from './config.js';

export const uid = () => randomUUID();
export const sha256 = (s) => createHash('sha256').update(s).digest('hex');
export const token = (bytes = 32) => randomBytes(bytes).toString('base64url');

// Passwords: scrypt (memory-hard, built into Node). Format: scrypt$N$r$p$salt$hash
const N = 16384, R = 8, P = 1, KEYLEN = 64;
export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N, r: R, p: P, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${hash.toString('base64')}`;
}
export function verifyPassword(password, stored) {
  try {
    const [alg, n, r, p, salt, hash] = stored.split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64');
    const actual = scryptSync(password, Buffer.from(salt, 'base64'), expected.length, { N: +n, r: +r, p: +p, maxmem: 64 * 1024 * 1024 });
    return timingSafeEqual(actual, expected);
  } catch { return false; }
}
export const DUMMY_HASH = hashPassword('dummy-password-for-timing');

export function safeEqual(a, b) {
  const ba = Buffer.from(String(a)), bb = Buffer.from(String(b));
  const ha = createHash('sha256').update(ba).digest(), hb = createHash('sha256').update(bb).digest();
  return timingSafeEqual(ha, hb);
}

// AES-256-GCM encryption for stored environment secrets (key derived from MASTER_KEY).
const key = createHash('sha256').update('apihub-secrets:' + config.masterKey).digest();
export function encrypt(plain) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
export function decrypt(blob) {
  if (!blob) return '';
  const buf = Buffer.from(blob, 'base64');
  const d = createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
}

// API keys for the execution engine: ahk_<prefix>_<secret>. Only SHA-256 of the full key is stored.
export function generateApiKey() {
  const prefix = randomBytes(4).toString('hex');
  const secret = randomBytes(24).toString('base64url');
  const full = `ahk_${prefix}_${secret}`;
  return { full, prefix: `ahk_${prefix}`, hash: sha256(full) };
}

// Minimal HS256 JWT verification (for APIs configured with auth_type=jwt).
export function verifyJwtHS256(jwt, secret) {
  const parts = String(jwt).split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (header.alg !== 'HS256') return null; // reject "none" and other algs
    const sig = createHmac('sha256', secret).update(parts[0] + '.' + parts[1]).digest();
    const given = Buffer.from(parts[2], 'base64url');
    if (sig.length !== given.length || !timingSafeEqual(sig, given)) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp === 'number' && payload.exp < now) return null;
    if (typeof payload.nbf === 'number' && payload.nbf > now) return null;
    return payload;
  } catch { return null; }
}
export function signJwtHS256(payload, secret) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s = createHmac('sha256', secret).update(h + '.' + b).digest('base64url');
  return `${h}.${b}.${s}`;
}
