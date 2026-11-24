import { readJson, bad, unauthorized, HttpError } from '../http.js';
import { str, now, uid } from '../util.js';
import { hashPassword, verifyPassword, DUMMY_HASH, sha256, token } from '../security.js';
import { config } from '../config.js';

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;

function checkPassword(pw) {
  if (typeof pw !== 'string' || pw.length < 10) throw bad('Password must be at least 10 characters');
  if (pw.length > 200) throw bad('Password too long');
  if (!/[a-zA-Z]/.test(pw) || !/[0-9]/.test(pw)) throw bad('Password must contain letters and digits');
}

export function register(r, ctx) {
  const { db, h, limiter } = ctx;

  function issueSession(userId, device) {
    const access = token(32), refresh = token(48);
    const t = now();
    db.prepare('INSERT INTO sessions (id,user_id,access_hash,refresh_hash,access_expires_at,refresh_expires_at,device,created_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(uid(), userId, sha256(access), sha256(refresh), t + config.accessTtlMin * 60000, t + config.refreshTtlDays * 86400000, device, t);
    return { accessToken: access, refreshToken: refresh, expiresIn: config.accessTtlMin * 60 };
  }

  r.post('/v1/auth/register', async (req, res, c) => {
    if (!config.allowRegistration) throw new HttpError(403, 'Registration is disabled on this server', 'registration_disabled');
    const lim = limiter.hit('reg:' + c.ip, config.registerLimitPerHour, 3600000);
    if (!lim.allowed) throw new HttpError(429, 'Too many registrations', 'rate_limited');
    const b = await readJson(req);
    const email = str(b.email, 'email', { required: true, max: 254 }).toLowerCase();
    if (!EMAIL_RE.test(email)) throw bad('Invalid email');
    checkPassword(b.password);
    const name = str(b.name, 'name', { max: 80 });
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) throw new HttpError(409, 'Email already registered', 'email_taken');
    const userId = uid(), wid = uid(), t = now();
    db.exec('BEGIN');
    try {
      db.prepare('INSERT INTO users (id,email,name,password_hash,created_at) VALUES (?,?,?,?,?)').run(userId, email, name, hashPassword(b.password), t);
      db.prepare('INSERT INTO workspaces (id,name,plan,owner_id,created_at) VALUES (?,?,?,?,?)').run(wid, 'Personal', 'free', userId, t);
      db.prepare('INSERT INTO workspace_members (workspace_id,user_id,role,created_at) VALUES (?,?,?,?)').run(wid, userId, 'owner', t);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    const s = issueSession(userId, str(b.device, 'device', { max: 80 }));
    return [201, { user: { id: userId, email, name }, workspaceId: wid, ...s }];
  });

  r.post('/v1/auth/login', async (req, res, c) => {
    const b = await readJson(req);
    const email = str(b.email, 'email', { required: true, max: 254 }).toLowerCase();
    if (typeof b.password !== 'string' || b.password.length > 200) throw bad('Invalid credentials');
    const lim = limiter.hit(`login:${c.ip}:${email}`, 10, 900000);
    if (!lim.allowed) throw new HttpError(429, 'Too many attempts, try again later', 'rate_limited');
    const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (u && u.locked_until > now()) throw new HttpError(429, 'Account temporarily locked', 'locked');
    const ok = verifyPassword(b.password, u ? u.password_hash : DUMMY_HASH); // constant-ish time even for unknown emails
    if (!u || !ok) {
      if (u) {
        const f = u.failed_logins + 1;
        db.prepare('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?').run(f >= 10 ? 0 : f, f >= 10 ? now() + 900000 : 0, u.id);
      }
      throw unauthorized('Invalid email or password');
    }
    db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?').run(u.id);
    const s = issueSession(u.id, str(b.device, 'device', { max: 80 }));
    return { user: { id: u.id, email: u.email, name: u.name }, ...s };
  });

  r.post('/v1/auth/refresh', async (req) => {
    const b = await readJson(req);
    if (typeof b.refreshToken !== 'string') throw bad('refreshToken required');
    const s = db.prepare('SELECT * FROM sessions WHERE refresh_hash = ?').get(sha256(b.refreshToken));
    if (!s || s.revoked || s.refresh_expires_at < now()) throw unauthorized('Invalid refresh token');
    db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(s.id); // rotation: old refresh token is single-use
    return issueSession(s.user_id, s.device);
  });

  r.post('/v1/auth/logout', async (req, res, c) => {
    const a = h.authenticate(req);
    db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(a.sessionId);
    return { ok: true };
  });

  r.post('/v1/auth/logout-all', async (req) => {
    const a = h.authenticate(req);
    db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?').run(a.userId);
    return { ok: true };
  });

  r.get('/v1/auth/me', async (req) => {
    const a = h.authenticate(req);
    const ws = db.prepare('SELECT w.id, w.name, w.plan, m.role FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id WHERE m.user_id = ? ORDER BY w.created_at').all(a.userId);
    return { user: { id: a.userId, email: a.email, name: a.name }, workspaces: ws.map((w) => ({ ...w })) };
  });

  r.post('/v1/auth/change-password', async (req) => {
    const a = h.authenticate(req);
    const b = await readJson(req);
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(a.userId);
    if (!verifyPassword(String(b.currentPassword ?? ''), u.password_hash)) throw unauthorized('Current password is incorrect');
    checkPassword(b.newPassword);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(b.newPassword), a.userId);
    db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?').run(a.userId, a.sessionId);
    return { ok: true };
  });
}
