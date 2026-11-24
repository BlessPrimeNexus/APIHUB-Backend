import { readJson, bad, forbidden, notFound, HttpError } from '../http.js';
import { str, oneOf, int, now, uid, ROLE_RANK } from '../util.js';
import { sha256, token } from '../security.js';
import { PLANS } from '../config.js';

export function register(r, ctx) {
  const { db, h } = ctx;

  r.get('/v1/workspaces', async (req) => {
    const a = h.authenticate(req);
    return db.prepare('SELECT w.id, w.name, w.plan, w.created_at AS createdAt, m.role FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id WHERE m.user_id = ?').all(a.userId).map((x) => ({ ...x }));
  });

  r.post('/v1/workspaces', async (req) => {
    const a = h.authenticate(req);
    const b = await readJson(req);
    const name = str(b.name, 'name', { required: true, max: 80 });
    const id = uid(), t = now();
    db.exec('BEGIN');
    try {
      db.prepare('INSERT INTO workspaces (id,name,plan,owner_id,created_at) VALUES (?,?,?,?,?)').run(id, name, 'free', a.userId, t);
      db.prepare('INSERT INTO workspace_members (workspace_id,user_id,role,created_at) VALUES (?,?,?,?)').run(id, a.userId, 'owner', t);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    h.audit(id, a.userId, 'create', 'workspace', id);
    return [201, { id, name, plan: 'free', role: 'owner' }];
  });

  r.get('/v1/workspaces/:wid', async (req, res, c) => {
    const a = h.authenticate(req);
    const role = h.member(a.userId, c.params.wid);
    const w = h.workspace(c.params.wid);
    const wid = w.id;
    const monthStart = new Date(); monthStart.setUTCDate(1); monthStart.setUTCHours(0, 0, 0, 0);
    const usage = {
      projects: db.prepare('SELECT COUNT(*) n FROM projects WHERE workspace_id = ? AND archived = 0').get(wid).n,
      apis: db.prepare('SELECT COUNT(*) n FROM apis WHERE workspace_id = ?').get(wid).n,
      members: db.prepare('SELECT COUNT(*) n FROM workspace_members WHERE workspace_id = ?').get(wid).n,
      requestsThisMonth: db.prepare('SELECT COUNT(*) n FROM request_logs WHERE workspace_id = ? AND ts >= ?').get(wid, monthStart.getTime()).n,
    };
    return { id: wid, name: w.name, plan: w.plan, role, limits: PLANS[w.plan] || PLANS.free, usage,
      settings: { logRetentionDays: w.log_retention_days, maskSensitive: !!w.mask_sensitive }, paymentConfigured: false };
  });

  r.put('/v1/workspaces/:wid', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid, 'admin');
    const b = await readJson(req);
    const w = h.workspace(c.params.wid);
    const plan = PLANS[w.plan];
    const name = b.name !== undefined ? str(b.name, 'name', { required: true, max: 80 }) : w.name;
    const ret = b.logRetentionDays !== undefined ? int(b.logRetentionDays, 'logRetentionDays', { min: 1, max: plan.logRetentionDays }) : w.log_retention_days;
    const mask = b.maskSensitive !== undefined ? (b.maskSensitive ? 1 : 0) : w.mask_sensitive;
    db.prepare('UPDATE workspaces SET name=?, log_retention_days=?, mask_sensitive=? WHERE id=?').run(name, ret, mask, w.id);
    h.audit(w.id, a.userId, 'update', 'workspace', w.id);
    return { ok: true };
  });

  // Plan changes: no payment provider is integrated. Only allowed when the server operator explicitly enables self-service (self-hosted installs).
  r.post('/v1/workspaces/:wid/plan', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid, 'owner');
    const b = await readJson(req);
    const plan = oneOf(b.plan, 'plan', Object.keys(PLANS));
    if (process.env.ALLOW_SELF_PLAN_CHANGE !== '1') throw new HttpError(402, 'No payment provider is configured on this server. Plan changes are disabled.', 'payment_not_configured');
    db.prepare('UPDATE workspaces SET plan = ? WHERE id = ?').run(plan, c.params.wid);
    h.audit(c.params.wid, a.userId, 'plan_change', 'workspace', c.params.wid);
    return { ok: true, plan };
  });

  r.get('/v1/workspaces/:wid/members', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid);
    return db.prepare('SELECT u.id, u.email, u.name, m.role FROM workspace_members m JOIN users u ON u.id = m.user_id WHERE m.workspace_id = ?').all(c.params.wid).map((x) => ({ ...x }));
  });

  r.post('/v1/workspaces/:wid/invitations', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid, 'admin');
    const b = await readJson(req);
    const email = str(b.email, 'email', { required: true, max: 254 }).toLowerCase();
    const role = oneOf(b.role, 'role', ['admin', 'developer', 'viewer'], 'developer');
    const members = db.prepare('SELECT COUNT(*) n FROM workspace_members WHERE workspace_id = ?').get(c.params.wid).n;
    h.limit(c.params.wid, 'members', members);
    const tok = token(24);
    db.prepare('INSERT INTO invitations (id,workspace_id,email,role,token_hash,expires_at,created_at) VALUES (?,?,?,?,?,?,?)').run(uid(), c.params.wid, email, role, sha256(tok), now() + 7 * 86400000, now());
    h.audit(c.params.wid, a.userId, 'invite', 'member', email);
    // The token must be delivered to the invitee out-of-band (no email service is bundled).
    return [201, { email, role, inviteToken: tok, expiresInDays: 7 }];
  });

  r.post('/v1/invitations/accept', async (req) => {
    const a = h.authenticate(req);
    const b = await readJson(req);
    const inv = db.prepare('SELECT * FROM invitations WHERE token_hash = ?').get(sha256(String(b.inviteToken ?? '')));
    if (!inv || inv.accepted || inv.expires_at < now()) throw bad('Invalid or expired invitation', 'invalid_invitation');
    if (inv.email !== a.email.toLowerCase()) throw forbidden('This invitation was issued for another email address');
    db.prepare('INSERT OR REPLACE INTO workspace_members (workspace_id,user_id,role,created_at) VALUES (?,?,?,?)').run(inv.workspace_id, a.userId, inv.role, now());
    db.prepare('UPDATE invitations SET accepted = 1 WHERE id = ?').run(inv.id);
    h.audit(inv.workspace_id, a.userId, 'join', 'member', a.userId);
    return { ok: true, workspaceId: inv.workspace_id, role: inv.role };
  });

  r.put('/v1/workspaces/:wid/members/:uid', async (req, res, c) => {
    const a = h.authenticate(req);
    const myRole = h.member(a.userId, c.params.wid, 'admin');
    const b = await readJson(req);
    const role = oneOf(b.role, 'role', ['admin', 'developer', 'viewer']);
    const target = db.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?').get(c.params.wid, c.params.uid);
    if (!target) throw notFound('Member not found');
    if (target.role === 'owner') throw forbidden('Owner role cannot be changed');
    if (ROLE_RANK[target.role] >= ROLE_RANK[myRole] && myRole !== 'owner') throw forbidden('Cannot modify a member with an equal or higher role');
    if (role === 'admin' && myRole !== 'owner') throw forbidden('Only the owner can grant admin');
    db.prepare('UPDATE workspace_members SET role = ? WHERE workspace_id = ? AND user_id = ?').run(role, c.params.wid, c.params.uid);
    h.audit(c.params.wid, a.userId, 'role_change', 'member', c.params.uid);
    return { ok: true };
  });

  r.del('/v1/workspaces/:wid/members/:uid', async (req, res, c) => {
    const a = h.authenticate(req);
    const isSelf = a.userId === c.params.uid;
    const myRole = h.member(a.userId, c.params.wid, isSelf ? 'viewer' : 'admin');
    const target = db.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?').get(c.params.wid, c.params.uid);
    if (!target) throw notFound('Member not found');
    if (target.role === 'owner') throw forbidden('The owner cannot be removed');
    if (!isSelf && ROLE_RANK[target.role] >= ROLE_RANK[myRole] && myRole !== 'owner') throw forbidden('Cannot remove a member with an equal or higher role');
    db.prepare('DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?').run(c.params.wid, c.params.uid);
    h.audit(c.params.wid, a.userId, 'remove', 'member', c.params.uid);
    return { ok: true };
  });

  r.get('/v1/workspaces/:wid/audit', async (req, res, c) => {
    const a = h.authenticate(req);
    h.member(a.userId, c.params.wid, 'admin');
    return db.prepare('SELECT id, user_id AS userId, action, entity, entity_id AS entityId, ts FROM audit_log WHERE workspace_id = ? ORDER BY id DESC LIMIT 200').all(c.params.wid).map((x) => ({ ...x }));
  });
}
