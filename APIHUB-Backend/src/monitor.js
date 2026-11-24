import { probe } from './ssrf.js';
import { now } from './util.js';

export function startMonitor({ db, config }) {
  const evalAlerts = () => {
    for (const al of db.prepare('SELECT * FROM alerts WHERE enabled = 1').all()) {
      const t = now(); const since = t - al.window_min * 60000;
      if (al.last_triggered_at && t - al.last_triggered_at < al.window_min * 60000) continue; // de-duplicate
      let msg = null;
      const s = db.prepare('SELECT COUNT(*) n, COALESCE(SUM(status >= 400),0) err, AVG(duration_ms) avg FROM request_logs WHERE api_id = ? AND ts >= ?').get(al.api_id, since);
      if (al.kind === 'error_rate' && s.n >= 5 && (s.err / s.n) * 100 >= al.threshold) msg = `Error rate ${((s.err / s.n) * 100).toFixed(1)}% over last ${al.window_min} min (threshold ${al.threshold}%)`;
      if (al.kind === 'latency' && s.n >= 1 && s.avg >= al.threshold) msg = `Average latency ${Math.round(s.avg)}ms over last ${al.window_min} min (threshold ${al.threshold}ms)`;
      if (al.kind === 'request_count' && s.n >= al.threshold) msg = `${s.n} requests in last ${al.window_min} min (threshold ${al.threshold})`;
      if (al.kind === 'down') {
        const last = db.prepare('SELECT ok FROM health_checks WHERE api_id = ? ORDER BY id DESC LIMIT 1').get(al.api_id);
        if (last && !last.ok) msg = 'API health check is failing';
      }
      if (msg) {
        db.prepare('INSERT INTO alert_events (alert_id, ts, message) VALUES (?,?,?)').run(al.id, t, msg);
        db.prepare('UPDATE alerts SET last_triggered_at = ? WHERE id = ?').run(t, al.id);
      }
    }
  };
  const checkHealth = async () => {
    for (const api of db.prepare("SELECT id, health_url FROM apis WHERE health_url != ''").all()) {
      const p = await probe(api.health_url);
      db.prepare('INSERT INTO health_checks (api_id,ts,ok,status,duration_ms,error) VALUES (?,?,?,?,?,?)').run(api.id, now(), p.ok ? 1 : 0, p.status, p.ms, p.error || '');
    }
  };
  const purge = () => {
    for (const w of db.prepare('SELECT id, log_retention_days d FROM workspaces').all()) db.prepare('DELETE FROM request_logs WHERE workspace_id = ? AND ts < ?').run(w.id, now() - w.d * 86400000);
    db.prepare('DELETE FROM health_checks WHERE ts < ?').run(now() - 30 * 86400000);
    db.prepare('DELETE FROM sessions WHERE refresh_expires_at < ? OR revoked = 1 AND created_at < ?').run(now(), now() - 7 * 86400000);
  };
  let running = false; let tick = 0;
  const run = async () => {
    if (running) return; running = true;
    try { await checkHealth(); evalAlerts(); if (tick++ % 60 === 0) purge(); } catch (e) { console.error('monitor error:', e.message); } finally { running = false; }
  };
  if (config.monitorIntervalSec <= 0) return { stop() {}, run };
  const timer = setInterval(run, config.monitorIntervalSec * 1000); timer.unref();
  return { stop: () => clearInterval(timer), run };
}
