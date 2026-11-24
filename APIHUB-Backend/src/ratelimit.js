// In-memory fixed-window limiter. For multi-instance deployments swap for Redis (see docs).
export class RateLimiter {
  constructor() { this.buckets = new Map(); this.timer = setInterval(() => this.gc(), 60000); this.timer.unref(); }
  hit(key, limit, windowMs) {
    const now = Date.now();
    let b = this.buckets.get(key);
    if (!b || b.reset <= now) { b = { count: 0, reset: now + windowMs }; this.buckets.set(key, b); }
    b.count++;
    return { allowed: b.count <= limit, remaining: Math.max(0, limit - b.count), resetMs: b.reset - now };
  }
  gc() { const now = Date.now(); for (const [k, v] of this.buckets) if (v.reset <= now) this.buckets.delete(k); }
  stop() { clearInterval(this.timer); }
}
