# Security guide

Implemented (and covered by tests unless noted)
* Passwords: scrypt (N=16384) with per-user salt; login rate limit + temporary lockout; constant-time path for unknown emails.
* Sessions: random opaque access/refresh tokens, only SHA-256 hashes stored; refresh tokens are single-use (rotation); logout/logout-all/password-change revoke sessions.
* API keys (engine access): shown once, stored as SHA-256 hash, permissions (read/write), expiry, revocation, last-used.
* Environment secrets: AES-256-GCM at rest (key derived from `MASTER_KEY`), masked in every API response.
* Basic/JWT auth secrets for published APIs: scrypt hash / AES-GCM; JWT accepts HS256 only (rejects `alg:none`).
* Access control: every resource is resolved through workspace membership; other users' resources return 404. Role checks (viewer read-only, developer cannot delete, admin required for keys).
* Engine: input validation (path/query/header types, JSON schema subset), body size cap, per-IP + per-API rate limits, monthly quota, response header allow-list (no Set-Cookie/Content-Type override), `CSP: sandbox`, `nosniff`, template values JSON-escaped (injection test), no user code is ever executed.
* SSRF: health-check probes validate scheme, block loopback/private/link-local/CGNAT/metadata ranges (IPv4+IPv6), resolve DNS and **pin the IP** (anti DNS-rebinding), no redirects, 5 s timeout, 64 KB read cap. The engine has no outbound proxy feature, so it cannot be used as an open proxy.
* HTTPS enforced in production; HSTS via Caddy.
* Logs store only route template, status, duration, size (no bodies, headers, tokens, query strings). Retention configurable per workspace; purge runs automatically.
* App: secrets in Android Keystore, history masks sensitive keys/query values, exports never include secrets, imports (Postman/OpenAPI/backup) are size/depth/count bounded and validated, `allowBackup=false`, HTTPS-only network config.

Known limits / your responsibility
* Single-node SQLite + in-memory limiter (see ARCHITECTURE). Keep `MASTER_KEY` and backups safe; rotating `MASTER_KEY` requires re-entering environment secrets.
* No email delivery: invitation tokens are returned to the inviter to send by another channel.
* Custom code functions are intentionally absent; if added later they must run in an isolated sandbox (separate process/container, no network, CPU/memory/time limits).
* No third-party penetration test has been performed.
