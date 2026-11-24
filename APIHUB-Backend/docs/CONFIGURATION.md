# Configuration (environment variables)
See `backend/.env.example`. Key settings: `MASTER_KEY` (required in prod), `DATABASE_PATH`, `PORT`, `TRUST_PROXY`, `REQUIRE_HTTPS`, `ALLOW_REGISTRATION` (0 = no new sign-ups after you created your account), `REGISTER_LIMIT_PER_HOUR`, `ACCESS_TOKEN_TTL_MIN`, `REFRESH_TOKEN_TTL_DAYS`, `MAX_BODY_BYTES`, `MONITOR_INTERVAL_SEC`, `ALLOW_SELF_PLAN_CHANGE` (self-hosted only: lets a workspace owner pick any plan; default off because no payment provider exists).

Plan limits are in `backend/src/config.js` (`PLANS`).

App settings (Settings screen): theme (System Default / Light / Dark — system by default), server URL, request timeout, max response size, masking of sensitive data in history, history retention.
