import { randomBytes } from 'node:crypto';
const env = process.env;
const num = (v, d) => (v === undefined || v === '' || Number.isNaN(Number(v)) ? d : Number(v));
const isProd = env.NODE_ENV === 'production';

let masterKey = env.MASTER_KEY || '';
if (!masterKey) {
  if (isProd) {
    console.error('FATAL: MASTER_KEY is required in production (openssl rand -hex 32).');
    process.exit(1);
  }
  masterKey = randomBytes(32).toString('hex'); // ephemeral, dev/test only
}
if (isProd && masterKey.length < 32) {
  console.error('FATAL: MASTER_KEY must be at least 32 characters.');
  process.exit(1);
}

export const config = {
  isProd,
  port: num(env.PORT, 8080),
  host: env.HOST || '0.0.0.0',
  databasePath: env.DATABASE_PATH || './data/apihub.db',
  masterKey,
  trustProxy: env.TRUST_PROXY === '1',
  requireHttps: isProd && env.REQUIRE_HTTPS !== '0',
  accessTtlMin: num(env.ACCESS_TOKEN_TTL_MIN, 60),
  refreshTtlDays: num(env.REFRESH_TOKEN_TTL_DAYS, 30),
  registerLimitPerHour: num(env.REGISTER_LIMIT_PER_HOUR, 10),
  allowRegistration: env.ALLOW_REGISTRATION !== '0',
  maxBodyBytes: num(env.MAX_BODY_BYTES, 1048576),
  monitorIntervalSec: num(env.MONITOR_INTERVAL_SEC, 60),
  allowPrivateTargets: env.ALLOW_PRIVATE_TARGETS === '1' && !isProd,
};

// Plan limits are enforced server-side. Payment itself is NOT implemented (see docs/SECURITY.md & README).
export const PLANS = {
  free: { projects: 3, apis: 3, endpointsPerApi: 25, requestsPerMonth: 10000, ratePerMin: 60, logRetentionDays: 7, members: 1, automatedTests: false, environments: 3 },
  pro: { projects: 25, apis: 50, endpointsPerApi: 200, requestsPerMonth: 500000, ratePerMin: 600, logRetentionDays: 30, members: 1, automatedTests: true, environments: 10 },
  team: { projects: 100, apis: 200, endpointsPerApi: 500, requestsPerMonth: 2000000, ratePerMin: 1500, logRetentionDays: 90, members: 25, automatedTests: true, environments: 20 },
  cloud: { projects: 500, apis: 1000, endpointsPerApi: 1000, requestsPerMonth: 20000000, ratePerMin: 6000, logRetentionDays: 180, members: 100, automatedTests: true, environments: 50 },
};
