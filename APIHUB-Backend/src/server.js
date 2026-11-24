import { openDb } from './db.js';
import { createApp } from './app.js';
import { config } from './config.js';

const db = openDb();
const app = createApp(db);
app.server.listen(config.port, config.host, () => console.log(`APIHUB backend listening on ${config.host}:${config.port} (${config.isProd ? 'production' : 'development'})`));
const stop = async () => { await app.close(); db.close(); process.exit(0); };
process.on('SIGTERM', stop); process.on('SIGINT', stop);
