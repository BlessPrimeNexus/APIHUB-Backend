import { openDb } from './db.js';
const db = openDb();
console.log('Database is up to date:', db.prepare('SELECT name FROM schema_migrations ORDER BY name').all().map((r) => r.name).join(', '));
