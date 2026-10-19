// Loaded before every test file (npm test: node --test --require ./test/setup.js).
// Each test file runs in its own process; give it a throwaway Postgres schema
// so files can run in parallel against one database without seeing each
// other's rows, and drop that schema when the file finishes.
//
// Needs DATABASE_URL pointing at a Postgres the tests may create schemas in
// (CI starts one; locally e.g. the demo's: see local-dev/docker-compose.yml).
const crypto = require('crypto');

if (!process.env.DATABASE_URL) {
  throw new Error('Set DATABASE_URL to a Postgres for the tests (each test file gets its own temporary schema).');
}
const schema = `test_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
process.env.DB_SCHEMA = schema;

let dropped = false;
process.on('beforeExit', () => {
  if (dropped) return;
  dropped = true;
  // Only if this file actually touched the database.
  const loaded = Object.keys(require.cache).some((p) => /[\\/]src[\\/]db\.js$/.test(p));
  if (!loaded) return;
  const { db } = require('../src/db');
  db.pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`)
    .catch(() => {})
    .finally(() => db.pool.end().catch(() => {}));
});
