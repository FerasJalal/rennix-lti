// One-time move of rennix-lti's data from the old SQLite file to Postgres.
//
//   DB_PATH=./data/lti.db DATABASE_URL=postgres://... node scripts/migrate-sqlite-to-postgres.js
//
// Copies everything that must survive -- platform registrations (with their
// original ids), deployments, the LTI-user -> Rennix-userid mappings (students
// keep their history), the per-tenant id counter, the tool's signing key(s),
// AGS endpoints, memberships and the audit log -- in one transaction, then
// checks row counts. Short-lived login / deep-link / registration sessions are
// skipped (they expire within minutes anyway). Refuses to run into a Postgres
// database that already has platforms or users unless --into-non-empty is given.
// Needs better-sqlite3 (an optional dependency of this package).

const path = require('path');

const TABLES = [
  // [table, primary-key columns (for ON CONFLICT), has serial id to re-seed]
  ['platforms', ['id'], true],
  ['platform_deployments', ['platform_id', 'deployment_id'], false],
  ['lti_user_map', ['tenant_key', 'platform_issuer', 'subject'], false],
  ['tenant_userid_seq', ['tenant_key'], false],
  ['tool_keys', ['kid'], false],
  ['ags_lineitems', ['resource_link_id'], false],
  ['lti_memberships', ['tenant_key', 'platform_issuer', 'context_id', 'subject'], false],
  ['admin_audit_log', ['id'], true],
];

async function main() {
  const allowNonEmpty = process.argv.includes('--into-non-empty');
  const sqlitePath = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'lti.db');
  let Database;
  try { Database = require('better-sqlite3'); } catch (e) {
    throw new Error('better-sqlite3 is not installed (run: npm install better-sqlite3), it is needed to read the old database');
  }
  const sqlite = new Database(sqlitePath, { readonly: true, fileMustExist: true });
  const { db, init } = require('../src/db');
  await init();

  const existing = await db.one('SELECT (SELECT COUNT(*) FROM platforms) AS p, (SELECT COUNT(*) FROM lti_user_map) AS u');
  if ((existing.p || existing.u) && !allowNonEmpty) {
    throw new Error(`Postgres already has ${existing.p} platforms and ${existing.u} user mappings; refusing to merge (pass --into-non-empty to override)`);
  }

  const sqliteTables = new Set(sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name));
  const summary = [];
  await db.tx(async (tx) => {
    for (const [table, keys, serial] of TABLES) {
      if (!sqliteTables.has(table)) { summary.push([table, 0, 'not in old database']); continue; }
      const pgColumns = (await tx.all(
        "SELECT column_name FROM information_schema.columns WHERE table_name = ? AND table_schema = current_schema()", [table]
      )).map((r) => r.column_name);
      const sqliteColumns = sqlite.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
      const columns = sqliteColumns.filter((c) => pgColumns.includes(c));
      let rows = sqlite.prepare(`SELECT ${columns.join(', ')} FROM ${table}`).all();

      if (table === 'tool_keys' && !sqliteColumns.includes('status')) {
        // Pre-rotation databases signed with the oldest key; keep exactly that one active.
        rows = rows.sort((a, b) => a.created_at - b.created_at);
        rows.forEach((r, i) => { r.status = i === 0 ? 'active' : 'removed'; r.activated_at = i === 0 ? r.created_at : null; });
        if (rows.length) columns.push('status', 'activated_at');
      }

      for (const row of rows) {
        const cols = columns.filter((c) => c in row);
        await tx.run(
          `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')}) ON CONFLICT (${keys.join(', ')}) DO NOTHING`,
          cols.map((c) => row[c])
        );
      }
      if (serial && rows.length) {
        await tx.run(`SELECT setval(pg_get_serial_sequence('${table}', 'id'), (SELECT MAX(id) FROM ${table}))`);
      }
      const copied = (await tx.one(`SELECT COUNT(*) AS n FROM ${table}`)).n;
      summary.push([table, rows.length, copied >= rows.length ? 'ok' : `ONLY ${copied} in Postgres`]);
    }
    // Very old databases predate platform_deployments: every platform's own
    // registration-time deployment id must still be accepted.
    await tx.run(
      "INSERT INTO platform_deployments (platform_id, deployment_id, created_at) SELECT id, deployment_id, created_at FROM platforms WHERE deployment_id <> '' ON CONFLICT DO NOTHING"
    );
    if (summary.some(([, , status]) => status.startsWith('ONLY'))) throw new Error('row counts do not match; nothing was committed');
  });

  console.log(`Migrated ${sqlitePath} -> Postgres:`);
  for (const [table, n, status] of summary) console.log(`  ${table.padEnd(22)} ${String(n).padStart(6)}  ${status}`);
  sqlite.close();
  await db.close();
}

main().catch(async (err) => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});
