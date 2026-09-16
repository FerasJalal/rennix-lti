const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { DB_PATH, APP_BASE_URL, TENANT_ADMIN_SECRET } = require('./config');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// "product" separates the Analytics tool from the Tutor Bot tool at the
// registration level -- each is installed in a university's LMS as its own
// External Tool with its own client_id, so a school can buy/enable one
// without the other. Same verification plumbing underneath (one service,
// one JWT/JWKS codepath), but from the customer's side these are two
// separate, independently purchasable tools, not one bundle.
db.exec(`
  CREATE TABLE IF NOT EXISTS platforms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product TEXT NOT NULL CHECK (product IN ('analytics', 'tutor_bot')),
    tenant_key TEXT NOT NULL,
    tenant_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    auth_login_url TEXT NOT NULL,
    auth_token_url TEXT,
    jwks_url TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(issuer, client_id)
  );
  CREATE TABLE IF NOT EXISTS lti_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    platform_id INTEGER NOT NULL,
    target_link_uri TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS lti_user_map (
    tenant_key TEXT NOT NULL,
    platform_issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    userid INTEGER NOT NULL,
    PRIMARY KEY (tenant_key, platform_issuer, subject)
  );
  CREATE TABLE IF NOT EXISTS tenant_userid_seq (
    tenant_key TEXT PRIMARY KEY,
    next_userid INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS tool_keys (
    kid TEXT PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS lti_dl_sessions (
    id TEXT PRIMARY KEY,
    platform_id INTEGER NOT NULL,
    deep_link_return_url TEXT NOT NULL,
    data TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    detail TEXT,
    ip TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit_log(created_at);
`);

// States/nonces are single-use and short-lived (10 min) -- sweep expired
// rows on every login attempt rather than running a separate cron.
function sweepExpiredStates() {
  db.prepare('DELETE FROM lti_states WHERE created_at < ?').run(Date.now() - 10 * 60 * 1000);
}

function getPlatform({ issuer, clientId }) {
  if (clientId) {
    return db.prepare('SELECT * FROM platforms WHERE issuer = ? AND client_id = ?').get(issuer, clientId);
  }
  const rows = db.prepare('SELECT * FROM platforms WHERE issuer = ?').all(issuer);
  return rows.length === 1 ? rows[0] : null; // ambiguous without a client_id if more than one
}

// Shared logic behind both the JSON API (curl/scripted onboarding) and the
// HTML form (a human filling in one school's details) -- one place that
// actually writes a platform row, so they can't drift.
function registerPlatform(fields) {
  const { product, tenantKey, tenantName, issuer, clientId, deploymentId, authLoginUrl, authTokenUrl, jwksUrl } = fields;
  const missing = ['product', 'tenantKey', 'tenantName', 'issuer', 'clientId', 'deploymentId', 'authLoginUrl', 'jwksUrl']
    .filter((k) => !fields[k]);
  if (missing.length) throw new Error(`Missing fields: ${missing.join(', ')}`);
  if (!['analytics', 'tutor_bot'].includes(product)) {
    throw new Error("product must be 'analytics' or 'tutor_bot'");
  }
  db.prepare(
    `INSERT INTO platforms (product, tenant_key, tenant_name, issuer, client_id, deployment_id, auth_login_url, auth_token_url, jwks_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(issuer, client_id) DO UPDATE SET
       product = excluded.product, tenant_key = excluded.tenant_key, tenant_name = excluded.tenant_name,
       deployment_id = excluded.deployment_id, auth_login_url = excluded.auth_login_url,
       auth_token_url = excluded.auth_token_url, jwks_url = excluded.jwks_url`
  ).run(product, tenantKey, tenantName, issuer, clientId, deploymentId, authLoginUrl, authTokenUrl || null, jwksUrl, Date.now());
}

// tutor-service's schema keys students by a small integer id (it grew up as
// a single Moodle-backed pilot, where that's just Moodle's own user id).
// LTI's own user identifier (the `sub` claim) is an opaque, platform-chosen
// string with no such guarantee -- so this is the one place that identity
// gets translated into a stable integer, scoped per tenant, allocated once
// and reused on every later launch by the same person. The 100000 starting
// point keeps freshly-allocated ids from ever colliding with any small id a
// tenant might already have from manual/legacy seeding.
//
// Before allocating fresh, this checks tutor-service for an existing student
// with the same email in this tenant -- essential for HTU specifically,
// which already has real students with real history (attendance, chat,
// notes) under small ids from the Moodle-plugin path; without this, the same
// person launching via LTI instead would silently become a second,
// historyless account. A tenant that only ever arrives via LTI never has a
// pre-existing row to match, so this is a no-op cost for it -- just
// allocating fresh, as before.
async function findExistingUserIdByEmail(tenantKey, email) {
  if (!email || !TENANT_ADMIN_SECRET) return null;
  try {
    const url = new URL('/admin/tenant-user-lookup', APP_BASE_URL);
    url.searchParams.set('tenant', tenantKey);
    url.searchParams.set('email', email);
    // Header, not a query param -- tutor-service's requireTenantAdmin no longer
    // accepts the secret via the URL (it would land in access/proxy logs).
    const resp = await fetch(url.toString(), { headers: { 'x-tenant-admin-secret': TENANT_ADMIN_SECRET } });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.userid || null;
  } catch (err) {
    require('./log').error('[LTI] existing-user lookup failed:', err.message);
    return null;
  }
}

async function getOrAllocateUserId(tenantKey, issuer, subject, email) {
  const existing = db.prepare(
    'SELECT userid FROM lti_user_map WHERE tenant_key = ? AND platform_issuer = ? AND subject = ?'
  ).get(tenantKey, issuer, subject);
  if (existing) return existing.userid;

  const matched = await findExistingUserIdByEmail(tenantKey, email);
  if (matched) {
    db.prepare(
      'INSERT INTO lti_user_map (tenant_key, platform_issuer, subject, userid) VALUES (?, ?, ?, ?)'
    ).run(tenantKey, issuer, subject, matched);
    return matched;
  }

  const allocate = db.transaction(() => {
    let seq = db.prepare('SELECT next_userid FROM tenant_userid_seq WHERE tenant_key = ?').get(tenantKey);
    if (!seq) {
      seq = { next_userid: 100000 };
      db.prepare('INSERT INTO tenant_userid_seq (tenant_key, next_userid) VALUES (?, ?)').run(tenantKey, seq.next_userid);
    }
    db.prepare('UPDATE tenant_userid_seq SET next_userid = next_userid + 1 WHERE tenant_key = ?').run(tenantKey);
    db.prepare(
      'INSERT INTO lti_user_map (tenant_key, platform_issuer, subject, userid) VALUES (?, ?, ?, ?)'
    ).run(tenantKey, issuer, subject, seq.next_userid);
    return seq.next_userid;
  });
  return allocate();
}

module.exports = {
  db, sweepExpiredStates, getPlatform, registerPlatform, getOrAllocateUserId, findExistingUserIdByEmail,
};
