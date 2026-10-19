const { Pool, types } = require('pg');
const { DATABASE_URL, DB_SCHEMA, APP_BASE_URL, TENANT_ADMIN_SECRET } = require('./config');

// ---- Postgres ----
// All state lives in Postgres so several instances can run behind a load
// balancer: platform registrations, user id mappings, the tool's signing keys,
// short-lived login/deep-link/registration sessions, the audit log and rate
// limits. Timestamps are epoch milliseconds (BIGINT), as before.
//
// BIGINT/COUNT(*) come back from node-postgres as strings by default; every
// value we store fits comfortably in a JS number (ids, ms timestamps), so
// parse them as numbers once, here.
types.setTypeParser(20, (v) => (v === null ? null : Number(v)));

if (DB_SCHEMA && !/^[a-z_][a-z0-9_]{0,62}$/.test(DB_SCHEMA)) throw new Error('DB_SCHEMA must be a plain lowercase identifier');
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: Number(process.env.DB_POOL_MAX || 10),
  // Idle connections don't keep a finished script or test process alive.
  allowExitOnIdle: true,
});
if (DB_SCHEMA) pool.on('connect', (client) => client.query(`SET search_path TO ${DB_SCHEMA}`));

// The SQL throughout this codebase uses `?` placeholders; Postgres wants $1..$n.
// No statement here contains a literal '?', so a positional rewrite is exact.
function toPg(sql) {
  let n = 0;
  return sql.replace(/\?/g, () => `$${++n}`);
}

// The schema is created on first use (see init below), so scripts and tests
// don't each need a setup call; the server still calls init() up front to fail
// fast at startup if Postgres is unreachable.
function makeRunner(queryable, { ensureSchema }) {
  const q = async (sql, params = []) => {
    if (ensureSchema) await init();
    return queryable.query(toPg(sql), params);
  };
  return {
    // First row or undefined.
    one: async (sql, params) => (await q(sql, params)).rows[0],
    // All rows.
    all: async (sql, params) => (await q(sql, params)).rows,
    // Writes: { changes, rows } (rows for RETURNING).
    run: async (sql, params) => { const r = await q(sql, params); return { changes: r.rowCount, rows: r.rows }; },
    exec: async (sql) => { if (ensureSchema) await init(); await queryable.query(sql); },
  };
}

const db = {
  ...makeRunner(pool, { ensureSchema: true }),
  pool,
  // Runs fn(tx) in one transaction; tx has the same one/all/run/exec.
  async tx(fn) {
    await init();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(makeRunner(client, { ensureSchema: false }));
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  },
  async close() { await pool.end(); },
};

// ---- Schema ----
// "product" separates the Analytics tool from the Tutor Bot tool at the
// registration level -- each is installed in a university's LMS as its own
// External Tool with its own client_id, so a school can buy/enable one
// without the other. Same verification plumbing underneath (one service,
// one JWT/JWKS codepath), but from the customer's side these are two
// separate, independently purchasable tools, not one bundle.
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS platforms (
    id BIGSERIAL PRIMARY KEY,
    product TEXT NOT NULL CHECK (product IN ('analytics', 'tutor_bot')),
    tenant_key TEXT NOT NULL,
    tenant_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    auth_login_url TEXT NOT NULL,
    auth_token_url TEXT,
    jwks_url TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    -- Deactivate, not delete (user mappings and audit history reference it).
    active INTEGER NOT NULL DEFAULT 1,
    -- Created via Dynamic Registration: gates auto-discovery of unknown
    -- deployment_ids in src/lti/launch.js (manual registrations stay strict).
    dynamic_registration INTEGER NOT NULL DEFAULT 0,
    UNIQUE (issuer, client_id)
  );
  CREATE TABLE IF NOT EXISTS lti_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    platform_id BIGINT NOT NULL,
    target_link_uri TEXT,
    created_at BIGINT NOT NULL,
    -- The platform's opaque launch hint, kept so a launch whose browser check
    -- failed can offer "open in a new tab" (Moodle's carries the activity id).
    lti_message_hint TEXT
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
  -- The tool's own signing keys. status: 'next' (published in the JWKS ahead
  -- of use), 'active' (signs everything), 'retired' (still published until
  -- retire_after so tokens it signed stay verifiable), 'removed'. See
  -- src/security/toolKeys.js. enc_iv/enc_tag present = private key encrypted.
  CREATE TABLE IF NOT EXISTS tool_keys (
    kid TEXT PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    enc_iv TEXT,
    enc_tag TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    activated_at BIGINT,
    retire_after BIGINT
  );
  CREATE TABLE IF NOT EXISTS lti_dl_sessions (
    id TEXT PRIMARY KEY,
    platform_id BIGINT NOT NULL,
    deep_link_return_url TEXT NOT NULL,
    data TEXT,
    created_at BIGINT NOT NULL,
    -- the request's deployment (answered back), what the platform accepts, and
    -- the exact items offered (the submit is matched against this list)
    deployment_id TEXT,
    accept_multiple INTEGER NOT NULL DEFAULT 0,
    accept_lineitem INTEGER NOT NULL DEFAULT 1,
    catalog TEXT
  );
  CREATE TABLE IF NOT EXISTS admin_audit_log (
    id BIGSERIAL PRIMARY KEY,
    event TEXT NOT NULL,
    detail TEXT,
    ip TEXT,
    created_at BIGINT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit_log (created_at);
  -- A platform's deployment_id column is its deployment at registration
  -- time; this table is the full set of deployment ids that platform is
  -- allowed to launch from (e.g. Canvas mints a new deployment_id per
  -- course/account that installs the same client_id).
  CREATE TABLE IF NOT EXISTS platform_deployments (
    platform_id BIGINT NOT NULL,
    deployment_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (platform_id, deployment_id)
  );
  -- Short-lived, single-use: the platform's openid_configuration and
  -- registration_token between GET /lti/register and POST
  -- /lti/register/complete (kept server-side: the token is a credential).
  CREATE TABLE IF NOT EXISTS lti_registration_sessions (
    id TEXT PRIMARY KEY,
    openid_config TEXT NOT NULL,
    registration_token TEXT,
    created_at BIGINT NOT NULL
  );
  -- Captured from the AGS endpoint claim on every resource-link launch
  -- (src/lti/launch.js). resource_link_id is platform-issued and stable for
  -- one activity; lineitem_url is its gradebook column, lineitems_url the
  -- collection used to create one lazily (src/lti/ags.js).
  CREATE TABLE IF NOT EXISTS ags_lineitems (
    resource_link_id TEXT PRIMARY KEY,
    platform_id BIGINT NOT NULL,
    tenant_key TEXT NOT NULL,
    lineitem_url TEXT,
    lineitems_url TEXT,
    scope TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
  );
  -- Who is currently enrolled in which LMS course (context), learned from NRPS
  -- roster syncs and launches. A student is only treated as dropped once they
  -- have no active membership in any course of their tenant (src/lti/nrps.js).
  CREATE TABLE IF NOT EXISTS lti_memberships (
    tenant_key TEXT NOT NULL,
    platform_issuer TEXT NOT NULL,
    context_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    active INTEGER NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_key, platform_issuer, context_id, subject)
  );
  -- Fixed-window request counters shared by every instance (src/rateLimit.js).
  CREATE TABLE IF NOT EXISTS rate_limits (
    bucket TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    window_ends BIGINT NOT NULL
  );
`;

let initPromise = null;
// Creates the schema (idempotent). Awaited once before the server listens and
// at the start of each test file; safe to call repeatedly.
function init() {
  if (!initPromise) {
    initPromise = (async () => {
      if (DB_SCHEMA) await pool.query(`CREATE SCHEMA IF NOT EXISTS ${DB_SCHEMA}`);
      // Several instances starting at once may race on CREATE ... IF NOT EXISTS;
      // an advisory lock serializes schema setup across them.
      const client = await pool.connect();
      try {
        await client.query('SELECT pg_advisory_lock(72410000)');
        await client.query(SCHEMA);
        // Columns added after a table first shipped (CREATE TABLE IF NOT EXISTS won't add them).
        await client.query('ALTER TABLE lti_states ADD COLUMN IF NOT EXISTS lti_message_hint TEXT');
      } finally {
        await client.query('SELECT pg_advisory_unlock(72410000)').catch(() => {});
        client.release();
      }
    })().catch((err) => { initPromise = null; throw err; });
  }
  return initPromise;
}

// ---- Memberships ----
async function setMembership(tenantKey, issuer, contextId, subject, active) {
  await db.run(
    'INSERT INTO lti_memberships (tenant_key, platform_issuer, context_id, subject, active, updated_at) VALUES (?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT (tenant_key, platform_issuer, context_id, subject) DO UPDATE SET active = excluded.active, updated_at = excluded.updated_at',
    [tenantKey, issuer, String(contextId), String(subject), active ? 1 : 0, Date.now()]
  );
}

async function hasActiveMembership(tenantKey, issuer, subject) {
  return !!(await db.one(
    'SELECT 1 FROM lti_memberships WHERE tenant_key = ? AND platform_issuer = ? AND subject = ? AND active = 1',
    [tenantKey, issuer, String(subject)]
  ));
}

// ---- Short-lived sessions ----
// States/nonces are single-use and short-lived (10 min) -- sweep expired
// rows on every login attempt rather than running a separate cron.
async function sweepExpiredStates() {
  await db.run('DELETE FROM lti_states WHERE created_at < ?', [Date.now() - 10 * 60 * 1000]);
}

// Same idea as sweepExpiredStates, for the Dynamic Registration hand-off
// session (src/lti/dynamicRegistration.js).
async function sweepExpiredRegistrationSessions() {
  await db.run('DELETE FROM lti_registration_sessions WHERE created_at < ?', [Date.now() - 10 * 60 * 1000]);
}

// ---- Platforms ----
async function getPlatform({ issuer, clientId }) {
  if (clientId) {
    return db.one('SELECT * FROM platforms WHERE issuer = ? AND client_id = ? AND active = 1', [issuer, clientId]);
  }
  const rows = await db.all('SELECT * FROM platforms WHERE issuer = ? AND active = 1', [issuer]);
  return rows.length === 1 ? rows[0] : null; // ambiguous without a client_id if more than one
}

async function getPlatformById(id) {
  return db.one('SELECT * FROM platforms WHERE id = ?', [id]);
}

async function setPlatformActive(id, active) {
  await db.run('UPDATE platforms SET active = ? WHERE id = ?', [active ? 1 : 0, id]);
}

// Shared logic behind manual registration (the JSON API, the /admin/onboard
// form) and Dynamic Registration (src/lti/dynamicRegistration.js) -- one
// place that actually writes a platform row, so they can't drift.
// requireDeployment=false is what Dynamic Registration needs: not every
// platform's registration response includes a deployment_id upfront (Canvas
// typically doesn't; Moodle typically does) -- deployment_id stays NOT NULL
// at the column level (storing '' rather than loosening the schema), and
// platform_deployments simply starts empty for that platform, to be filled
// by launch.js's auto-discovery (gated on the `dynamic` flag this sets).
async function upsertPlatform(fields, { requireDeployment, dynamic }) {
  const { product, tenantKey, tenantName, issuer, clientId, deploymentId, authLoginUrl, authTokenUrl, jwksUrl } = fields;
  const requiredFields = ['product', 'tenantKey', 'tenantName', 'issuer', 'clientId', 'authLoginUrl', 'jwksUrl'];
  if (requireDeployment) requiredFields.push('deploymentId');
  const missing = requiredFields.filter((k) => !fields[k]);
  if (missing.length) throw new Error(`Missing fields: ${missing.join(', ')}`);
  if (!['analytics', 'tutor_bot'].includes(product)) {
    throw new Error("product must be 'analytics' or 'tutor_bot'");
  }
  const now = Date.now();
  const { rows } = await db.run(
    `INSERT INTO platforms (product, tenant_key, tenant_name, issuer, client_id, deployment_id, auth_login_url, auth_token_url, jwks_url, dynamic_registration, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (issuer, client_id) DO UPDATE SET
       product = excluded.product, tenant_key = excluded.tenant_key, tenant_name = excluded.tenant_name,
       deployment_id = excluded.deployment_id, auth_login_url = excluded.auth_login_url,
       auth_token_url = excluded.auth_token_url, jwks_url = excluded.jwks_url
     RETURNING id`,
    [product, tenantKey, tenantName, issuer, clientId, deploymentId || '', authLoginUrl, authTokenUrl || null, jwksUrl, dynamic ? 1 : 0, now]
  );
  const id = rows[0].id;
  if (deploymentId) await addDeployment(id, deploymentId);
  return id;
}

async function registerPlatform(fields) {
  return upsertPlatform(fields, { requireDeployment: true, dynamic: false });
}

async function registerDynamicPlatform(fields) {
  return upsertPlatform(fields, { requireDeployment: false, dynamic: true });
}

// Fixes an already-registered platform in place (typo'd issuer/client_id, a
// token URL that was never captured, an LMS that moved hosts...) instead of
// deactivating it and re-onboarding. tenant_key and product are deliberately
// not editable: lti_user_map and tutor-service's per-tenant database are keyed
// on tenant_key, so changing it would silently detach every existing user.
const EDITABLE_PLATFORM_FIELDS = {
  tenantName: 'tenant_name',
  issuer: 'issuer',
  clientId: 'client_id',
  authLoginUrl: 'auth_login_url',
  authTokenUrl: 'auth_token_url',
  jwksUrl: 'jwks_url',
};
const PLATFORM_URL_FIELDS = ['issuer', 'authLoginUrl', 'authTokenUrl', 'jwksUrl'];

async function updatePlatform(id, fields) {
  const existing = await getPlatformById(id);
  if (!existing) throw new Error('Platform not found.');
  const next = {};
  for (const [field, column] of Object.entries(EDITABLE_PLATFORM_FIELDS)) {
    const value = fields[field] === undefined ? existing[column] : String(fields[field]).trim();
    next[column] = value === '' && field === 'authTokenUrl' ? null : value;
  }
  const missing = Object.entries(EDITABLE_PLATFORM_FIELDS)
    .filter(([field, column]) => field !== 'authTokenUrl' && !next[column]).map(([field]) => field);
  if (missing.length) throw new Error(`Missing fields: ${missing.join(', ')}`);
  for (const field of PLATFORM_URL_FIELDS) {
    const value = next[EDITABLE_PLATFORM_FIELDS[field]];
    if (value && !/^https?:\/\/[^\s]+$/i.test(value)) throw new Error(`${field} must be an http(s) URL.`);
  }
  const clash = await db.one('SELECT id FROM platforms WHERE issuer = ? AND client_id = ? AND id <> ?', [next.issuer, next.client_id, id]);
  if (clash) throw new Error('Another platform is already registered with that issuer and client ID.');
  await db.run(
    `UPDATE platforms SET tenant_name = ?, issuer = ?, client_id = ?, auth_login_url = ?, auth_token_url = ?, jwks_url = ?
     WHERE id = ?`,
    [next.tenant_name, next.issuer, next.client_id, next.auth_login_url, next.auth_token_url, next.jwks_url, id]
  );
  // The caller needs this to decide whether cached platform keys are stale.
  const changed = Object.values(EDITABLE_PLATFORM_FIELDS).filter((column) => (existing[column] || null) !== (next[column] || null));
  return { platform: await getPlatformById(id), changed };
}

// The full set of deployment ids a platform (an (issuer, client_id)
// registration) is allowed to launch from -- see platform_deployments above.
async function isKnownDeployment(platformId, deploymentId) {
  return !!(await db.one('SELECT 1 FROM platform_deployments WHERE platform_id = ? AND deployment_id = ?', [platformId, deploymentId]));
}

async function addDeployment(platformId, deploymentId) {
  await db.run(
    'INSERT INTO platform_deployments (platform_id, deployment_id, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING',
    [platformId, deploymentId, Date.now()]
  );
}

// ---- AGS (see src/lti/ags.js for the actual score-push logic) ----
// Called from src/lti/launch.js on every LtiResourceLinkRequest that carries
// an AGS endpoint claim -- refreshes lineitems_url/scope every launch (a
// platform could change them), but never clobbers an already-known
// lineitem_url with a blank one from a launch that didn't happen to include
// a direct lineitem reference.
async function upsertAgsEndpoint(resourceLinkId, { platformId, tenantKey, lineitemUrl, lineitemsUrl, scope }) {
  const now = Date.now();
  await db.run(
    `INSERT INTO ags_lineitems (resource_link_id, platform_id, tenant_key, lineitem_url, lineitems_url, scope, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (resource_link_id) DO UPDATE SET
       lineitems_url = excluded.lineitems_url, scope = excluded.scope, updated_at = excluded.updated_at,
       lineitem_url = COALESCE(excluded.lineitem_url, ags_lineitems.lineitem_url)`,
    [resourceLinkId, platformId, tenantKey, lineitemUrl || null, lineitemsUrl || null, scope || null, now, now]
  );
}

async function getAgsLineItem(resourceLinkId) {
  return db.one('SELECT * FROM ags_lineitems WHERE resource_link_id = ?', [resourceLinkId]);
}

async function setAgsLineItemUrl(resourceLinkId, lineitemUrl) {
  await db.run('UPDATE ags_lineitems SET lineitem_url = ?, updated_at = ? WHERE resource_link_id = ?', [lineitemUrl, Date.now(), resourceLinkId]);
}

// ---- User ids ----
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

async function findMappedUserId(tenantKey, issuer, subject) {
  const row = await db.one(
    'SELECT userid FROM lti_user_map WHERE tenant_key = ? AND platform_issuer = ? AND subject = ?',
    [tenantKey, issuer, String(subject)]
  );
  return row ? row.userid : null;
}

// Two launches by the same new person can race (several instances, double
// clicks): the mapping insert is ON CONFLICT DO NOTHING and whoever loses
// reads back the winner's id, so one person never ends up with two ids.
async function mapUserId(tenantKey, issuer, subject, userid) {
  await db.run(
    'INSERT INTO lti_user_map (tenant_key, platform_issuer, subject, userid) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING',
    [tenantKey, issuer, String(subject), userid]
  );
  return findMappedUserId(tenantKey, issuer, subject);
}

async function getOrAllocateUserId(tenantKey, issuer, subject, email) {
  const existing = await findMappedUserId(tenantKey, issuer, subject);
  if (existing) return existing;

  const matched = await findExistingUserIdByEmail(tenantKey, email);
  if (matched) return mapUserId(tenantKey, issuer, subject, matched);

  // Atomic per-tenant counter: next_userid holds the next free id.
  const { rows } = await db.run(
    `INSERT INTO tenant_userid_seq (tenant_key, next_userid) VALUES (?, 100001)
     ON CONFLICT (tenant_key) DO UPDATE SET next_userid = tenant_userid_seq.next_userid + 1
     RETURNING next_userid - 1 AS userid`,
    [tenantKey]
  );
  return mapUserId(tenantKey, issuer, subject, rows[0].userid);
}

module.exports = {
  db, init, sweepExpiredStates, sweepExpiredRegistrationSessions, getPlatform, getPlatformById,
  registerPlatform, registerDynamicPlatform, updatePlatform, setPlatformActive,
  isKnownDeployment, addDeployment, getOrAllocateUserId, findExistingUserIdByEmail, findMappedUserId,
  setMembership, hasActiveMembership,
  upsertAgsEndpoint, getAgsLineItem, setAgsLineItemUrl,
};
