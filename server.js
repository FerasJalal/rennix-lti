// rennix-lti — LTI 1.3 Tool (the "Tool" side of the spec; a Moodle/Canvas/etc.
// course is the "Platform"). This is deliberately separate from tutor-service:
// tutor-service is the single-tenant HTU pilot; this is the multi-tenant
// connector any institution's LMS launches into, without us ever needing
// direct access to their backend and without them installing custom code
// beyond a standard "External Tool" registration their LMS already supports.
//
// Flow (OIDC third-party initiated login, per the LTI 1.3 core spec):
//   1. Platform sends the user's browser to GET /lti/login with iss/login_hint/
//      target_link_uri/client_id. We look up the platform, mint a state+nonce,
//      and redirect to the platform's own auth endpoint.
//   2. Platform authenticates the user itself, then POSTs an id_token (a JWT
//      it signs) to POST /lti/launch along with our state.
//   3. We verify the JWT against the platform's published JWKS, check the
//      nonce we minted, and only then trust the identity/course/role claims
//      inside it. Nothing here ever reads the platform's database directly.

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { createRemoteJWKSet, jwtVerify, SignJWT, generateKeyPair, exportJWK } = require('jose');

const PORT = process.env.PORT || 3002;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'lti.db');
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
// Where a verified launch hands off to -- the actual product. Points at
// tutor-service for now (single shared app across tenants); swap per-tenant
// once the multi-tenant app itself exists.
const APP_BASE_URL = process.env.APP_BASE_URL || 'https://tutor.edu.rennix.ai';
// Shared with tutor-service specifically (separate from block_criterio's
// IDENTITY_SECRET) -- this is what lets a verified launch actually open the
// real app instead of the proof-of-concept page.
const LTI_BRIDGE_SECRET = process.env.LTI_BRIDGE_SECRET || '';
// Shared with tutor-service specifically, for the one cross-service call the
// onboarding form below makes (setting a new tenant's own OpenAI key).
const TENANT_ADMIN_SECRET = process.env.TENANT_ADMIN_SECRET || '';

if (!ADMIN_SECRET) {
  console.warn('WARNING: ADMIN_SECRET is not set -- /admin/platforms is effectively open. Set it before registering a real platform.');
}

const fs = require('fs');
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
`);

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
    url.searchParams.set('secret', TENANT_ADMIN_SECRET);
    url.searchParams.set('tenant', tenantKey);
    url.searchParams.set('email', email);
    const resp = await fetch(url.toString());
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.userid || null;
  } catch (err) {
    console.error('[LTI] existing-user lookup failed:', err.message);
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

// The token tutor-service actually trusts to open the real app -- distinct
// from signSessionToken below, which is this service's own internal-only
// token for the proof-of-concept landing page.
function signBridgeToken(payload) {
  if (!LTI_BRIDGE_SECRET) throw new Error('LTI_BRIDGE_SECRET is not set');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', LTI_BRIDGE_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

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

// Our own signing key, for the compact session token we hand to the app
// after a verified launch (HMAC is enough here -- this token never leaves
// our own infrastructure, unlike the platform's id_token which does).
function signSessionToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

const app = express();
// Behind Caddy (TLS-terminating reverse proxy) -- without this, req.protocol
// always reports 'http' (the internal Caddy->Node hop), which corrupted the
// redirect_uri sent to Moodle and made it reject the login (redirect_uri
// must exactly match the https:// URL registered on the tool). Caught via
// a real launch test against HTU's Moodle, not by inspection.
app.set('trust proxy', true);
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));

// ---- Step 1: OIDC third-party initiated login ----
// The LTI 1.3 / OIDC spec allows the platform to send this via GET or POST
// (its choice); Moodle uses POST (a form_post autosubmit), so both must work.
function handleLtiLogin(req, res) {
  sweepExpiredStates();
  const params = req.method === 'POST' ? req.body : req.query;
  const { iss, login_hint, target_link_uri, client_id, lti_message_hint } = params;
  if (!iss || !login_hint || !target_link_uri) {
    return res.status(400).send('Missing required LTI login parameters (iss, login_hint, target_link_uri).');
  }

  const platform = getPlatform({ issuer: iss, clientId: client_id });
  if (!platform) {
    return res.status(400).send(`Unknown platform (issuer=${iss}${client_id ? `, client_id=${client_id}` : ''}). Register it first via /admin/platforms.`);
  }

  const state = crypto.randomBytes(24).toString('base64url');
  const nonce = crypto.randomBytes(24).toString('base64url');
  db.prepare(
    'INSERT INTO lti_states (state, nonce, platform_id, target_link_uri, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(state, nonce, platform.id, String(target_link_uri), Date.now());

  const authUrl = new URL(platform.auth_login_url);
  authUrl.searchParams.set('scope', 'openid');
  authUrl.searchParams.set('response_type', 'id_token');
  authUrl.searchParams.set('client_id', platform.client_id);
  authUrl.searchParams.set('redirect_uri', `${req.protocol}://${req.get('host')}/lti/launch`);
  authUrl.searchParams.set('login_hint', String(login_hint));
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('response_mode', 'form_post');
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('prompt', 'none');
  if (lti_message_hint) authUrl.searchParams.set('lti_message_hint', String(lti_message_hint));

  res.redirect(302, authUrl.toString());
}
app.get('/lti/login', handleLtiLogin);
app.post('/lti/login', handleLtiLogin);

// ---- Step 2: launch -- verify the platform's signed id_token ----
app.post('/lti/launch', async (req, res) => {
  try {
    const { id_token, state } = req.body;
    if (!id_token || !state) return res.status(400).send('Missing id_token or state.');

    const stateRow = db.prepare('SELECT * FROM lti_states WHERE state = ?').get(state);
    if (!stateRow) return res.status(400).send('Unknown or expired state -- restart the launch from your LMS.');
    db.prepare('DELETE FROM lti_states WHERE state = ?').run(state); // single-use

    const platform = db.prepare('SELECT * FROM platforms WHERE id = ?').get(stateRow.platform_id);
    if (!platform) return res.status(400).send('Platform no longer registered.');

    const jwks = createRemoteJWKSet(new URL(platform.jwks_url));
    const { payload } = await jwtVerify(id_token, jwks, {
      issuer: platform.issuer,
      audience: platform.client_id,
    });

    if (payload.nonce !== stateRow.nonce) {
      return res.status(400).send('Nonce mismatch -- possible replay, rejecting launch.');
    }
    const messageType = payload['https://purl.imsglobal.org/spec/lti/claim/message_type'];
    const ltiVersion = payload['https://purl.imsglobal.org/spec/lti/claim/version'];
    const deploymentId = payload['https://purl.imsglobal.org/spec/lti/claim/deployment_id'];
    if (messageType !== 'LtiResourceLinkRequest' || ltiVersion !== '1.3.0') {
      return res.status(400).send(`Unsupported LTI message (type=${messageType}, version=${ltiVersion}).`);
    }
    if (deploymentId !== platform.deployment_id) {
      return res.status(400).send('Deployment ID does not match this platform\'s registration.');
    }

    const roles = payload['https://purl.imsglobal.org/spec/lti/claim/roles'] || [];
    const isInstructor = roles.some((r) => /Instructor|ContentDeveloper|Administrator/i.test(r));
    const context = payload['https://purl.imsglobal.org/spec/lti/claim/context'] || {};
    const resourceLink = payload['https://purl.imsglobal.org/spec/lti/claim/resource_link'] || {};

    const identity = {
      product: platform.product,
      tenantKey: platform.tenant_key,
      platformIssuer: platform.issuer,
      subject: payload.sub,
      name: payload.name || [payload.given_name, payload.family_name].filter(Boolean).join(' ') || 'Unknown',
      email: payload.email || null,
      role: isInstructor ? 'instructor' : 'student',
      courseId: context.id || null,
      courseTitle: context.title || context.label || null,
      resourceLinkId: resourceLink.id || null,
    };

    // Hand off into the actual product now that tutor-service has a
    // multi-tenant schema to receive it: mint the signed bridge token it
    // trusts, and land straight on the real instructor/student app for
    // this person's own tenant -- the same pages block_criterio's Moodle
    // handoff opens, just reached through a different, cross-platform door.
    const userid = await getOrAllocateUserId(platform.tenant_key, platform.issuer, payload.sub, identity.email);
    const role = isInstructor ? 'course_supervisor' : 'student';
    const bridgeToken = signBridgeToken({
      tenant: platform.tenant_key,
      userid,
      role,
      fullname: identity.name,
      email: identity.email,
    });

    const dest = new URL(isInstructor ? '/app/instructor' : '/app/home', APP_BASE_URL);
    dest.searchParams.set('t', bridgeToken);
    res.redirect(303, dest.toString());
  } catch (err) {
    console.error('[LTI launch] verification failed:', err.message);
    res.status(400).send(`Launch verification failed: ${err.message}`);
  }
});

// Proof-of-concept landing page: decodes (does not re-verify -- it's our own
// HMAC-signed token, not the platform's) the session token and shows the
// identity that came through a real, cryptographically verified LTI launch.
app.get('/lti/launched', (req, res) => {
  const token = req.query.session;
  if (!token) return res.status(400).send('Missing session token.');
  const [body, sig] = String(token).split('.');
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  if (sig !== expectedSig) return res.status(400).send('Invalid session token.');
  const identity = JSON.parse(Buffer.from(body, 'base64url').toString());

  res.set('Content-Type', 'text/html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>LTI Launch Verified</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background:#f7f8fa; margin:0; padding:40px; }
  .card { max-width:480px; margin:0 auto; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:28px; }
  h1 { font-size:18px; margin-top:0; color:#1f9d55; }
  dl { display:grid; grid-template-columns:auto 1fr; gap:6px 14px; font-size:13px; }
  dt { color:#8a94a6; font-weight:700; }
  dd { margin:0; }
</style></head>
<body>
  <div class="card">
    <h1>&#10003; LTI 1.3 launch verified</h1>
    <p style="color:#57606a; font-size:13px;">This identity came from a signature-verified id_token issued by your LMS -- not from anything the browser sent us directly.</p>
    <dl>
      <dt>Product</dt><dd>${identity.product === 'analytics' ? 'Rennix Analytics' : 'Rennix Tutor Bot'}</dd>
      <dt>Tenant</dt><dd>${identity.tenantKey}</dd>
      <dt>Platform</dt><dd>${identity.platformIssuer}</dd>
      <dt>Name</dt><dd>${identity.name}</dd>
      <dt>Email</dt><dd>${identity.email || '—'}</dd>
      <dt>Role</dt><dd>${identity.role}</dd>
      <dt>Course</dt><dd>${identity.courseTitle || identity.courseId || '—'}</dd>
    </dl>
  </div>
</body></html>`);
});

// ---- Our own JWKS (forward-compatible: not required for a pure resource-link
// launch, but most registration flows expect a tool to publish one, and it's
// needed the moment we add signed service calls back into the platform) ----
let toolJwkCache = null;
async function getToolJwk() {
  if (toolJwkCache) return toolJwkCache;
  const { publicKey } = await generateKeyPair('RS256');
  const jwk = await exportJWK(publicKey);
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  jwk.kid = 'rennix-lti-1';
  toolJwkCache = jwk;
  return jwk;
}
app.get('/lti/jwks', async (req, res) => {
  const jwk = await getToolJwk();
  res.json({ keys: [jwk] });
});

// ---- Admin: register a platform (manual registration -- no Dynamic
// Registration support yet). Gate behind a shared secret; this is bootstrap
// tooling for onboarding the first handful of institutions by hand. ----
function requireAdmin(req, res, next) {
  const provided = req.get('x-admin-secret') || req.query.secret || (req.body && req.body.secret);
  if (!ADMIN_SECRET || provided !== ADMIN_SECRET) {
    return res.status(401).send('Missing or invalid admin secret.');
  }
  next();
}

// Shared logic behind both the JSON API (curl/scripted onboarding) and the
// HTML form below (a human filling in one school's details) -- one place
// that actually writes a platform row, so they can't drift.
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

app.post('/admin/platforms', requireAdmin, (req, res) => {
  try {
    registerPlatform(req.body);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/admin/platforms', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, product, tenant_key, tenant_name, issuer, client_id, deployment_id, jwks_url, created_at FROM platforms').all());
});

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// ---- Onboarding form: a real page instead of hand-written curl commands.
// Registers the platform(s) here (same registerPlatform() the JSON API
// uses), then makes one HTTP call to tutor-service's own admin endpoint to
// set the school's OpenAI key -- that setting lives on tutor-service's side
// (per-tenant database), not here. ----
app.get('/admin', (req, res) => {
  const secret = String(req.query.secret || '');
  const registered = secret && secret === ADMIN_SECRET
    ? db.prepare('SELECT product, tenant_key, tenant_name, issuer, created_at FROM platforms ORDER BY created_at DESC').all()
    : null;

  res.set('Content-Type', 'text/html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Onboard a school</title>
<style>
  body { font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif; background:#f7f8fa; margin:0; padding:32px 16px; }
  .card { max-width:560px; margin:0 auto 20px; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:24px; }
  h1 { font-size:18px; margin:0 0 4px; }
  p.sub { color:#57606a; font-size:13px; margin:0 0 16px; }
  label { display:block; font-weight:700; font-size:13px; margin:14px 0 4px; }
  input, select { width:100%; box-sizing:border-box; padding:9px 10px; border:1px solid #ccc; border-radius:6px; font-size:13px; }
  button { margin-top:20px; padding:10px 18px; border:none; border-radius:8px; background:#d41128; color:#fff; font-weight:700; cursor:pointer; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  td, th { text-align:left; padding:6px 8px; border-bottom:1px solid #eef1f4; }
  .hint { color:#8a94a6; font-size:12px; margin-top:4px; }
  fieldset { border:1px solid #e2e8f0; border-radius:8px; margin-top:16px; padding:12px; }
  legend { font-size:12px; font-weight:700; color:#57606a; padding:0 4px; }
</style></head>
<body>
  <div class="card">
    <h1>Onboard a school</h1>
    <p class="sub">Registers this institution's LTI platform (so their Moodle/Canvas/Blackboard can launch the tool) and sets their own OpenAI key on tutor-service, in one submit.</p>
    <form method="post" action="/admin/onboard">
      <label>Admin secret</label>
      <input name="secret" type="password" value="${escapeHtml(secret)}" required>

      <label>Tenant key (slug, e.g. "htu")</label>
      <input name="tenantKey" required pattern="[a-z0-9-]+" title="lowercase letters, numbers, hyphens only">
      <label>Tenant name</label>
      <input name="tenantName" placeholder="e.g. Al-Hussein Technical University" required>

      <label>Product</label>
      <select name="product">
        <option value="tutor_bot">Rennix Tutor Bot</option>
        <option value="analytics">Rennix Analytics</option>
      </select>
      <div class="hint">Each product is registered as its own External Tool in their LMS -- run this form again with the other product to enable both.</div>

      <fieldset>
        <legend>From their LMS admin's External Tool config</legend>
        <label>Issuer</label>
        <input name="issuer" placeholder="https://their-lms.example.edu" required>
        <label>Client ID</label>
        <input name="clientId" required>
        <label>Deployment ID</label>
        <input name="deploymentId" required>
        <label>Auth login URL</label>
        <input name="authLoginUrl" required>
        <label>JWKS URL</label>
        <input name="jwksUrl" required>
      </fieldset>

      <label>Their own OpenAI API key (optional)</label>
      <input name="openaiApiKey" type="password" placeholder="Leave blank to use the shared default for now">

      <button type="submit">Onboard</button>
    </form>
  </div>
  ${registered ? `
  <div class="card">
    <h1>Already registered</h1>
    <table>
      <tr><th>Product</th><th>Tenant</th><th>Issuer</th></tr>
      ${registered.map((p) => `<tr><td>${escapeHtml(p.product)}</td><td>${escapeHtml(p.tenant_name)} (${escapeHtml(p.tenant_key)})</td><td>${escapeHtml(p.issuer)}</td></tr>`).join('')}
    </table>
  </div>` : ''}
</body></html>`);
});

app.post('/admin/onboard', requireAdmin, async (req, res) => {
  const { tenantKey, tenantName, product, issuer, clientId, deploymentId, authLoginUrl, jwksUrl, openaiApiKey, secret } = req.body;

  try {
    registerPlatform({ product, tenantKey, tenantName, issuer, clientId, deploymentId, authLoginUrl, jwksUrl });
  } catch (err) {
    return res.status(400).send(`Platform registration failed: ${escapeHtml(err.message)}`);
  }

  let keyStatus = 'skipped (no key entered)';
  if (openaiApiKey && openaiApiKey.trim()) {
    if (!TENANT_ADMIN_SECRET) {
      keyStatus = 'NOT set -- TENANT_ADMIN_SECRET is not configured on this service';
    } else {
      try {
        const resp = await fetch(`${APP_BASE_URL}/admin/tenant-settings`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ secret: TENANT_ADMIN_SECRET, tenant: tenantKey, openai_api_key: openaiApiKey.trim() }),
        });
        keyStatus = resp.ok ? 'set successfully' : `failed (tutor-service returned ${resp.status})`;
      } catch (err) {
        keyStatus = `failed (${err.message})`;
      }
    }
  }

  res.set('Content-Type', 'text/html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Onboarding result</title>
<style>body{font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:#f7f8fa;margin:0;padding:32px 16px;}
.card{max-width:480px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:24px;}
h1{font-size:18px;color:#1f9d55;margin-top:0;}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:13px;}
dt{color:#8a94a6;font-weight:700;}dd{margin:0;}
a{color:#d41128;}</style></head>
<body><div class="card">
  <h1>&#10003; Onboarded</h1>
  <dl>
    <dt>Tenant</dt><dd>${escapeHtml(tenantName)} (${escapeHtml(tenantKey)})</dd>
    <dt>Product</dt><dd>${escapeHtml(product)}</dd>
    <dt>Platform</dt><dd>registered</dd>
    <dt>OpenAI key</dt><dd>${escapeHtml(keyStatus)}</dd>
  </dl>
  <p><a href="/admin?secret=${encodeURIComponent(secret)}">&larr; Back</a></p>
</div></body></html>`);
});

app.listen(PORT, () => console.log(`rennix-lti listening on ${PORT}`));
