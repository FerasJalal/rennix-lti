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

// Our own signing key, for the compact session token we hand to the app
// after a verified launch (HMAC is enough here -- this token never leaves
// our own infrastructure, unlike the platform's id_token which does).
function signSessionToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));

// ---- Step 1: OIDC third-party initiated login ----
app.get('/lti/login', (req, res) => {
  sweepExpiredStates();
  const { iss, login_hint, target_link_uri, client_id, lti_message_hint } = req.query;
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
});

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

    const sessionToken = signSessionToken(identity);
    // Hand off into the actual product. For this MVP, land on a page that
    // proves the verified identity round-tripped correctly; wiring this into
    // tutor-service's real student/instructor app is the next step once the
    // multi-tenant schema exists there to receive it.
    const dest = new URL('/lti/launched', `${req.protocol}://${req.get('host')}`);
    dest.searchParams.set('session', sessionToken);
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
  if (!ADMIN_SECRET || req.get('x-admin-secret') !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Missing or invalid x-admin-secret header.' });
  }
  next();
}

app.post('/admin/platforms', requireAdmin, (req, res) => {
  const { product, tenantKey, tenantName, issuer, clientId, deploymentId, authLoginUrl, authTokenUrl, jwksUrl } = req.body;
  const missing = ['product', 'tenantKey', 'tenantName', 'issuer', 'clientId', 'deploymentId', 'authLoginUrl', 'jwksUrl']
    .filter((k) => !req.body[k]);
  if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(', ')}` });
  if (!['analytics', 'tutor_bot'].includes(product)) {
    return res.status(400).json({ error: "product must be 'analytics' or 'tutor_bot'" });
  }

  db.prepare(
    `INSERT INTO platforms (product, tenant_key, tenant_name, issuer, client_id, deployment_id, auth_login_url, auth_token_url, jwks_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(issuer, client_id) DO UPDATE SET
       product = excluded.product, tenant_key = excluded.tenant_key, tenant_name = excluded.tenant_name,
       deployment_id = excluded.deployment_id, auth_login_url = excluded.auth_login_url,
       auth_token_url = excluded.auth_token_url, jwks_url = excluded.jwks_url`
  ).run(product, tenantKey, tenantName, issuer, clientId, deploymentId, authLoginUrl, authTokenUrl || null, jwksUrl, Date.now());

  res.json({ ok: true });
});

app.get('/admin/platforms', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, product, tenant_key, tenant_name, issuer, client_id, deployment_id, jwks_url, created_at FROM platforms').all());
});

app.listen(PORT, () => console.log(`rennix-lti listening on ${PORT}`));
