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
const { createRemoteJWKSet, jwtVerify, SignJWT, generateKeyPair, exportJWK, importPKCS8, exportPKCS8 } = require('jose');

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

// Never pass raw secrets, tokens, or full request bodies into `detail` --
// this table exists to answer "who did what, when", not to reconstruct
// credentials from logs.
function logAdminEvent(event, detail, req) {
  const ip = req ? (req.get('x-forwarded-for') || req.socket?.remoteAddress || '') : '';
  db.prepare('INSERT INTO admin_audit_log (event, detail, ip, created_at) VALUES (?, ?, ?, ?)')
    .run(event, detail || null, String(ip).split(',')[0].trim(), Date.now());
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
// ---- LTI role -> internal role mapping ----
// LTI 1.3 roles are full IMS vocabulary URNs (context roles such as
// .../membership#Instructor, or system roles such as .../system/person#Administrator),
// not free text. Matching them precisely -- instead of the old blanket
// /Instructor|ContentDeveloper|Administrator/i regex, which collapsed every one of
// those into a single "instructor" bucket with identical rights -- is what lets
// different LTI roles carry different actual permissions. Two instructor-tier
// roles already exist on tutor-service's side: 'course_supervisor' (full rights,
// including the Verification queue) and 'section_instructor' (content/analytics
// access, no verification authority). This is where that split gets decided, not
// left implicit at each call site.
const LTI_ROLE_SUPERVISOR_SUFFIXES = ['membership#Instructor', 'system/person#Administrator', 'institution/person#Administrator'];
const LTI_ROLE_SECTION_INSTRUCTOR_SUFFIXES = ['membership#ContentDeveloper', 'membership#TeachingAssistant'];
function mapLtiRolesToInternalRole(ltiRoles) {
  const roles = ltiRoles || [];
  if (roles.some((r) => LTI_ROLE_SUPERVISOR_SUFFIXES.some((suffix) => r.endsWith(suffix)))) return 'course_supervisor';
  // TeachingAssistant previously matched nothing in the old regex and silently fell
  // through to 'student' -- a TA launching the tool got no instructor tooling at all.
  if (roles.some((r) => LTI_ROLE_SECTION_INSTRUCTOR_SUFFIXES.some((suffix) => r.endsWith(suffix)))) return 'section_instructor';
  return 'student';
}

function signSessionToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

// ---- Admin session cookie -- replaces passing ADMIN_SECRET around in query
// strings/POST bodies on every request. A human logs in once (POST
// /admin/login, secret in the body only, never the URL), gets a signed,
// HttpOnly, short-lived cookie back, and that carries them from then on.
// x-admin-secret header auth stays available separately for scripted/API use
// (curl, CI), where a header doesn't end up in browser history or Referer
// headers the way a query string does. ----
const ADMIN_SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000;

function signAdminSession() {
  const body = Buffer.from(JSON.stringify({ type: 'admin', exp: Date.now() + ADMIN_SESSION_MAX_AGE_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyAdminSession(token) {
  if (!token || typeof token !== 'string') return false;
  const [body, sig] = token.split('.');
  if (!body || !sig) return false;
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  let parsed;
  try { parsed = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch (e) { return false; }
  return parsed.type === 'admin' && typeof parsed.exp === 'number' && parsed.exp > Date.now();
}

function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

// ---- Rate limiting ----
// Per-process, in-memory sliding window keyed by IP + endpoint name. Fine for a
// single instance; becomes inaccurate across multiple replicas behind a load
// balancer -- same caveat as the state/nonce store, both move to a shared store
// (Redis) together if this ever runs multi-replica. Hand-rolled rather than a
// dependency to match how the rest of this file already does rate limiting
// (see tutor-service's checkAndRecordRateLimit, same idea against SQLite).
const rateLimitBuckets = new Map(); // "name:ip" -> timestamps[]
function isRateLimited(key, maxRequests, windowMs) {
  const now = Date.now();
  const bucket = (rateLimitBuckets.get(key) || []).filter((t) => now - t < windowMs);
  bucket.push(now);
  rateLimitBuckets.set(key, bucket);
  return bucket.length > maxRequests;
}
function rateLimit(name, maxRequests, windowMs) {
  return (req, res, next) => {
    const ip = (req.get('x-forwarded-for') || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
    if (isRateLimited(`${name}:${ip}`, maxRequests, windowMs)) {
      return res.status(429).send('Too many requests. Try again shortly.');
    }
    next();
  };
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
const ltiEntryRateLimit = rateLimit('lti-login', 30, 60 * 1000);
app.get('/lti/login', ltiEntryRateLimit, handleLtiLogin);
app.post('/lti/login', ltiEntryRateLimit, handleLtiLogin);

// ---- Step 2: launch -- verify the platform's signed id_token ----
app.post('/lti/launch', rateLimit('lti-launch', 30, 60 * 1000), async (req, res) => {
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
      logAdminEvent('lti_nonce_mismatch', `platform_id=${platform.id} tenant=${platform.tenant_key}`, req);
      return res.status(400).send('Nonce mismatch -- possible replay, rejecting launch.');
    }
    const messageType = payload['https://purl.imsglobal.org/spec/lti/claim/message_type'];
    const ltiVersion = payload['https://purl.imsglobal.org/spec/lti/claim/version'];
    const deploymentId = payload['https://purl.imsglobal.org/spec/lti/claim/deployment_id'];
    if (ltiVersion !== '1.3.0' || !['LtiResourceLinkRequest', 'LtiDeepLinkingRequest'].includes(messageType)) {
      logAdminEvent('lti_unsupported_message', `type=${messageType} version=${ltiVersion} platform_id=${platform.id}`, req);
      return res.status(400).send(`Unsupported LTI message (type=${messageType}, version=${ltiVersion}).`);
    }
    if (deploymentId !== platform.deployment_id) {
      logAdminEvent('lti_deployment_mismatch', `platform_id=${platform.id} tenant=${platform.tenant_key}`, req);
      return res.status(400).send('Deployment ID does not match this platform\'s registration.');
    }

    const roles = payload['https://purl.imsglobal.org/spec/lti/claim/roles'] || [];
    const internalRole = mapLtiRolesToInternalRole(roles);
    const isInstructor = internalRole !== 'student';

    // Deep Linking: the platform is asking the instructor to pick content
    // *inside* Rennix, not launching an already-created activity -- a
    // completely different response shape (a signed content-selection JWT
    // POSTed back to Moodle, not a redirect into the app). Branches off
    // before any of the resource-link-specific handling below.
    if (messageType === 'LtiDeepLinkingRequest') {
      return handleDeepLinkingRequest(req, res, payload, platform, isInstructor);
    }

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

    // "Rennix Analytics" is an instructor-only product -- a student
    // launching it should see that plainly, not silently land on the
    // generic student home page as if they'd launched the (student-facing)
    // Tutor Bot instead. That would make Analytics look like it has no real
    // boundary at all, which defeats the point of it being sold as its own
    // separate, instructor-only tool.
    if (platform.product === 'analytics' && !isInstructor) {
      logAdminEvent('lti_analytics_blocked_student', `tenant=${platform.tenant_key}`, req);
      return res.set('Content-Type', 'text/html').status(403).send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Instructor access only</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background:#f7f8fa; margin:0; padding:40px; }
  .card { max-width:440px; margin:0 auto; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:28px; text-align:center; }
  h1 { font-size:17px; margin:0 0 8px; color:#1a1a1a; }
  p { color:#57606a; font-size:13px; line-height:1.6; margin:0; }
</style></head>
<body>
  <div class="card">
    <h1>Instructor access only</h1>
    <p>Rennix Analytics is an instructor tool. Your account (${escapeHtml(identity.name)}) is signed in as a student in this course, so there's nothing to show here.</p>
  </div>
</body></html>`);
    }

    // Hand off into the actual product now that tutor-service has a
    // multi-tenant schema to receive it: mint the signed bridge token it
    // trusts, and land straight on the real instructor/student app for
    // this person's own tenant -- the same pages block_criterio's Moodle
    // handoff opens, just reached through a different, cross-platform door.
    const userid = await getOrAllocateUserId(platform.tenant_key, platform.issuer, payload.sub, identity.email);
    const role = internalRole;
    const bridgeToken = signBridgeToken({
      tenant: platform.tenant_key,
      userid,
      role,
      fullname: identity.name,
      email: identity.email,
      // Which of the two independently-registered External Tools this
      // launch came through -- 'analytics' vs 'tutor_bot'. tutor-service
      // uses this to show only what that product actually includes (an
      // "analytics"-only launch never sees the chat/quiz-authoring tools
      // that belong to the separate "tutor_bot" product).
      product: platform.product,
      // Both already extracted from the verified id_token above but
      // previously never carried past this point -- tutor-service had no
      // verified knowledge of which Moodle course or which specific
      // resource-link activity a launch came from, only tenant/user/role.
      // Threaded through now so that context is actually available and
      // auditable on the receiving side, not silently dropped.
      courseId: identity.courseId,
      resourceLinkId: identity.resourceLinkId,
    });

    const nrpsClaim = payload['https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice'];
    logAdminEvent('lti_launch_success', `tenant=${platform.tenant_key} product=${platform.product} role=${role} course=${identity.courseId || 'none'} resourceLink=${identity.resourceLinkId || 'none'} nrps=${nrpsClaim ? 'yes' : 'no'}`, req);

    // If this activity was created via Deep Linking with a specific lecture
    // chosen, every subsequent resource-link launch of it carries that choice
    // back in the custom claim -- route straight into that lecture (students)
    // or its analytics (instructors) instead of the generic landing page.
    const customClaim = payload['https://purl.imsglobal.org/spec/lti/claim/custom'] || {};
    const deepLinkedLectureId = customClaim.rennix_lecture_id || null;
    let destPath = isInstructor ? '/app/instructor' : '/app/home';
    if (deepLinkedLectureId) {
      destPath = isInstructor ? '/instructor/video-analytics' : `/lecture/${encodeURIComponent(deepLinkedLectureId)}`;
    }
    const dest = new URL(destPath, APP_BASE_URL);
    dest.searchParams.set('t', bridgeToken);
    if (deepLinkedLectureId && isInstructor) dest.searchParams.set('lecture_id', deepLinkedLectureId);
    res.redirect(303, dest.toString());

    // Fire-and-forget: never delay the user's redirect on a roster sync. Only
    // instructor-tier launches trigger it -- a student's own launch has no
    // more course-membership visibility than what NRPS already grants any
    // launch, but there's no reason to fetch+push the whole roster on every
    // single student click when one instructor launch a day covers it.
    if (nrpsClaim && nrpsClaim.context_memberships_url && isInstructor) {
      syncRosterViaNrps(platform, nrpsClaim.context_memberships_url).catch((err) => {
        logAdminEvent('nrps_sync_failed', `tenant=${platform.tenant_key} error=${err.message}`.slice(0, 500), null);
      });
    }
  } catch (err) {
    // err.message only -- never the id_token itself, which is the platform's
    // signed credential for this user, not something to persist in a log.
    logAdminEvent('lti_jwt_verification_failed', err.message, req);
    console.error('[LTI launch] verification failed:', err.message);
    res.status(400).send(`Launch verification failed: ${err.message}`);
  }
});

// ---- Deep Linking: let an instructor pick real content inside Rennix while
// adding the activity in Moodle, instead of creating one generic External Tool
// activity and always landing on the same page. Real content only -- the
// picker queries tutor-service's actual lecture list, nothing invented. ----
async function fetchTenantLectures(tenantKey) {
  const url = new URL('/content/lectures', APP_BASE_URL);
  url.searchParams.set('tenant', tenantKey);
  const resp = await fetch(url, { headers: { 'x-tenant-admin-secret': TENANT_ADMIN_SECRET } });
  if (!resp.ok) throw new Error(`tutor-service /content/lectures returned ${resp.status}`);
  const data = await resp.json();
  return data.lectures || [];
}

function renderDeepLinkPicker(sessionId, platform, pickerItems, fetchError) {
  const productLabel = platform.product === 'analytics' ? 'Rennix Analytics' : 'Rennix Tutor Bot';
  const generalTitle = platform.product === 'analytics' ? 'Rennix Analytics dashboard (whole course)' : 'General Tutor Bot (course-wide, no specific lecture)';
  const generalLink = `/lti/deep-link/select?session=${sessionId}&title=${encodeURIComponent(generalTitle)}`;
  const items = pickerItems.map((it) => {
    const label = `${it.chapterTitle} — ${it.title}`;
    const href = `/lti/deep-link/select?session=${sessionId}&lecture_id=${encodeURIComponent(it.lecture_id)}&title=${encodeURIComponent(label)}`;
    return `<a class="item" href="${href}">${escapeHtml(label)}</a>`;
  }).join('');
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Add ${escapeHtml(productLabel)}</title>
<style>
  body { font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif; background:#f7f8fa; margin:0; padding:32px 16px; }
  .card { max-width:560px; margin:0 auto; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:24px; }
  h1 { font-size:18px; margin:0 0 4px; }
  p.sub { color:#57606a; font-size:13px; margin:0 0 16px; }
  .item { display:block; padding:10px 12px; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:8px; text-decoration:none; color:#1a1a1a; font-size:13px; }
  .item:hover { border-color:#d41128; }
  .item.default { font-weight:700; margin-bottom:16px; }
  .err { color:#a10f22; font-size:12px; margin-bottom:12px; }
  .list { max-height:360px; overflow-y:auto; }
</style></head>
<body>
  <div class="card">
    <h1>Add ${escapeHtml(productLabel)}</h1>
    <p class="sub">Choose what this activity should link to.</p>
    ${fetchError ? `<div class="err">Couldn't load the lecture list (${escapeHtml(fetchError)}) -- only the general option is available.</div>` : ''}
    <a class="item default" href="${generalLink}">${escapeHtml(generalTitle)}</a>
    ${items ? `<div class="list">${items}</div>` : ''}
  </div>
</body></html>`;
}

async function handleDeepLinkingRequest(req, res, payload, platform, isInstructor) {
  if (!isInstructor) {
    logAdminEvent('deep_link_blocked_student', `tenant=${platform.tenant_key}`, req);
    return res.status(403).send('Only instructors can select content to add to a course.');
  }
  const dlSettings = payload['https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings'];
  if (!dlSettings || !dlSettings.deep_link_return_url) {
    return res.status(400).send('Missing deep linking settings in the launch.');
  }

  const sessionId = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO lti_dl_sessions (id, platform_id, deep_link_return_url, data, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(sessionId, platform.id, dlSettings.deep_link_return_url, dlSettings.data || null, Date.now());

  let pickerItems = [];
  let fetchError = null;
  if (platform.product === 'tutor_bot') {
    try {
      pickerItems = await fetchTenantLectures(platform.tenant_key);
    } catch (err) {
      fetchError = err.message;
      logAdminEvent('deep_link_content_fetch_failed', `tenant=${platform.tenant_key} error=${err.message}`, req);
    }
  }

  logAdminEvent('deep_link_picker_shown', `tenant=${platform.tenant_key} product=${platform.product} items=${pickerItems.length}`, req);
  res.set('Content-Type', 'text/html').send(renderDeepLinkPicker(sessionId, platform, pickerItems, fetchError));
}

app.get('/lti/deep-link/select', async (req, res) => {
  try {
    const { session, lecture_id, title } = req.query;
    const dlSession = db.prepare('SELECT * FROM lti_dl_sessions WHERE id = ?').get(session);
    if (!dlSession) return res.status(400).send('Unknown or expired selection session -- restart from Moodle.');
    db.prepare('DELETE FROM lti_dl_sessions WHERE id = ?').run(session); // single-use
    if (Date.now() - dlSession.created_at > 10 * 60 * 1000) {
      return res.status(400).send('This selection session expired -- restart from Moodle.');
    }

    const platform = db.prepare('SELECT * FROM platforms WHERE id = ?').get(dlSession.platform_id);
    if (!platform) return res.status(400).send('Platform no longer registered.');

    const contentItem = {
      type: 'ltiResourceLink',
      title: title ? String(title).slice(0, 200) : (platform.product === 'analytics' ? 'Rennix Analytics' : 'Rennix Tutor Bot'),
      url: `${req.protocol}://${req.get('host')}/lti/launch`,
    };
    if (lecture_id) contentItem.custom = { rennix_lecture_id: String(lecture_id) };

    const { privateKey, kid } = await getToolKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const responseJwt = await new SignJWT({
      'https://purl.imsglobal.org/spec/lti/claim/deployment_id': platform.deployment_id,
      'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiDeepLinkingResponse',
      'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
      'https://purl.imsglobal.org/spec/lti-dl/claim/content_items': [contentItem],
      ...(dlSession.data ? { 'https://purl.imsglobal.org/spec/lti-dl/claim/data': dlSession.data } : {}),
    })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(platform.client_id)
      .setAudience(platform.issuer)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    logAdminEvent('deep_link_response_sent', `tenant=${platform.tenant_key} product=${platform.product} lecture_id=${lecture_id || 'none'}`, req);

    res.set('Content-Type', 'text/html').send(`<!doctype html><html><body onload="document.forms[0].submit()">
  <form method="POST" action="${escapeHtml(dlSession.deep_link_return_url)}">
    <input type="hidden" name="JWT" value="${escapeHtml(responseJwt)}">
  </form>
  <p>Adding content to your course&hellip;</p>
</body></html>`);
  } catch (err) {
    logAdminEvent('deep_link_response_failed', err.message, req);
    res.status(500).send(`Deep linking failed: ${err.message}`);
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

// ---- Our own key pair ----
// This used to regenerate a random key pair on every call and only ever kept
// the public half -- which meant /lti/jwks changed on every restart (breaking
// any platform's cached copy of it) and there was no private key anywhere to
// actually sign anything with. Needed for real now: NRPS/AGS service calls
// require this tool to sign its own JWT client assertions, which means the
// key pair has to be stable across restarts, not regenerated each time.
// Persisted in this service's own database (same trust boundary as every
// other secret this service already holds -- ADMIN_SECRET, LTI_BRIDGE_SECRET
// -- none of which are encrypted at rest either).
let toolKeyPairCache = null; // { privateKey: CryptoKey, publicJwk, kid }
async function getToolKeyPair() {
  if (toolKeyPairCache) return toolKeyPairCache;
  const row = db.prepare('SELECT * FROM tool_keys ORDER BY created_at ASC LIMIT 1').get();
  if (row) {
    const privateKey = await importPKCS8(row.private_key_pem, 'RS256');
    toolKeyPairCache = { privateKey, publicJwk: JSON.parse(row.public_jwk), kid: row.kid };
    return toolKeyPairCache;
  }
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const kid = 'rennix-lti-' + crypto.randomBytes(4).toString('hex');
  const jwk = await exportJWK(publicKey);
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  jwk.kid = kid;
  const pem = await exportPKCS8(privateKey);
  db.prepare('INSERT INTO tool_keys (kid, private_key_pem, public_jwk, created_at) VALUES (?, ?, ?, ?)')
    .run(kid, pem, JSON.stringify(jwk), Date.now());
  toolKeyPairCache = { privateKey, publicJwk: jwk, kid };
  return toolKeyPairCache;
}
app.get('/lti/jwks', async (req, res) => {
  const { publicJwk } = await getToolKeyPair();
  res.json({ keys: [publicJwk] });
});

// ---- LTI Advantage service calls (NRPS today, AGS later reuses the same
// token exchange) ----
// A service call means: sign a short-lived JWT asserting this tool's own
// identity (client_id) using OUR private key, trade it for an OAuth access
// token at the platform's token endpoint, then use that token as a normal
// Bearer credential against the actual service URL. Cached per
// platform+scope until shortly before expiry, rather than requesting a fresh
// token on every single service call -- the standard pattern for LTI
// Advantage service calls (roadmap item: service-token caching).
const serviceTokenCache = new Map(); // "platformId:scope" -> { token, expiresAt }
async function getServiceAccessToken(platform, scope) {
  const cacheKey = `${platform.id}:${scope}`;
  const cached = serviceTokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 30_000) return cached.token;

  if (!platform.auth_token_url) {
    throw new Error(`Platform ${platform.tenant_key} has no auth_token_url registered -- cannot request a service token.`);
  }
  const { privateKey, kid } = await getToolKeyPair();
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({
    sub: platform.client_id,
    aud: platform.auth_token_url,
    jti: crypto.randomBytes(16).toString('hex'),
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(platform.client_id)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion,
    scope,
  });
  const resp = await fetch(platform.auth_token_url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Token request failed (${resp.status}): ${text.slice(0, 200)}`);
  }
  const data = await resp.json();
  serviceTokenCache.set(cacheKey, { token: data.access_token, expiresAt: Date.now() + (data.expires_in || 3600) * 1000 });
  return data.access_token;
}

// ---- Names and Role Provisioning Service ----
// The launch-time roster (who has actually clicked into the tool) is a subset
// of the real course membership -- NRPS is what lets the instructor dashboard
// eventually distinguish "enrolled but never used the tutor" from "not
// enrolled at all", instead of only ever knowing about students who happened
// to launch.
const NRPS_SCOPE = 'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly';
async function fetchCourseMembership(membershipsUrl, accessToken) {
  const resp = await fetch(membershipsUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.ims.lti-nrps.v2.membershipcontainer+json',
    },
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`NRPS request failed (${resp.status}): ${text.slice(0, 200)}`);
  }
  return resp.json(); // { id, context, members: [{ user_id, roles, status, name, email, ... }] }
}

// Fire-and-forget from /lti/launch -- never blocks the student/instructor's
// redirect on a roster sync. Pushes the full membership into tutor-service via
// the same /students/sync endpoint the legacy Moodle-native path uses, so both
// roster sources land in one place rather than needing two parallel systems.
async function syncRosterViaNrps(platform, membershipsUrl) {
  const accessToken = await getServiceAccessToken(platform, NRPS_SCOPE);
  const data = await fetchCourseMembership(membershipsUrl, accessToken);
  const members = data.members || [];

  const students = [];
  for (const m of members) {
    const roles = m.roles || [];
    const internalRole = mapLtiRolesToInternalRole(roles);
    const userid = await getOrAllocateUserId(platform.tenant_key, platform.issuer, m.user_id, m.email);
    students.push({
      userid,
      username: m.email ? m.email.split('@')[0] : `nrps-${m.user_id}`,
      fullname: m.name || [m.given_name, m.family_name].filter(Boolean).join(' ') || 'Unknown',
      email: m.email || null,
      role: internalRole,
    });
  }

  if (!TENANT_ADMIN_SECRET) {
    throw new Error('TENANT_ADMIN_SECRET is not configured -- cannot push the roster to tutor-service.');
  }
  const resp = await fetch(`${APP_BASE_URL}/students/sync`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-tenant-admin-secret': TENANT_ADMIN_SECRET },
    body: JSON.stringify({ tenant: platform.tenant_key, students }),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`tutor-service /students/sync returned ${resp.status}: ${text.slice(0, 200)}`);
  }
  logAdminEvent('nrps_roster_synced', `tenant=${platform.tenant_key} members=${students.length}`, null);
}

// ---- Admin: register a platform (manual registration -- no Dynamic
// Registration support yet). Two ways in: a browser-facing session cookie
// (see /admin/login below) for humans, or the x-admin-secret header for
// scripted/API callers. Deliberately does NOT accept the secret from
// req.query or req.body anymore -- a query string ends up in browser
// history, proxy/access logs, and Referer headers; a POST body posted over
// TLS is safer but still means re-sending the secret on every single call
// instead of authenticating once. ----
function requireAdmin(req, res, next) {
  const headerSecret = req.get('x-admin-secret');
  if (ADMIN_SECRET && headerSecret && headerSecret === ADMIN_SECRET) return next();
  const cookies = parseCookies(req.headers.cookie);
  if (verifyAdminSession(cookies.admin_session)) return next();
  if (req.method === 'GET' && req.accepts('html')) return res.redirect('/admin/login');
  return res.status(401).json({ error: 'Missing or invalid admin credentials.' });
}

app.get('/admin/login', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (verifyAdminSession(cookies.admin_session)) return res.redirect('/admin');
  res.set('Content-Type', 'text/html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Admin sign-in</title>
<style>
  body { font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif; background:#f7f8fa; margin:0; padding:80px 16px; }
  .card { max-width:360px; margin:0 auto; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:24px; }
  h1 { font-size:18px; margin:0 0 16px; }
  label { display:block; font-weight:700; font-size:13px; margin:0 0 6px; }
  input { width:100%; box-sizing:border-box; padding:9px 10px; border:1px solid #ccc; border-radius:6px; font-size:13px; }
  button { margin-top:16px; width:100%; padding:10px 18px; border:none; border-radius:8px; background:#d41128; color:#fff; font-weight:700; cursor:pointer; }
  .err { color:#a10f22; font-size:13px; margin-top:10px; }
</style></head>
<body>
  <div class="card">
    <h1>Admin sign-in</h1>
    <form method="post" action="/admin/login">
      <label>Admin secret</label>
      <input name="secret" type="password" required autofocus>
      <button type="submit">Sign in</button>
    </form>
    ${req.query.error ? '<div class="err">Invalid secret.</div>' : ''}
  </div>
</body></html>`);
});

app.post('/admin/login', rateLimit('admin-login', 5, 15 * 60 * 1000), (req, res) => {
  const provided = req.body && req.body.secret;
  if (!ADMIN_SECRET || provided !== ADMIN_SECRET) {
    logAdminEvent('admin_login_failed', null, req);
    return res.redirect('/admin/login?error=1');
  }
  logAdminEvent('admin_login_success', null, req);
  res.cookie('admin_session', signAdminSession(), {
    httpOnly: true, secure: true, sameSite: 'strict', maxAge: ADMIN_SESSION_MAX_AGE_MS,
  });
  res.redirect('/admin');
});

app.post('/admin/logout', (req, res) => {
  res.clearCookie('admin_session');
  res.redirect('/admin/login');
});

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
    logAdminEvent('platform_registered', `${req.body.product} / ${req.body.tenantKey}`, req);
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
  const cookies = parseCookies(req.headers.cookie);
  if (!verifyAdminSession(cookies.admin_session)) return res.redirect('/admin/login');
  const registered = db.prepare('SELECT product, tenant_key, tenant_name, issuer, created_at FROM platforms ORDER BY created_at DESC').all();

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
  .signout { text-align:right; max-width:560px; margin:0 auto 8px; }
  .signout button { background:none; border:none; color:#8a94a6; font-size:12px; cursor:pointer; text-decoration:underline; padding:0; margin:0; }
</style></head>
<body>
  <div class="signout"><form method="post" action="/admin/logout"><button type="submit">Sign out</button></form></div>
  <div class="card">
    <h1>Onboard a school</h1>
    <p class="sub">Registers this institution's LTI platform (so their Moodle/Canvas/Blackboard can launch the tool) and sets their own OpenAI key on tutor-service, in one submit.</p>
    <form method="post" action="/admin/onboard">
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
  ${registered.length ? `
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
  const { tenantKey, tenantName, product, issuer, clientId, deploymentId, authLoginUrl, jwksUrl, openaiApiKey } = req.body;

  try {
    registerPlatform({ product, tenantKey, tenantName, issuer, clientId, deploymentId, authLoginUrl, jwksUrl });
    logAdminEvent('platform_onboarded', `${product} / ${tenantKey}`, req);
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
          headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-tenant-admin-secret': TENANT_ADMIN_SECRET },
          body: new URLSearchParams({ tenant: tenantKey, openai_api_key: openaiApiKey.trim() }),
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
  <p><a href="/admin">&larr; Back</a></p>
</div></body></html>`);
});

app.listen(PORT, () => console.log(`rennix-lti listening on ${PORT}`));
