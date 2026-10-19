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
//
// See src/ for the actual route/business-logic modules -- this file is only
// the composition root (middleware + router mounting + listen).

const express = require('express');
const cors = require('cors');
const { PORT } = require('./src/config');
const { db } = require('./src/db');
const log = require('./src/log');

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

// Proves the DB is actually reachable, not just that the process is up --
// a lost Postgres connection otherwise wouldn't surface until the first real
// request hit it. Load balancers use this to take a broken instance out.
app.get('/health', async (req, res) => {
  try {
    await db.one('SELECT 1 AS ok');
    res.json({ ok: true });
  } catch (err) {
    log.error('[health] DB check failed:', err.message);
    res.status(503).json({ ok: false, error: 'database unreachable' });
  }
});

app.use(require('./src/security/toolKeys').router);
app.use(require('./src/lti/login').router);
app.use(require('./src/lti/launch').router);
app.use(require('./src/lti/deepLinking').router);
app.use(require('./src/lti/dynamicRegistration').router);
app.use(require('./src/lti/ags').router);
app.use(require('./src/lti/playback').router);
app.use(require('./src/lti/launchedDebugPage').router);
app.use(require('./src/admin/auth').router);
app.use(require('./src/admin/platforms').router);
app.use(require('./src/admin/onboard').router);
app.use(require('./src/admin/auditView').router);
app.use(require('./src/admin/keys').router);
app.use(require('./src/admin/dataRights').router);
app.use(require('./src/admin/health').router);

// Last resort for errors that escaped a route (see src/util/asyncRoute.js):
// log the detail, show the user nothing internal.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  log.error(`[error] ${req.method} ${req.path}:`, err.message);
  if (!res.headersSent) res.status(500).send('Something went wrong. Please try again.');
});

// Housekeeping every instance runs; each job is safe to run concurrently.
const HOUSEKEEPING_INTERVAL_MS = 60 * 60 * 1000;
function startHousekeeping() {
  const { rotateIfDue } = require('./src/security/toolKeys');
  const { sweepRateLimits } = require('./src/rateLimit');
  const { logAdminEvent } = require('./src/audit');
  const run = () => {
    rotateIfDue(logAdminEvent).catch((err) => log.error('[housekeeping] key rotation check failed:', err.message));
    sweepRateLimits().catch((err) => log.error('[housekeeping] rate-limit sweep failed:', err.message));
  };
  run();
  setInterval(run, HOUSEKEEPING_INTERVAL_MS).unref();
}

async function start() {
  const { init } = require('./src/db');
  await init();
  await require('./src/security/toolKeys').ensureKeys();
  startHousekeeping();
  app.listen(PORT, () => log.info(`rennix-lti listening on ${PORT}`));
}

if (require.main === module) {
  start().catch((err) => {
    log.error('[startup] failed:', err.message);
    process.exit(1);
  });
}

module.exports = app;
