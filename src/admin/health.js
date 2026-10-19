const express = require('express');
const { db } = require('../db');
const { requireAdmin } = require('./auth');
const { asyncRoute } = require('../util/asyncRoute');
const { listKeys, nextScheduledRotation } = require('../security/toolKeys');

// ---- What went wrong recently, per school ----
// Counts from the admin audit log over the last ?minutes= (default 60, max 7
// days): successful launches, and each kind of failure that means a school's
// students or grades are affected. For scripts/monitor.js and operators.

const FAILURE_EVENTS = [
  'lti_jwt_verification_failed', 'lti_nonce_mismatch', 'lti_deployment_mismatch', 'lti_browser_check_failed',
  'ags_score_push_failed', 'nrps_sync_failed', 'deep_link_response_failed', 'deep_link_content_fetch_failed',
  'dynamic_registration_failed', 'admin_login_failed',
];

const router = express.Router();

router.get('/admin/health/summary', requireAdmin, asyncRoute(async (req, res) => {
  const minutes = Math.min(Math.max(Number(req.query.minutes) || 60, 1), 7 * 24 * 60);
  const since = Date.now() - minutes * 60 * 1000;
  const rows = await db.all(
    `SELECT event, detail FROM admin_audit_log WHERE created_at > ? AND (event = 'lti_launch_success' OR event IN (${FAILURE_EVENTS.map(() => '?').join(', ')}))`,
    [since, ...FAILURE_EVENTS]
  );
  const failures = {};
  const schools = {};
  for (const { event, detail } of rows) {
    const tenant = (/(?:^|\s)tenant=([a-z0-9-]+)/.exec(detail || '') || [])[1] || 'unknown';
    const s = (schools[tenant] ||= { launches: 0, failures: {} });
    if (event === 'lti_launch_success') { s.launches += 1; continue; }
    failures[event] = (failures[event] || 0) + 1;
    s.failures[event] = (s.failures[event] || 0) + 1;
  }
  const active = (await listKeys()).find((k) => k.status === 'active');
  const next = nextScheduledRotation(active);
  res.json({
    minutes, since: new Date(since).toISOString(), failures, schools,
    signing_key: active ? { kid: active.kid, next_rotation: next ? new Date(next).toISOString() : null } : null,
  });
}));

module.exports = { router, FAILURE_EVENTS };
