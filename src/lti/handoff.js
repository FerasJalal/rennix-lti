const crypto = require('crypto');
const express = require('express');
const { asyncRoute } = require('../util/asyncRoute');
const { redeemHandoffCode } = require('../db');
const { logAdminEvent } = require('../audit');
const { rateLimit } = require('../rateLimit');
const { LTI_BRIDGE_SECRET } = require('../config');

// ---- One-time launch handoff: tutor-service redeems the code ----
// After a verified launch, launch.js stores the launch details and sends the
// browser to tutor-service with only a random code (?c=). tutor-service's
// server then calls this endpoint, server to server, to swap the code for the
// details. The code works once and for 60 seconds, so a URL copied from
// history, a log or a Referer header is useless, and the person's name and
// email never travel in a URL. The caller proves itself with the bridge
// secret both services already share, sent as a Bearer token.
const router = express.Router();

function callerIsTrusted(req) {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  if (!LTI_BRIDGE_SECRET || !m) return false;
  const given = Buffer.from(m[1]);
  const expected = Buffer.from(LTI_BRIDGE_SECRET);
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

router.post('/lti/handoff/redeem', rateLimit('lti-handoff', 120, 60 * 1000), asyncRoute(async (req, res) => {
  if (!callerIsTrusted(req)) return res.status(401).json({ error: 'Unauthorized.' });
  const code = typeof (req.body || {}).code === 'string' ? req.body.code : '';
  if (!code || code.length > 200) return res.status(400).json({ error: 'code is required.' });
  const launch = await redeemHandoffCode(code);
  if (!launch) {
    logAdminEvent('lti_handoff_refused', 'unknown, used or expired code', req);
    return res.status(404).json({ error: 'Unknown, used or expired code.' });
  }
  res.set('Cache-Control', 'no-store').json({ launch });
}));

module.exports = { router };
