const crypto = require('crypto');
const express = require('express');
const { db, sweepExpiredStates, getPlatform } = require('../db');
const { rateLimit } = require('../rateLimit');
const { asyncRoute } = require('../util/asyncRoute');
const { setStateCookie } = require('./browserBinding');

// ---- Step 1: OIDC third-party initiated login ----
// The LTI 1.3 / OIDC spec allows the platform to send this via GET or POST
// (its choice); Moodle uses POST (a form_post autosubmit), so both must work.
async function handleLtiLogin(req, res) {
  await sweepExpiredStates();
  const params = req.method === 'POST' ? req.body : req.query;
  const { iss, login_hint, target_link_uri, client_id, lti_message_hint } = params;
  if (!iss || !login_hint || !target_link_uri) {
    return res.status(400).send('Missing required LTI login parameters (iss, login_hint, target_link_uri).');
  }

  const platform = await getPlatform({ issuer: iss, clientId: client_id });
  if (!platform) {
    return res.status(400).send(`Unknown platform (issuer=${iss}${client_id ? `, client_id=${client_id}` : ''}). Register it first via /admin/platforms.`);
  }

  const state = crypto.randomBytes(24).toString('base64url');
  const nonce = crypto.randomBytes(24).toString('base64url');
  await db.run(
    'INSERT INTO lti_states (state, nonce, platform_id, target_link_uri, created_at, lti_message_hint) VALUES (?, ?, ?, ?, ?, ?)',
    [state, nonce, platform.id, String(target_link_uri), Date.now(), lti_message_hint ? String(lti_message_hint).slice(0, 2000) : null]
  );
  // Launch only accepts this state from the browser that got this cookie.
  setStateCookie(res, state);

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

const router = express.Router();
const ltiEntryRateLimit = rateLimit('lti-login', 30, 60 * 1000);
router.get('/lti/login', ltiEntryRateLimit, asyncRoute(handleLtiLogin));
router.post('/lti/login', ltiEntryRateLimit, asyncRoute(handleLtiLogin));

module.exports = { router, handleLtiLogin };
