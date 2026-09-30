const express = require('express');
const { db, registerPlatform, setPlatformActive, addDeployment } = require('../db');
const { logAdminEvent } = require('../audit');
const { requireAdmin } = require('./auth');
const { asyncRoute } = require('../util/asyncRoute');

const router = express.Router();

// Platform ids are numeric; anything else is a bad link, not a database error.
function platformId(req, res) {
  if (!/^\d+$/.test(String(req.params.id))) { res.status(404).send('Platform not found.'); return null; }
  return Number(req.params.id);
}

router.post('/admin/platforms', requireAdmin, asyncRoute(async (req, res) => {
  try {
    await registerPlatform(req.body);
    logAdminEvent('platform_registered', `${req.body.product} / ${req.body.tenantKey}`, req);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}));

router.get('/admin/platforms', requireAdmin, asyncRoute(async (req, res) => {
  res.json(await db.all('SELECT id, product, tenant_key, tenant_name, issuer, client_id, deployment_id, jwks_url, active, created_at FROM platforms ORDER BY id'));
}));

// Deactivate, not delete -- lti_user_map and admin_audit_log rows reference
// platform_id/tenant history that a real delete would orphan. A deactivated
// platform's /lti/login starts returning "Unknown platform" (see
// getPlatform's `active = 1` filter in src/db.js) without losing any of
// that history, and can be reactivated later.
router.post('/admin/platforms/:id/deactivate', requireAdmin, asyncRoute(async (req, res) => {
  const id = platformId(req, res);
  if (id === null) return;
  await setPlatformActive(id, false);
  logAdminEvent('platform_deactivated', `platform_id=${id}`, req);
  res.redirect('/admin');
}));

router.post('/admin/platforms/:id/reactivate', requireAdmin, asyncRoute(async (req, res) => {
  const id = platformId(req, res);
  if (id === null) return;
  await setPlatformActive(id, true);
  logAdminEvent('platform_reactivated', `platform_id=${id}`, req);
  res.redirect('/admin');
}));

// Lets an admin manually add a second (or third, ...) deployment_id to an
// already-registered platform -- e.g. a Canvas install where the same
// client_id gets a fresh deployment_id per course/account. Dynamic
// Registration's auto-discovery uses the same addDeployment underneath.
router.post('/admin/platforms/:id/deployments', requireAdmin, asyncRoute(async (req, res) => {
  const id = platformId(req, res);
  if (id === null) return;
  const deploymentId = req.body && req.body.deploymentId;
  if (!deploymentId) return res.status(400).send('Missing deploymentId.');
  await addDeployment(id, String(deploymentId));
  logAdminEvent('deployment_added', `platform_id=${id} deployment_id=${deploymentId}`, req);
  res.redirect('/admin');
}));

module.exports = { router, platformId };
