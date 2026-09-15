const express = require('express');
const { db, registerPlatform } = require('../db');
const { logAdminEvent } = require('../audit');
const { requireAdmin } = require('./auth');

const router = express.Router();

router.post('/admin/platforms', requireAdmin, (req, res) => {
  try {
    registerPlatform(req.body);
    logAdminEvent('platform_registered', `${req.body.product} / ${req.body.tenantKey}`, req);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/admin/platforms', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, product, tenant_key, tenant_name, issuer, client_id, deployment_id, jwks_url, created_at FROM platforms').all());
});

module.exports = { router };
