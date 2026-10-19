const express = require('express');
const { db } = require('../db');
const { requireAdmin } = require('./auth');
const { logAdminEvent } = require('../audit');
const { asyncRoute } = require('../util/asyncRoute');

// ---- Data rights: the LTI side of a person's or a school's data ----
// rennix-lti keeps, per person, the mapping from their LMS identity (issuer +
// subject) to the Rennix user id, and their course memberships; per school,
// its platform registrations, deployments and grade endpoints. tutor-service
// holds everything else (its own /admin/data routes). Erasing a person here
// breaks the link from their LMS account to their old Rennix data: a later
// launch gets a fresh user id. The admin audit log is kept as a record.

const TENANT_RE = /^[a-z0-9-]{1,64}$/;

function target(source, res, { needUser = true } = {}) {
  const tenant = String(source.tenant || '').toLowerCase();
  const userid = Number(source.userid);
  if (!TENANT_RE.test(tenant)) { res.status(400).json({ error: 'tenant (the school key) is required' }); return null; }
  if (needUser && (!Number.isInteger(userid) || userid <= 0)) { res.status(400).json({ error: 'userid must be a positive integer' }); return null; }
  return { tenant, userid };
}

const router = express.Router();

router.get('/admin/data/user', requireAdmin, asyncRoute(async (req, res) => {
  const t = target(req.query, res);
  if (!t) return;
  const identities = await db.all('SELECT platform_issuer, subject, userid FROM lti_user_map WHERE tenant_key = ? AND userid = ?', [t.tenant, t.userid]);
  const memberships = [];
  for (const id of identities) {
    memberships.push(...await db.all(
      'SELECT platform_issuer, context_id, active, updated_at FROM lti_memberships WHERE tenant_key = ? AND platform_issuer = ? AND subject = ?',
      [t.tenant, id.platform_issuer, id.subject]
    ));
  }
  logAdminEvent('user_data_exported', `tenant=${t.tenant} userid=${t.userid}`, req);
  res.json({ tenant: t.tenant, userid: t.userid, exported_at: new Date().toISOString(), identities, memberships });
}));

router.post('/admin/data/user/erase', requireAdmin, asyncRoute(async (req, res) => {
  const t = target(req.body || {}, res);
  if (!t) return;
  if (Number((req.body || {}).confirm) !== t.userid) return res.status(400).json({ error: 'confirm must repeat the userid' });
  const counts = await db.tx(async (tx) => {
    const identities = await tx.all('SELECT platform_issuer, subject FROM lti_user_map WHERE tenant_key = ? AND userid = ?', [t.tenant, t.userid]);
    let memberships = 0;
    for (const id of identities) {
      memberships += (await tx.run('DELETE FROM lti_memberships WHERE tenant_key = ? AND platform_issuer = ? AND subject = ?',
        [t.tenant, id.platform_issuer, id.subject])).changes;
    }
    const identitiesDeleted = (await tx.run('DELETE FROM lti_user_map WHERE tenant_key = ? AND userid = ?', [t.tenant, t.userid])).changes;
    return { identities: identitiesDeleted, memberships };
  });
  logAdminEvent('user_data_erased', `tenant=${t.tenant} userid=${t.userid} identities=${counts.identities} memberships=${counts.memberships}`, req);
  res.json({ ok: true, tenant: t.tenant, userid: t.userid, deleted: counts });
}));

// Everything rennix-lti holds for one school: its registrations (so its LMS can
// no longer launch), people mappings, memberships and grade endpoints.
router.post('/admin/data/school/erase', requireAdmin, asyncRoute(async (req, res) => {
  const t = target(req.body || {}, res, { needUser: false });
  if (!t) return;
  if ((req.body || {}).confirm !== `delete ${t.tenant}`) return res.status(400).json({ error: `confirm must be exactly "delete ${t.tenant}"` });
  const counts = await db.tx(async (tx) => {
    const ids = (await tx.all('SELECT id FROM platforms WHERE tenant_key = ?', [t.tenant])).map((r) => r.id);
    const out = { platforms: ids.length, deployments: 0, deep_link_sessions: 0 };
    for (const id of ids) {
      out.deployments += (await tx.run('DELETE FROM platform_deployments WHERE platform_id = ?', [id])).changes;
      out.deep_link_sessions += (await tx.run('DELETE FROM lti_dl_sessions WHERE platform_id = ?', [id])).changes;
      await tx.run('DELETE FROM lti_states WHERE platform_id = ?', [id]);
    }
    await tx.run('DELETE FROM platforms WHERE tenant_key = ?', [t.tenant]);
    out.grade_endpoints = (await tx.run('DELETE FROM ags_lineitems WHERE tenant_key = ?', [t.tenant])).changes;
    out.identities = (await tx.run('DELETE FROM lti_user_map WHERE tenant_key = ?', [t.tenant])).changes;
    out.memberships = (await tx.run('DELETE FROM lti_memberships WHERE tenant_key = ?', [t.tenant])).changes;
    await tx.run('DELETE FROM tenant_userid_seq WHERE tenant_key = ?', [t.tenant]);
    return out;
  });
  logAdminEvent('school_data_erased', `tenant=${t.tenant} ${JSON.stringify(counts)}`, req);
  res.json({ ok: true, tenant: t.tenant, deleted: counts });
}));

module.exports = { router };
