const express = require('express');
const { db, registerPlatform } = require('../db');
const { logAdminEvent } = require('../audit');
const { escapeHtml } = require('../util/html');
const { parseCookies, verifyAdminSession } = require('../security/tokens');
const { requireAdmin } = require('./auth');
const { APP_BASE_URL, TENANT_ADMIN_SECRET } = require('../config');

const router = express.Router();

// ---- Onboarding form: a real page instead of hand-written curl commands.
// Registers the platform(s) here (same registerPlatform() the JSON API
// uses), then makes one HTTP call to tutor-service's own admin endpoint to
// set the school's OpenAI key -- that setting lives on tutor-service's side
// (per-tenant database), not here. ----
router.get('/admin', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (!verifyAdminSession(cookies.admin_session)) return res.redirect('/admin/login');
  const registered = db.prepare(`
    SELECT p.id, p.product, p.tenant_key, p.tenant_name, p.issuer, p.active, p.dynamic_registration, p.created_at,
           (SELECT COUNT(*) FROM platform_deployments d WHERE d.platform_id = p.id) AS deployment_count
    FROM platforms p ORDER BY p.created_at DESC
  `).all();

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
  .signout { text-align:right; max-width:560px; margin:0 auto 8px; display:flex; justify-content:flex-end; gap:14px; align-items:center; }
  .signout a { color:#8a94a6; font-size:12px; text-decoration:underline; }
  .signout button { background:none; border:none; color:#8a94a6; font-size:12px; cursor:pointer; text-decoration:underline; padding:0; margin:0; }
  .status { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
  .status.active { background:#e6f7ec; color:#1f9d55; }
  .status.inactive { background:#f7e6e6; color:#a10f22; }
  .status.dynamic { background:#eef0ff; color:#3a3fd4; }
  .status.manual { background:#f2f4f6; color:#57606a; }
  .rowaction { background:none; border:none; color:#8a94a6; font-size:11px; cursor:pointer; text-decoration:underline; padding:0; }
  .adddeploy { display:flex; gap:4px; align-items:center; }
  .adddeploy input { width:110px; padding:3px 6px; font-size:11px; border:1px solid #ccc; border-radius:4px; }
  .adddeploy button { padding:3px 8px; font-size:11px; border:1px solid #ccc; border-radius:4px; background:#fff; cursor:pointer; }
</style></head>
<body>
  <div class="signout">
    <a href="/admin/audit">Audit log</a>
    <form method="post" action="/admin/logout"><button type="submit">Sign out</button></form>
  </div>
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
      <tr><th>Product</th><th>Tenant</th><th>Issuer</th><th>Source</th><th>Status</th><th>Deployments</th><th></th></tr>
      ${registered.map((p) => `<tr>
        <td>${escapeHtml(p.product)}</td>
        <td>${escapeHtml(p.tenant_name)} (${escapeHtml(p.tenant_key)})</td>
        <td>${escapeHtml(p.issuer)}</td>
        <td><span class="status ${p.dynamic_registration ? 'dynamic' : 'manual'}">${p.dynamic_registration ? 'Dynamic' : 'Manual'}</span></td>
        <td><span class="status ${p.active ? 'active' : 'inactive'}">${p.active ? 'Active' : 'Inactive'}</span></td>
        <td>${p.deployment_count}
          <form class="adddeploy" method="post" action="/admin/platforms/${p.id}/deployments">
            <input name="deploymentId" placeholder="add deployment id" required>
            <button type="submit">Add</button>
          </form>
        </td>
        <td><form method="post" action="/admin/platforms/${p.id}/${p.active ? 'deactivate' : 'reactivate'}">
          <button class="rowaction" type="submit">${p.active ? 'Deactivate' : 'Reactivate'}</button>
        </form></td>
      </tr>`).join('')}
    </table>
  </div>` : ''}
</body></html>`);
});

router.post('/admin/onboard', requireAdmin, async (req, res) => {
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

module.exports = { router };
