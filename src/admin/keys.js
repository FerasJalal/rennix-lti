const express = require('express');
const { listKeys, rotateKeys, nextScheduledRotation, KEY_ROTATION_DAYS } = require('../security/toolKeys');
const { logAdminEvent } = require('../audit');
const { escapeHtml } = require('../util/html');
const { requireAdmin } = require('./auth');
const { asyncRoute } = require('../util/asyncRoute');

// ---- Signing keys: see what platforms currently trust, and rotate ----
// Automatic rotation runs every KEY_ROTATION_DAYS (server.js housekeeping).
// "Rotate key now" does the same no-downtime rotation on demand; "Emergency"
// assumes the stored keys leaked and replaces all of them at once.

const router = express.Router();

const STATUS_LABEL = {
  active: ['Active', 'Signs everything'],
  next: ['Next', 'Published in advance; becomes active at the next rotation'],
  retired: ['Retired', 'No longer signs; still published until its grace period ends'],
  removed: ['Removed', 'No longer published'],
};

function fmt(ms) {
  return ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '—';
}

function renderKeysPage(keys, message) {
  const active = keys.find((k) => k.status === 'active');
  const due = nextScheduledRotation(active);
  const rows = keys.map((k) => {
    const [label, hint] = STATUS_LABEL[k.status] || [k.status, ''];
    const until = k.status === 'retired' || k.status === 'removed' ? fmt(k.retire_after) : '—';
    return `<tr><td class="mono">${escapeHtml(k.kid)}</td><td><span class="st ${escapeHtml(k.status)}" title="${escapeHtml(hint)}">${label}</span></td>
      <td>${fmt(k.created_at)}</td><td>${fmt(k.activated_at)}</td><td>${until}</td></tr>`;
  }).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>Signing keys</title>
<style>
  body { font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif; background:#f7f8fa; margin:0; padding:32px 16px; }
  .card { max-width:760px; margin:0 auto 20px; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:24px; }
  h1 { font-size:18px; margin:0 0 4px; } h2 { font-size:15px; margin:0 0 6px; }
  p { color:#57606a; font-size:13px; margin:0 0 12px; line-height:1.55; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  td, th { text-align:left; padding:7px 8px; border-bottom:1px solid #eef1f4; }
  th { color:#8a94a6; font-weight:700; }
  .mono { font-family:ui-monospace,Consolas,monospace; }
  .st { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
  .st.active { background:#e6f7ec; color:#1f9d55; } .st.next { background:#eef0ff; color:#3a3fd4; }
  .st.retired { background:#fff4e0; color:#9a5b00; } .st.removed { background:#f2f4f6; color:#8a94a6; }
  .msg { background:#e6f7ec; color:#1f7a45; padding:10px 12px; border-radius:8px; font-size:13px; margin-bottom:14px; }
  .row { display:flex; gap:16px; flex-wrap:wrap; }
  .row form { flex:1 1 300px; border:1px solid #e2e8f0; border-radius:10px; padding:14px; }
  .row form.danger { border-color:#f1c2c8; background:#fff8f9; }
  button { margin-top:10px; padding:9px 16px; border:none; border-radius:8px; background:#1f2937; color:#fff; font-weight:700; cursor:pointer; }
  .danger button { background:#d41128; }
  label { font-size:12px; color:#57606a; display:flex; gap:6px; align-items:flex-start; }
  a { color:#8a94a6; font-size:12px; }
</style></head><body>
<div class="card">
  <h1>Signing keys</h1>
  <p>Schools' LMSs verify everything Rennix signs (content selection, roster and grade requests) against the public keys at <span class="mono">/lti/jwks</span>. Keys rotate automatically every ${KEY_ROTATION_DAYS} days${due ? `; the next automatic rotation is due <b>${fmt(due)}</b>` : ''}.</p>
  ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ''}
  <table><tr><th>Key id</th><th>Status</th><th>Created</th><th>Active since</th><th>Published until</th></tr>${rows}</table>
</div>
<div class="card">
  <h2>Rotate</h2>
  <div class="row">
    <form method="post" action="/admin/keys/rotate">
      <b>Rotate key now</b>
      <p>The same no-downtime rotation as the automatic one: the pre-published next key becomes active and the current key stays published for a grace period. Schools notice nothing.</p>
      <button type="submit">Rotate key now</button>
    </form>
    <form method="post" action="/admin/keys/rotate" class="danger">
      <input type="hidden" name="emergency" value="1">
      <b>Emergency: replace all keys</b>
      <p>Use if a key may have leaked. Generates a brand-new key and stops publishing every old one immediately, so a stolen key is useless at once. A school whose LMS cached the old key may see errors until it re-fetches (usually minutes).</p>
      <label><input type="checkbox" name="confirm" value="1" required> I understand the old keys stop working immediately.</label>
      <button type="submit">Replace all keys now</button>
    </form>
  </div>
</div>
<div class="card" style="background:none;border:0;padding:0"><a href="/admin">&larr; Back to schools</a></div>
</body></html>`;
}

router.get('/admin/keys', requireAdmin, asyncRoute(async (req, res) => {
  const message = { rotated: 'Key rotated. The previous key stays published for its grace period.', emergency: 'All keys replaced. Old keys are no longer published.' }[req.query.done];
  res.set('Content-Type', 'text/html').send(renderKeysPage(await listKeys(), message));
}));

router.post('/admin/keys/rotate', requireAdmin, asyncRoute(async (req, res) => {
  const emergency = req.body && req.body.emergency === '1';
  if (emergency && req.body.confirm !== '1') return res.status(400).send('Tick the confirmation box to replace all keys.');
  const result = await rotateKeys({ emergency });
  logAdminEvent('tool_key_rotated', `${emergency ? 'emergency' : 'manual'} previous=${result.previousKid} active=${result.activeKid}`, req);
  res.redirect(`/admin/keys?done=${emergency ? 'emergency' : 'rotated'}`);
}));

module.exports = { router };
