const crypto = require('crypto');
const express = require('express');
const { SignJWT } = require('jose');
const { db, getPlatformById } = require('../db');
const { logAdminEvent } = require('../audit');
const { getToolKeyPair } = require('../security/toolKeys');
const { escapeHtml } = require('../util/html');
const log = require('../log');
const { APP_BASE_URL, TENANT_ADMIN_SECRET } = require('../config');

// Same reasoning as src/lti/launch.js's launchErrorMessage: the raw
// exception text is useful to us (it's always in the audit log), not to
// whatever's rendering this page inside the LMS.
function deepLinkErrorMessage(err) {
  if (process.env.NODE_ENV === 'production') {
    return 'Deep linking failed. Contact your LMS administrator.';
  }
  return `Deep linking failed: ${err.message}`;
}

// ---- Deep Linking: let an instructor pick real content inside Rennix while
// adding activities in Moodle ("Select content"), instead of creating one
// generic External Tool activity that always lands on the same page. Real
// content only -- the picker lists tutor-service's actual lectures, knowledge
// checks and PDFs, nothing invented. Several items can be added at once when
// the platform accepts it, and graded items (knowledge checks, the course-wide
// Tutor Bot) are created with their own gradebook column (a lineItem), so
// grades land in the right place from the first answer. ----
// courseId (the LMS course asking): tutor-service flags which items that
// course is linked to (inCourse), or says it isn't linked (courseLinked false).
async function fetchTenantContent(tenantKey, courseId) {
  const url = new URL('/content/lectures', APP_BASE_URL);
  url.searchParams.set('tenant', tenantKey);
  if (courseId) url.searchParams.set('course', String(courseId));
  const resp = await fetch(url, { headers: { 'x-tenant-admin-secret': TENANT_ADMIN_SECRET } });
  if (!resp.ok) throw new Error(`tutor-service /content/lectures returned ${resp.status}`);
  const data = await resp.json();
  return { lectures: data.lectures || [], pdfs: data.pdfs || [], courseLinked: !!data.courseLinked };
}

// Everything the picker offers, keyed so a submitted choice can be matched
// back to exactly one offered item. `custom` becomes the activity's LTI custom
// parameters (read back in launch.js); `lineItem` makes it graded.
function buildCatalog(platform, content) {
  if (platform.product === 'analytics') {
    return [{ key: 'general', group: 'Course', title: 'Rennix Analytics dashboard (whole course)' }];
  }
  const items = [{
    key: 'general', group: 'Course', title: 'Rennix Tutor Bot & dashboard (course-wide)',
    detail: 'Graded: overall quick-check score',
    lineItem: { label: 'Rennix quick checks (overall)', resourceId: 'rennix:overall' },
  }];
  for (const l of content.lectures) {
    items.push({
      key: `lecture:${l.lecture_id}`, group: 'Lectures', title: `${l.chapterTitle} — ${l.title}`, inCourse: l.inCourse !== false,
      custom: { rennix_lecture_id: String(l.lecture_id) },
    });
  }
  for (const l of content.lectures.filter((x) => x.knowledgeCheckQuestions > 0)) {
    items.push({
      key: `kc:${l.lecture_id}`, inCourse: l.inCourse !== false, group: 'Knowledge checks', title: `Knowledge check: ${l.title}`,
      detail: `${l.knowledgeCheckQuestions} question${l.knowledgeCheckQuestions === 1 ? '' : 's'} · graded`,
      custom: { rennix_view: 'knowledge_check', rennix_lecture_id: String(l.lecture_id) },
      lineItem: { label: `Knowledge check: ${l.title}`, resourceId: `rennix:kc:${l.lecture_id}` },
    });
  }
  for (const p of content.pdfs) {
    items.push({
      key: `pdf:${p.id}`, group: 'Documents (PDF)', title: p.title, inCourse: p.inCourse !== false,
      detail: 'Opens in the Rennix viewer with the Tutor Bot',
      custom: { rennix_pdf_id: String(p.id) },
    });
  }
  return items;
}

function renderDeepLinkPicker(sessionId, platform, catalog, { acceptMultiple, fetchError, courseLinked }) {
  const productLabel = platform.product === 'analytics' ? 'Rennix Analytics' : 'Rennix Tutor Bot';
  const inputType = acceptMultiple ? 'checkbox' : 'radio';
  const groups = [];
  for (const item of catalog) {
    let g = groups.find((x) => x.name === item.group);
    if (!g) groups.push(g = { name: item.group, items: [] });
    g.items.push(item);
  }
  // Items outside this course (when it's linked) start hidden behind "Show all".
  const other = (it) => courseLinked && it.inCourse === false;
  const hasOthers = catalog.some(other);
  const school = platform.tenant_name || platform.tenant_key;
  const groupHtml = groups.map((g) => `
    <fieldset class="${g.items.every(other) ? 'other' : ''}">
      <legend>${escapeHtml(g.name)}</legend>
      ${g.items.map((it) => `
      <label class="item${other(it) ? ' other' : ''}">
        <input type="${inputType}" name="item" value="${escapeHtml(it.key)}" ${it.key === 'general' && !acceptMultiple ? 'checked' : ''}>
        <span><span class="t">${escapeHtml(it.title)}</span>${it.detail ? `<span class="d">${escapeHtml(it.detail)}</span>` : ''}</span>
      </label>`).join('')}
    </fieldset>`).join('');
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Add ${escapeHtml(productLabel)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif; background:#f7f8fa; margin:0; padding:24px 16px; }
  .card { max-width:620px; margin:0 auto; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:22px; }
  h1 { font-size:18px; margin:0 0 4px; }
  p.sub { color:#57606a; font-size:13px; margin:0 0 14px; }
  fieldset { border:0; padding:0; margin:0 0 14px; }
  legend { font-size:11px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; color:#8a94a6; margin-bottom:6px; }
  .list { max-height:60vh; overflow-y:auto; }
  .item { display:flex; gap:10px; align-items:flex-start; padding:9px 11px; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:6px; cursor:pointer; font-size:13px; }
  .item:hover { border-color:#d41128; }
  .item input { margin-top:2px; accent-color:#d41128; }
  .item .t { display:block; color:#1a1a1a; }
  .item .d { display:block; color:#8a94a6; font-size:12px; margin-top:2px; }
  .err { color:#a10f22; font-size:12px; margin-bottom:12px; }
  .bar { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-top:14px; }
  .count { color:#57606a; font-size:12px; }
  button { padding:10px 18px; border:none; border-radius:8px; background:#d41128; color:#fff; font-weight:700; cursor:pointer; font-size:14px; }
  button:disabled { opacity:.45; cursor:default; }
  .scope { display:flex; justify-content:space-between; align-items:center; gap:10px; background:#f7f8fa; border-radius:8px; padding:8px 11px; font-size:12px; color:#57606a; margin-bottom:12px; }
  .scope label { display:flex; gap:6px; align-items:center; cursor:pointer; white-space:nowrap; }
  .only-course .other { display:none; }
</style></head>
<body>
  <form class="card${hasOthers ? ' only-course' : ''}" method="post" action="/lti/deep-link/select">
    <h1>Add ${escapeHtml(productLabel)}</h1>
    <p class="sub">${acceptMultiple ? 'Choose one or more items. Each becomes its own activity in the course.' : 'Choose what this activity should open.'}</p>
    ${fetchError ? `<div class="err">Couldn't load the course content (${escapeHtml(fetchError)}); only the course-wide option is available.</div>` : ''}
    ${courseLinked && !fetchError ? `<div class="scope"><span>Showing this course's content.</span>${hasOthers ? `<label><input type="checkbox" id="showAll"> Show all ${escapeHtml(school)} content</label>` : ''}</div>` : ''}
    ${!courseLinked && !fetchError && platform.product === 'tutor_bot' ? `<div class="scope"><span>This course isn't linked to its content yet, so everything ${escapeHtml(school)} has in Rennix is listed. To narrow it, open Rennix in this course and go to Content &rarr; Content for this course.</span></div>` : ''}
    <input type="hidden" name="session" value="${escapeHtml(sessionId)}">
    <div class="list">${groupHtml}</div>
    <div class="bar"><span class="count" id="count"></span><button type="submit" id="add">Add to course</button></div>
  </form>
<script>
  (function () {
    var form = document.querySelector('form'), btn = document.getElementById('add'), count = document.getElementById('count');
    function update() {
      var n = form.querySelectorAll('input[name=item]:checked').length;
      btn.disabled = n === 0;
      count.textContent = n ? n + ' selected' : 'Nothing selected yet';
      btn.textContent = n > 1 ? 'Add ' + n + ' activities' : 'Add to course';
    }
    var showAll = document.getElementById('showAll');
    if (showAll) showAll.addEventListener('change', function () {
      form.classList.toggle('only-course', !showAll.checked);
      // Nothing hidden stays selected.
      if (!showAll.checked) form.querySelectorAll('.item.other input:checked').forEach(function (i) { i.checked = false; });
      update();
    });
    form.addEventListener('change', update);
    form.addEventListener('submit', function () { btn.disabled = true; btn.textContent = 'Adding...'; });
    update();
  })();
</script>
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
  const acceptTypes = dlSettings.accept_types || ['ltiResourceLink'];
  if (!acceptTypes.includes('ltiResourceLink')) {
    return res.status(400).send('This LMS placement does not accept LTI resource links, which is all Rennix provides.');
  }

  let content = { lectures: [], pdfs: [] };
  let fetchError = null;
  if (platform.product === 'tutor_bot') {
    try {
      const context = payload['https://purl.imsglobal.org/spec/lti/claim/context'] || {};
      content = await fetchTenantContent(platform.tenant_key, context.id);
    } catch (err) {
      fetchError = err.message;
      logAdminEvent('deep_link_content_fetch_failed', `tenant=${platform.tenant_key} error=${err.message}`, req);
    }
  }
  const catalog = buildCatalog(platform, content);
  const acceptMultiple = dlSettings.accept_multiple === true;

  const sessionId = crypto.randomBytes(16).toString('hex');
  await db.run(
    'INSERT INTO lti_dl_sessions (id, platform_id, deep_link_return_url, data, created_at, deployment_id, accept_multiple, accept_lineitem, catalog) ' +
    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [
      sessionId, platform.id, dlSettings.deep_link_return_url, dlSettings.data || null, Date.now(),
      payload['https://purl.imsglobal.org/spec/lti/claim/deployment_id'] || platform.deployment_id,
      acceptMultiple ? 1 : 0, dlSettings.accept_lineitem === false ? 0 : 1, JSON.stringify(catalog),
    ]
  );

  logAdminEvent('deep_link_picker_shown', `tenant=${platform.tenant_key} product=${platform.product} items=${catalog.length} multiple=${acceptMultiple}`, req);
  res.set('Content-Type', 'text/html').send(renderDeepLinkPicker(sessionId, platform, catalog, { acceptMultiple, fetchError, courseLinked: !!content.courseLinked }));
}

// One offered catalog item -> an LTI Deep Linking content item.
function toContentItem(item, launchUrl, { acceptLineItem }) {
  const contentItem = { type: 'ltiResourceLink', title: item.title.slice(0, 200), url: launchUrl };
  if (item.custom) contentItem.custom = item.custom;
  if (item.lineItem && acceptLineItem) {
    contentItem.lineItem = { scoreMaximum: 100, label: item.lineItem.label.slice(0, 200), resourceId: item.lineItem.resourceId, tag: 'rennix' };
  }
  return contentItem;
}

const router = express.Router();
router.post('/lti/deep-link/select', async (req, res) => {
  try {
    const { session } = req.body || {};
    const dlSession = session && await db.one('SELECT * FROM lti_dl_sessions WHERE id = ?', [String(session)]);
    if (!dlSession) return res.status(400).send('Unknown or expired selection session -- restart from Moodle.');
    if (Date.now() - dlSession.created_at > 10 * 60 * 1000) {
      await db.run('DELETE FROM lti_dl_sessions WHERE id = ?', [dlSession.id]);
      return res.status(400).send('This selection session expired -- restart from Moodle.');
    }

    const chosenKeys = [].concat(req.body.item || []).map(String);
    const catalog = JSON.parse(dlSession.catalog || '[]');
    const chosen = catalog.filter((it) => chosenKeys.includes(it.key));
    if (!chosen.length) return res.status(400).send('Choose at least one item.');
    if (chosen.length > 1 && !dlSession.accept_multiple) return res.status(400).send('This LMS accepts one item at a time -- choose one.');
    // Single-use once valid -- atomically, so a double submit can't send two responses.
    const claimed = await db.run('DELETE FROM lti_dl_sessions WHERE id = ?', [dlSession.id]);
    if (!claimed.changes) return res.status(400).send('This selection was already submitted.');

    const platform = await getPlatformById(dlSession.platform_id);
    if (!platform) return res.status(400).send('Platform no longer registered.');

    const launchUrl = `${req.protocol}://${req.get('host')}/lti/launch`;
    const contentItems = chosen.map((it) => toContentItem(it, launchUrl, { acceptLineItem: !!dlSession.accept_lineitem }));

    const { privateKey, kid } = await getToolKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const responseJwt = await new SignJWT({
      'https://purl.imsglobal.org/spec/lti/claim/deployment_id': dlSession.deployment_id || platform.deployment_id,
      'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiDeepLinkingResponse',
      'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
      'https://purl.imsglobal.org/spec/lti-dl/claim/content_items': contentItems,
      ...(dlSession.data ? { 'https://purl.imsglobal.org/spec/lti-dl/claim/data': dlSession.data } : {}),
    })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(platform.client_id)
      .setAudience(platform.issuer)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    logAdminEvent('deep_link_response_sent', `tenant=${platform.tenant_key} product=${platform.product} items=${chosen.map((c) => c.key).join(',')}`.slice(0, 500), req);

    res.set('Content-Type', 'text/html').send(`<!doctype html><html><body onload="document.forms[0].submit()">
  <form method="POST" action="${escapeHtml(dlSession.deep_link_return_url)}">
    <input type="hidden" name="JWT" value="${escapeHtml(responseJwt)}">
  </form>
  <p>Adding ${chosen.length === 1 ? 'the activity' : `${chosen.length} activities`} to your course&hellip;</p>
</body></html>`);
  } catch (err) {
    logAdminEvent('deep_link_response_failed', err.message, req);
    log.error('[LTI deep-link] response failed:', err.message);
    res.status(500).send(deepLinkErrorMessage(err));
  }
});

module.exports = { router, handleDeepLinkingRequest, buildCatalog, toContentItem };
