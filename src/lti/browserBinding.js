const { escapeHtml } = require('../util/html');

// ---- Tying a launch to the browser that started it ----
// The one-time `state` (login.js -> launch.js) proves the launch was started
// through our login step, but not that the browser finishing it is the one
// that started it. Without that, someone could start a launch in their own
// browser and get a student's browser to finish it (login CSRF), leaving the
// student signed in as them. So login also sets a cookie named after the
// state, and launch accepts the state only from a browser that sends it back.
//
// Inside the LMS's iframe this is a third-party cookie, so it's SameSite=None
// + Partitioned (CHIPS): kept per LMS site, which most browsers allow even
// when they block ordinary third-party cookies. Where it's blocked anyway,
// launch.js shows fallbackPage() instead: open the activity in its own tab,
// where the cookie is first-party. (The LTI "Platform Storage" alternative,
// lti.put_data/get_data postMessages, isn't supported by Moodle as of 5.2.)

const COOKIE_PREFIX = 'lti_state_';
const MAX_AGE_MS = 10 * 60 * 1000; // same lifetime as the state row

const cookieName = (state) => COOKIE_PREFIX + state;
const cookieOptions = { httpOnly: true, secure: true, sameSite: 'none', partitioned: true, path: '/lti/launch' };

function setStateCookie(res, state) {
  res.cookie(cookieName(state), '1', { ...cookieOptions, maxAge: MAX_AGE_MS });
}

function clearStateCookie(res, state) {
  res.clearCookie(cookieName(state), cookieOptions);
}

function hasStateCookie(req, state) {
  const wanted = cookieName(state) + '=';
  return String(req.headers.cookie || '').split(';').some((part) => part.trim().startsWith(wanted));
}

// Where "open in a new tab" should go: the LMS's own launch of this activity,
// which then runs our login in a first-party window. Moodle's lti_message_hint
// is JSON carrying the course-module id; other platforms get null (the page
// then points at the course instead).
function relaunchUrl(platform, ltiMessageHint) {
  let hint;
  try { hint = JSON.parse(ltiMessageHint || ''); } catch (e) { return null; }
  const cmid = hint && /^\d+$/.test(String(hint.cmid || '')) ? String(hint.cmid) : null;
  const authPath = '/mod/lti/auth.php';
  if (!cmid || !platform.auth_login_url || !platform.auth_login_url.endsWith(authPath)) return null;
  return `${platform.auth_login_url.slice(0, -authPath.length)}/mod/lti/launch.php?id=${cmid}`;
}

// Shown when the browser didn't send the cookie back. Framed: offer a new tab
// (the usual cause is blocked third-party cookies). Top-level: cookies are off
// entirely (or this is a forged launch), so explain and point back.
function fallbackPage({ openUrl, returnUrl }) {
  const open = openUrl || returnUrl;
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Open Rennix in a new tab</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background:#f7f8fa; margin:0; padding:40px; }
  .card { max-width:460px; margin:0 auto; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:28px; text-align:center; }
  h1 { font-size:17px; margin:0 0 8px; color:#1a1a1a; }
  p { color:#57606a; font-size:13px; line-height:1.6; margin:0 0 16px; }
  a.btn { display:inline-block; background:#d41128; color:#fff; text-decoration:none; font-weight:700; font-size:13px; padding:10px 18px; border-radius:8px; }
  a.link { color:#57606a; font-size:12px; }
  .top { display:none; }
  html.is-top .framed { display:none; } html.is-top .top { display:block; }
</style>
<script>if (window.self === window.top) document.documentElement.classList.add('is-top');</script>
</head>
<body>
  <div class="card framed">
    <h1>Open Rennix in a new tab</h1>
    <p>Your browser's privacy settings stopped Rennix from signing you in inside this page. It works in its own tab.</p>
    ${open ? `<a class="btn" href="${escapeHtml(open)}" target="_blank" rel="noopener">Open in a new tab</a>` : '<p>Open this activity again from your course.</p>'}
    ${!openUrl && returnUrl ? '<p style="margin-top:12px">Then start Rennix from the course page.</p>' : ''}
  </div>
  <div class="card top">
    <h1>Couldn't confirm this sign-in</h1>
    <p>Rennix couldn't confirm that this launch started in this browser. Make sure cookies are allowed for this site, then open the activity again from your course.</p>
    ${returnUrl ? `<a class="btn" href="${escapeHtml(returnUrl)}">Back to course</a>` : ''}
  </div>
</body></html>`;
}

module.exports = { setStateCookie, clearStateCookie, hasStateCookie, relaunchUrl, fallbackPage };
