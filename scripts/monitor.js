#!/usr/bin/env node
// Checks rennix-lti and tutor-service and raises an alert when students or
// grades are affected. Run it every few minutes (cron / a systemd timer):
//
//   */5 * * * * cd /srv/rennix-lti && node scripts/monitor.js
//
// Settings (env):
//   RENNIX_LTI_URL, TUTOR_URL        the two services (public base URLs)
//   ADMIN_SECRET                     rennix-lti admin secret
//   TENANT_ADMIN_SECRET              tutor-service admin secret
//   ALERT_WEBHOOK_URL                optional: a Slack / Microsoft Teams / Discord
//                                    incoming webhook; alerts are POSTed there
//   MONITOR_WINDOW_MINUTES           look-back window (default 10; match the schedule)
//   MAX_LAUNCH_FAILURES              per school per window before alerting (default 3)
//   MAX_AI_ERRORS                    per school per window (default 5)
//   CAP_ALERT_PCT                    warn when a school has spent this % of its
//                                    monthly AI cap (default 90); schools
//                                    without a cap are never flagged
// A grade push failure, a failed roster sync, or a service that is down or not
// ready always alerts. Prints a report; exits 1 when it alerted, 0 when all is well.

const W = Number(process.env.MONITOR_WINDOW_MINUTES || 10);
const MAX_LAUNCH_FAILURES = Number(process.env.MAX_LAUNCH_FAILURES || 3);
const MAX_AI_ERRORS = Number(process.env.MAX_AI_ERRORS || 5);
const capAlertPct = () => Number(process.env.CAP_ALERT_PCT || 90);
const usd = (n) => `$${Number(n || 0).toFixed(2)}`;
const LAUNCH_FAILURES = ['lti_jwt_verification_failed', 'lti_nonce_mismatch', 'lti_deployment_mismatch', 'lti_browser_check_failed'];

async function getJson(url, headers = {}) {
  const res = await fetch(url, { headers: { accept: 'application/json', ...headers }, signal: AbortSignal.timeout(10000) });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

async function check() {
  const problems = [];
  const lti = process.env.RENNIX_LTI_URL;
  const tutor = process.env.TUTOR_URL;
  if (!lti || !tutor) throw new Error('RENNIX_LTI_URL and TUTOR_URL are required');

  for (const [name, url] of [['rennix-lti', `${lti}/health`], ['tutor-service', `${tutor}/health/ready`]]) {
    try {
      const r = await getJson(url);
      if (r.status !== 200) {
        const detail = r.body && r.body.checks ? Object.entries(r.body.checks).filter(([, v]) => v !== 'ok').map(([k, v]) => `${k} ${v}`).join('; ') : `HTTP ${r.status}`;
        problems.push(`${name} is not ready: ${detail}`);
      }
    } catch (e) {
      problems.push(`${name} is unreachable (${e.message})`);
    }
  }

  try {
    const r = await getJson(`${lti}/admin/health/summary?minutes=${W}`, { 'x-admin-secret': process.env.ADMIN_SECRET || '' });
    if (r.status !== 200) throw new Error(`HTTP ${r.status}`);
    for (const [school, s] of Object.entries(r.body.schools)) {
      const launchFailures = LAUNCH_FAILURES.reduce((n, e) => n + (s.failures[e] || 0), 0);
      if (launchFailures >= MAX_LAUNCH_FAILURES) {
        problems.push(`${school}: ${launchFailures} failed launches in ${W} min (${s.launches} succeeded) -- ${LAUNCH_FAILURES.filter((e) => s.failures[e]).map((e) => `${e} x${s.failures[e]}`).join(', ')}`);
      }
      if (s.failures.ags_score_push_failed) problems.push(`${school}: ${s.failures.ags_score_push_failed} grade push(es) to the LMS failed in ${W} min`);
      if (s.failures.nrps_sync_failed) problems.push(`${school}: roster sync failed ${s.failures.nrps_sync_failed} time(s) in ${W} min`);
    }
  } catch (e) {
    problems.push(`could not read rennix-lti's summary (${e.message})`);
  }

  try {
    const r = await getJson(`${tutor}/admin/health/summary?minutes=${W}`, { 'x-tenant-admin-secret': process.env.TENANT_ADMIN_SECRET || '' });
    if (r.status !== 200) throw new Error(`HTTP ${r.status}`);
    for (const [school, s] of Object.entries(r.body.schools)) {
      if (s.ai_errors >= MAX_AI_ERRORS) problems.push(`${school}: ${s.ai_errors} AI errors in ${W} min (${s.chats} chats answered)`);
      if (s.grade_push_failures) problems.push(`${school}: tutor-service could not hand ${s.grade_push_failures} grade(s) to rennix-lti in ${W} min`);
      // Monthly AI cap: warn before the Tutor Bot stops answering the school's students.
      if (typeof s.monthly_cap_usd === 'number' && s.monthly_cap_usd > 0 && typeof s.month_cost_usd === 'number') {
        const pct = Math.round((s.month_cost_usd / s.monthly_cap_usd) * 100);
        if (pct >= 100) {
          problems.push(`${school}: monthly AI cap reached (${usd(s.month_cost_usd)} of ${usd(s.monthly_cap_usd)}) -- the Tutor Bot is refusing its students until the cap is raised or the month ends`);
        } else if (pct >= capAlertPct()) {
          problems.push(`${school}: ${pct}% of the monthly AI cap used (${usd(s.month_cost_usd)} of ${usd(s.monthly_cap_usd)}) -- the Tutor Bot stops answering at 100%`);
        }
      }
      if (s.error) problems.push(`${school}: ${s.error}`);
    }
  } catch (e) {
    problems.push(`could not read tutor-service's summary (${e.message})`);
  }
  return problems;
}

async function alert(problems) {
  const text = `Rennix alert (${new Date().toISOString()}):\n- ${problems.join('\n- ')}`;
  console.error(text);
  const hook = process.env.ALERT_WEBHOOK_URL;
  if (!hook) return;
  // `text` is what Slack and Teams read; `content` is Discord's.
  const res = await fetch(hook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text, content: text.slice(0, 1900) }), signal: AbortSignal.timeout(10000) })
    .catch((e) => ({ ok: false, status: e.message }));
  if (!res.ok) console.error(`could not deliver the alert to the webhook (${res.status})`);
}

if (require.main === module) {
  check().then(async (problems) => {
    if (!problems.length) { console.log(`all good (${W} min window)`); return; }
    await alert(problems);
    process.exit(1);
  }).catch((e) => { console.error(`monitor failed: ${e.message}`); process.exit(2); });
}

module.exports = { check };
