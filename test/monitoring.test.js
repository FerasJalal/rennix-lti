// Monitoring: the admin summary counts launches and failures per school, and
// scripts/monitor.js turns them (and both services' health) into alerts.
const http = require('http');
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_SECRET = 'monitoring-admin-secret';
const { db } = require('../src/db');
const { check } = require('../scripts/monitor');

let lti, ltiPort, tutor, tutorPort;
let tutorState = { ready: 200, summary: { schools: {} } };

before(async () => {
  lti = http.createServer(require('../server'));
  ltiPort = await new Promise((r) => lti.listen(0, '127.0.0.1', () => r(lti.address().port)));
  // A stand-in tutor-service: readiness and summary, as its real routes answer.
  tutor = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url.startsWith('/health/ready')) {
      res.statusCode = tutorState.ready;
      return res.end(JSON.stringify({ ok: tutorState.ready === 200, checks: { database: 'ok', search_index: tutorState.ready === 200 ? 'ok' : 'failed: HTTP 503' } }));
    }
    if (req.url.startsWith('/admin/health/summary')) {
      if (req.headers['x-tenant-admin-secret'] !== 'tutor-secret') { res.statusCode = 401; return res.end('{}'); }
      return res.end(JSON.stringify(tutorState.summary));
    }
    res.statusCode = 404; res.end('{}');
  });
  tutorPort = await new Promise((r) => tutor.listen(0, '127.0.0.1', () => r(tutor.address().port)));
  Object.assign(process.env, {
    RENNIX_LTI_URL: `http://127.0.0.1:${ltiPort}`, TUTOR_URL: `http://127.0.0.1:${tutorPort}`,
    TENANT_ADMIN_SECRET: 'tutor-secret', MONITOR_WINDOW_MINUTES: '10',
  });
});
after(async () => { await new Promise((r) => lti.close(r)); await new Promise((r) => tutor.close(r)); });
beforeEach(async () => {
  await db.run('DELETE FROM admin_audit_log');
  tutorState = { ready: 200, summary: { schools: {} } };
});

const audit = (event, detail, ageMs = 0) => db.run('INSERT INTO admin_audit_log (event, detail, ip, created_at) VALUES (?, ?, ?, ?)', [event, detail, null, Date.now() - ageMs]);
const summary = async (minutes) => (await fetch(`http://127.0.0.1:${ltiPort}/admin/health/summary?minutes=${minutes}`, { headers: { 'x-admin-secret': process.env.ADMIN_SECRET } })).json();

test('the summary counts launches and failures per school within the window, and is admin-only', async () => {
  assert.equal((await fetch(`http://127.0.0.1:${ltiPort}/admin/health/summary`, { headers: { accept: 'application/json' } })).status, 401);
  await audit('lti_launch_success', 'tenant=school-a product=tutor_bot');
  await audit('lti_launch_success', 'tenant=school-a product=tutor_bot');
  await audit('lti_deployment_mismatch', 'platform_id=1 tenant=school-a deployment_id=x');
  await audit('ags_score_push_failed', 'tenant=school-b status=409');
  await audit('lti_jwt_verification_failed', 'signature verification failed');
  await audit('lti_launch_success', 'tenant=school-a product=tutor_bot', 2 * 60 * 60 * 1000); // outside the window
  const s = await summary(60);
  assert.equal(s.schools['school-a'].launches, 2);
  assert.deepEqual(s.schools['school-a'].failures, { lti_deployment_mismatch: 1 });
  assert.deepEqual(s.schools['school-b'].failures, { ags_score_push_failed: 1 });
  assert.deepEqual(s.schools.unknown.failures, { lti_jwt_verification_failed: 1 }, 'failures before the school is known still count');
  assert.equal(s.failures.lti_deployment_mismatch, 1);
});

test('the monitor is quiet when everything is fine', async () => {
  await audit('lti_launch_success', 'tenant=school-a');
  assert.deepEqual(await check(), []);
});

test('the monitor alerts on repeated launch failures, any grade push failure, and AI errors', async () => {
  for (let i = 0; i < 3; i++) await audit('lti_browser_check_failed', 'platform_id=1 tenant=school-a target=iframe');
  await audit('lti_browser_check_failed', 'platform_id=2 tenant=school-c target=iframe'); // one alone is below the threshold
  await audit('ags_score_push_failed', 'tenant=school-b status=500');
  tutorState.summary = { schools: { 'school-a': { ai_errors: 7, chats: 20, grade_push_failures: 0 } } };
  const problems = await check();
  assert.ok(problems.some((p) => /school-a: 3 failed launches/.test(p)), problems.join('\n'));
  assert.ok(!problems.some((p) => /school-c/.test(p)));
  assert.ok(problems.some((p) => /school-b: 1 grade push/.test(p)));
  assert.ok(problems.some((p) => /school-a: 7 AI errors/.test(p)));
});

test('the monitor alerts when a service is not ready or its summary can\'t be read', async () => {
  tutorState.ready = 503;
  let problems = await check();
  assert.ok(problems.some((p) => /tutor-service is not ready: search_index failed/.test(p)), problems.join('\n'));
  tutorState.ready = 200;
  const saved = process.env.TENANT_ADMIN_SECRET;
  process.env.TENANT_ADMIN_SECRET = 'wrong';
  problems = await check();
  process.env.TENANT_ADMIN_SECRET = saved;
  assert.ok(problems.some((p) => /could not read tutor-service's summary \(HTTP 401\)/.test(p)));
});
