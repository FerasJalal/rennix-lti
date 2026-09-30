// Roster sync -> tutor-service: who counts as dropped. A fake LMS (token
// endpoint + NRPS) and a fake tutor-service (/students/sync) stand in.
const http = require('http');
const crypto = require('crypto');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

process.env.TENANT_ADMIN_SECRET = 'sync-secret';

const ISSUER = 'https://moodle.sync.test';
const LEARNER = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner';
const MENTOR = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Mentor';
let lms, tutor, lmsBase, db, platform, syncRosterViaNrps, setMembership;
let roster = { contextId: 'course-A', members: [] };
const pushes = [];

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

before(async () => {
  lms = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url.startsWith('/token')) return res.end(JSON.stringify({ access_token: 'tok', expires_in: 3600 }));
    res.end(JSON.stringify({ id: 'x', context: { id: roster.contextId }, members: roster.members }));
  });
  lmsBase = `http://127.0.0.1:${await listen(lms)}`;
  tutor = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => { pushes.push(JSON.parse(body)); res.setHeader('Content-Type', 'application/json'); res.end('{"ok":true}'); });
  });
  process.env.APP_BASE_URL = `http://127.0.0.1:${await listen(tutor)}`;

  let registerPlatform, getPlatform;
  ({ db, registerPlatform, getPlatform, setMembership } = require('../src/db'));
  ({ syncRosterViaNrps } = require('../src/lti/nrps'));
  await registerPlatform({
    product: 'tutor_bot', tenantKey: 'sync', tenantName: 'Sync School', issuer: ISSUER, clientId: 'sync-client',
    deploymentId: '1', authLoginUrl: `${ISSUER}/auth`, authTokenUrl: `${lmsBase}/token`, jwksUrl: `${lmsBase}/jwks`,
  });
  platform = await getPlatform({ issuer: ISSUER, clientId: 'sync-client' });
  // s1 and s2 already use Rennix; s3 never has.
  const map = (...args) => db.run('INSERT INTO lti_user_map (tenant_key, platform_issuer, subject, userid) VALUES (?, ?, ?, ?)', args);
  await map('sync', ISSUER, 's1', 100001);
  await map('sync', ISSUER, 's2', 100002);
});

after(async () => {
  for (const s of [lms, tutor]) await new Promise((r) => s.close(r));
});

async function sync(contextId, members) {
  roster = { contextId, members };
  pushes.length = 0;
  await syncRosterViaNrps(platform, `${lmsBase}/members`, contextId);
  const sent = pushes[0].students;
  return {
    active: sent.filter((s) => s.role !== 'dropped').map((s) => s.userid).sort(),
    dropped: sent.filter((s) => s.role === 'dropped').map((s) => s.userid).sort(),
  };
}
const member = (id, extra = {}) => ({ user_id: id, roles: [LEARNER], name: id, email: `${id}@x.test`, ...extra });

test('a full roster syncs everyone as active', async () => {
  const r = await sync('course-A', [member('s1'), member('s2')]);
  assert.deepEqual(r.active, [100001, 100002]);
  assert.deepEqual(r.dropped, []);
});

test('a student missing from a complete roster (Moodle-style) is dropped', async () => {
  const r = await sync('course-A', [member('s1')]);
  assert.deepEqual(r.active, [100001]);
  assert.deepEqual(r.dropped, [100002]);
});

test('missing from one course but still active in another: not dropped', async () => {
  await setMembership('sync', ISSUER, 'course-B', 's1', true);
  const r = await sync('course-A', []);
  assert.deepEqual(r.dropped, [], 's1 is still enrolled in course-B');
});

test('an explicit Inactive (Canvas-style) in their last active course: dropped', async () => {
  const r = await sync('course-B', [member('s1', { status: 'Inactive' })]);
  assert.deepEqual(r.dropped, [100001]);
  assert.deepEqual(r.active, []);
});

test('people who never used Rennix are not given accounts, and observers are skipped', async () => {
  const before = (await db.one('SELECT COUNT(*) AS n FROM lti_user_map')).n;
  const r = await sync('course-C', [member('s3', { status: 'Inactive' }), member('p1', { roles: [MENTOR] })]);
  assert.deepEqual(r.active, []);
  assert.deepEqual(r.dropped, []);
  assert.equal((await db.one('SELECT COUNT(*) AS n FROM lti_user_map')).n, before, 'no new Rennix accounts');
});

test('re-enrolling makes a dropped student active again', async () => {
  const r = await sync('course-A', [member('s2')]);
  assert.deepEqual(r.active, [100002]);
});
