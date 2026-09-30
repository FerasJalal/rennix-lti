// Data rights on the LTI side: export/erase one person's identity mapping and
// memberships, or everything for one school -- nothing belonging to others.
const http = require('http');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_SECRET = 'data-rights-admin-secret';

const { db, registerPlatform, getPlatform, getOrAllocateUserId, setMembership, addDeployment } = require('../src/db');

let server, port, uidA1, uidA2, uidB;
const ISS = 'https://lms.dr.test';

before(async () => {
  server = http.createServer(require('../server'));
  port = await new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
  for (const [tenantKey, clientId] of [['school-a', 'a-client'], ['school-b', 'b-client']]) {
    await registerPlatform({ product: 'tutor_bot', tenantKey, tenantName: tenantKey, issuer: ISS, clientId, deploymentId: 'd1', authLoginUrl: `${ISS}/auth`, jwksUrl: `${ISS}/jwks` });
  }
  await addDeployment((await getPlatform({ issuer: ISS, clientId: 'a-client' })).id, 'd2');
  uidA1 = await getOrAllocateUserId('school-a', ISS, 'sub-1', 'one@a.test');
  uidA2 = await getOrAllocateUserId('school-a', ISS, 'sub-2', 'two@a.test');
  uidB = await getOrAllocateUserId('school-b', ISS, 'sub-1', 'one@b.test');
  await setMembership('school-a', ISS, 'course-1', 'sub-1', true);
  await setMembership('school-a', ISS, 'course-2', 'sub-1', false);
  await setMembership('school-a', ISS, 'course-1', 'sub-2', true);
  await setMembership('school-b', ISS, 'course-1', 'sub-1', true);
});
after(() => new Promise((r) => server.close(r)));

const call = (method, path, body, withSecret = true) => fetch(`http://127.0.0.1:${port}${path}`, {
  method,
  headers: { ...(withSecret ? { 'x-admin-secret': process.env.ADMIN_SECRET } : {}), ...(body ? { 'content-type': 'application/json' } : {}), accept: 'application/json' },
  body: body ? JSON.stringify(body) : undefined,
});

test('data routes need the admin secret', async () => {
  assert.equal((await call('GET', `/admin/data/user?tenant=school-a&userid=${uidA1}`, null, false)).status, 401);
  assert.equal((await call('POST', '/admin/data/user/erase', { tenant: 'school-a', userid: uidA1, confirm: uidA1 }, false)).status, 401);
  assert.equal((await call('POST', '/admin/data/school/erase', { tenant: 'school-a', confirm: 'delete school-a' }, false)).status, 401);
});

test('a person\'s export lists their LMS identity and course memberships', async () => {
  const res = await call('GET', `/admin/data/user?tenant=school-a&userid=${uidA1}`);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.deepEqual(data.identities, [{ platform_issuer: ISS, subject: 'sub-1', userid: uidA1 }]);
  assert.deepEqual(data.memberships.map((m) => m.context_id).sort(), ['course-1', 'course-2']);
});

test('erasing a person removes only their mapping and memberships; a later launch gets a new user id', async () => {
  assert.equal((await call('POST', '/admin/data/user/erase', { tenant: 'school-a', userid: uidA1 })).status, 400, 'needs confirmation');
  const res = await call('POST', '/admin/data/user/erase', { tenant: 'school-a', userid: uidA1, confirm: uidA1 });
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json()).deleted, { identities: 1, memberships: 2 });
  assert.equal((await db.one("SELECT COUNT(*) AS n FROM lti_memberships WHERE tenant_key = 'school-a' AND subject = 'sub-2'")).n, 1, 'others in the school keep theirs');
  assert.equal((await db.one("SELECT COUNT(*) AS n FROM lti_user_map WHERE tenant_key = 'school-b' AND subject = 'sub-1'")).n, 1, 'the same subject in another school is untouched');
  const again = await getOrAllocateUserId('school-a', ISS, 'sub-1', 'one@a.test');
  assert.notEqual(again, uidA1);
});

test('erasing a school removes its registrations and people, and leaves other schools working', async () => {
  assert.equal((await call('POST', '/admin/data/school/erase', { tenant: 'school-a', confirm: 'yes' })).status, 400);
  const res = await call('POST', '/admin/data/school/erase', { tenant: 'school-a', confirm: 'delete school-a' });
  assert.equal(res.status, 200);
  const { deleted } = await res.json();
  assert.equal(deleted.platforms, 1);
  assert.equal(deleted.deployments, 2);
  assert.ok(deleted.identities >= 2);
  assert.equal(await getPlatform({ issuer: ISS, clientId: 'a-client' }), undefined, 'school A\'s LMS can no longer launch');
  assert.ok(await getPlatform({ issuer: ISS, clientId: 'b-client' }), 'school B is still registered');
  assert.equal((await db.one("SELECT COUNT(*) AS n FROM lti_user_map WHERE tenant_key = 'school-a'")).n, 0);
  assert.equal((await db.one("SELECT COUNT(*) AS n FROM lti_user_map WHERE tenant_key = 'school-b'")).n, 1);
  assert.equal((await db.one("SELECT COUNT(*) AS n FROM admin_audit_log WHERE event = 'school_data_erased'")).n >= 1, true, 'the erase itself is on record');
});
