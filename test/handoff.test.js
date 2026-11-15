// The one-time launch handoff (src/lti/handoff.js) and the narrowed email
// linking in getOrAllocateUserId (src/db.js).
const http = require('http');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_SECRET = 'handoff-admin-secret';
process.env.SESSION_SECRET = 'handoff-session-secret';
process.env.LTI_BRIDGE_SECRET = 'handoff-bridge-secret';
process.env.TENANT_ADMIN_SECRET = 'handoff-tenant-admin-secret';

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

// A stand-in for tutor-service's /admin/tenant-user-lookup: a pre-LTI
// (Moodle-plugin) student, and an account an LTI launch created.
const KNOWN = { 'legacy@school.test': 42, 'made-by-lti@school.test': 100005, 'first-lti@school.test': 100000 };
let tutor, server, base, db, createHandoffCode, getOrAllocateUserId;

before(async () => {
  tutor = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const ok = req.headers['x-tenant-admin-secret'] === process.env.TENANT_ADMIN_SECRET;
    const userid = ok ? KNOWN[url.searchParams.get('email')] : undefined;
    res.writeHead(userid ? 200 : 404, { 'content-type': 'application/json' });
    res.end(JSON.stringify(userid ? { userid } : {}));
  });
  process.env.APP_BASE_URL = `http://127.0.0.1:${await listen(tutor)}`;
  ({ db, createHandoffCode, getOrAllocateUserId } = require('../src/db'));
  server = http.createServer(require('../server'));
  base = `http://127.0.0.1:${await listen(server)}`;
  await require('../src/db').init();
});
after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => tutor.close(r));
});

const redeem = (code, secret = process.env.LTI_BRIDGE_SECRET) => fetch(`${base}/lti/handoff/redeem`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(secret ? { authorization: `Bearer ${secret}` } : {}) },
  body: JSON.stringify({ code }),
});

test('a handoff code is redeemed once, by the trusted caller only', async () => {
  const code = await createHandoffCode({ aud: 'tutor-service', tenant: 'school-a', userid: 7, email: 'p@school.test' });
  assert.equal((await redeem(code, null)).status, 401, 'no secret');
  assert.equal((await redeem(code, 'wrong-secret-of-same-len')).status, 401, 'wrong secret');
  const first = await redeem(code);
  assert.equal(first.status, 200);
  assert.deepEqual((await first.json()).launch, { aud: 'tutor-service', tenant: 'school-a', userid: 7, email: 'p@school.test' });
  assert.equal((await redeem(code)).status, 404, 'a replayed code is refused');
});

test('an expired or unknown code is refused, and only its hash is stored', async () => {
  const code = await createHandoffCode({ tenant: 'school-a', userid: 8 });
  const stored = await db.all('SELECT code_hash, payload FROM lti_handoff_codes');
  assert.ok(stored.every((r) => r.code_hash !== code), 'the code itself is never stored');
  await db.run('UPDATE lti_handoff_codes SET expires_at = ?', [Date.now() - 1]);
  assert.equal((await redeem(code)).status, 404);
  assert.equal((await redeem('not-a-code')).status, 404);
  assert.equal((await redeem('')).status, 400);
});

test('email links only to an unclaimed pre-LTI account', async () => {
  const issuerA = 'https://lms-a.test', issuerB = 'https://lms-b.test';
  assert.equal(await getOrAllocateUserId('school-a', issuerA, 'sub-1', 'legacy@school.test'), 42, 'the pre-LTI student keeps their history');
  assert.equal(await getOrAllocateUserId('school-a', issuerA, 'sub-1', 'anything@else.test'), 42, 'the mapping, not the email, is used afterwards');

  const second = await getOrAllocateUserId('school-a', issuerB, 'sub-9', 'legacy@school.test');
  assert.notEqual(second, 42, 'a second identity showing the same email does not get the claimed account');
  assert.equal(second, 100000, 'a fresh id instead -- the first LTI id in a school is 100000');

  const third = await getOrAllocateUserId('school-a', issuerA, 'sub-2', 'made-by-lti@school.test');
  assert.notEqual(third, 100005, 'an account made by an LTI launch is never reached by email');
  const fourth = await getOrAllocateUserId('school-a', issuerA, 'sub-3', 'first-lti@school.test');
  assert.notEqual(fourth, 100000, 'not even the first LTI-made account, which sits exactly on the floor');

  const linked = await db.all("SELECT detail FROM admin_audit_log WHERE event = 'lti_user_linked_by_email'");
  assert.equal(linked.length, 1);
  assert.match(linked[0].detail, /userid=42/);
});
