// Signing-key rotation: scheduled (automatic / "Rotate key now") keeps every
// published key working through the switch; emergency unpublishes old keys at
// once; automatic rotation fires only when due, and only once across instances.
const http = require('http');
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

process.env.ADMIN_SECRET = 'keys-admin-secret';

const { db } = require('../src/db');
const keys = require('../src/security/toolKeys');

const DAY = 24 * 60 * 60 * 1000;
const kidsIn = async () => (await keys.getPublishedJwks()).keys.map((k) => k.kid).sort();
const statusOf = async (kid) => (await db.one('SELECT status FROM tool_keys WHERE kid = ?', [kid])).status;

beforeEach(async () => {
  await db.run('DELETE FROM tool_keys');
  keys.clearKeyCache();
});

test('first use creates an active key and a pre-published next key', async () => {
  await keys.ensureKeys();
  const { kid } = await keys.getToolKeyPair();
  const next = await db.one("SELECT kid FROM tool_keys WHERE status = 'next'");
  assert.ok(next);
  assert.deepEqual(await kidsIn(), [kid, next.kid].sort(), 'JWKS publishes both, so platforms learn the next key early');
});

test('a scheduled rotation promotes next, keeps the old key published for its grace period, and adds a new next', async () => {
  await keys.ensureKeys();
  const before = (await keys.getToolKeyPair()).kid;
  const prepublished = (await db.one("SELECT kid FROM tool_keys WHERE status = 'next'")).kid;

  const result = await keys.rotateKeys();
  assert.equal(result.previousKid, before);
  assert.equal(result.activeKid, prepublished, 'the key platforms already know becomes the signing key');
  assert.equal((await keys.getToolKeyPair()).kid, prepublished);
  assert.equal(await statusOf(before), 'retired');

  const published = await kidsIn();
  assert.ok(published.includes(before), 'old key still verifiable during the grace period');
  assert.ok(published.includes(prepublished));
  assert.equal(published.length, 3, 'retired + active + a fresh next');
});

test('retired keys leave the JWKS once their grace period is over', async () => {
  await keys.ensureKeys();
  const old = (await keys.getToolKeyPair()).kid;
  await keys.rotateKeys();
  await db.run('UPDATE tool_keys SET retire_after = ? WHERE kid = ?', [Date.now() - 1000, old]);
  await keys.removeExpiredRetiredKeys();
  assert.equal(await statusOf(old), 'removed');
  assert.ok(!(await kidsIn()).includes(old));
});

test('an emergency rotation replaces every key and unpublishes the old ones immediately', async () => {
  await keys.ensureKeys();
  const oldActive = (await keys.getToolKeyPair()).kid;
  const oldNext = (await db.one("SELECT kid FROM tool_keys WHERE status = 'next'")).kid;

  const result = await keys.rotateKeys({ emergency: true });
  assert.notEqual(result.activeKid, oldNext, 'the pre-published next key is presumed leaked too');
  const published = await kidsIn();
  assert.ok(!published.includes(oldActive) && !published.includes(oldNext), 'no old key is published any more');
  assert.equal(published.length, 2, 'brand-new active + brand-new next');
  assert.equal((await keys.getToolKeyPair()).kid, result.activeKid);
});

test('automatic rotation does nothing until the key is due, then rotates exactly once even if two instances check at once', async () => {
  await keys.ensureKeys();
  const kid = (await keys.getToolKeyPair()).kid;
  assert.equal(await keys.rotateIfDue(), null, 'a fresh key is not due');

  await db.run('UPDATE tool_keys SET activated_at = ? WHERE kid = ?', [Date.now() - (keys.KEY_ROTATION_DAYS + 1) * DAY, kid]);
  const results = await Promise.all([keys.rotateIfDue(), keys.rotateIfDue()]);
  assert.equal(results.filter(Boolean).length, 1, 'one rotation, not two');
  assert.equal(await statusOf(kid), 'retired');
  assert.equal((await db.one("SELECT COUNT(*) AS n FROM tool_keys WHERE status = 'active'")).n, 1);
});

test('rotation keeps signing working: the new key can sign and the JWKS publishes it', async () => {
  const { SignJWT, jwtVerify, createLocalJWKSet } = require('jose');
  await keys.ensureKeys();
  await keys.rotateKeys();
  const { privateKey, kid } = await keys.getToolKeyPair();
  const token = await new SignJWT({ hello: 'lms' }).setProtectedHeader({ alg: 'RS256', kid }).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const { payload } = await jwtVerify(token, createLocalJWKSet(await keys.getPublishedJwks()));
  assert.equal(payload.hello, 'lms');
});

// ---- Admin page ----
let server, port;
before(async () => {
  server = http.createServer(require('../server'));
  port = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
});
after(() => new Promise((resolve) => server.close(resolve)));

const admin = (method, path, form, withSecret = true) => fetch(`http://127.0.0.1:${port}${path}`, {
  method, redirect: 'manual',
  headers: { ...(withSecret ? { 'x-admin-secret': 'keys-admin-secret' } : {}), ...(form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}) },
  body: form ? new URLSearchParams(form) : undefined,
});

test('the Signing keys page and both buttons require admin access', async () => {
  const anon = await admin('GET', '/admin/keys', null, false);
  assert.equal(anon.status, 302, 'a browser without a session is sent to sign in');
  assert.equal(anon.headers.get('location'), '/admin/login');
  assert.equal((await admin('POST', '/admin/keys/rotate', {}, false)).status, 401);
  const page = await admin('GET', '/admin/keys');
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Rotate key now/);
  assert.match(html, /Emergency: replace all keys/);
});

test('"Rotate key now" rotates; the emergency button needs its confirmation box', async () => {
  await keys.ensureKeys();
  const before = (await keys.getToolKeyPair()).kid;
  const r = await admin('POST', '/admin/keys/rotate', {});
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), '/admin/keys?done=rotated');
  assert.equal(await statusOf(before), 'retired');

  assert.equal((await admin('POST', '/admin/keys/rotate', { emergency: '1' })).status, 400, 'no confirmation, no emergency');
  const e = await admin('POST', '/admin/keys/rotate', { emergency: '1', confirm: '1' });
  assert.equal(e.headers.get('location'), '/admin/keys?done=emergency');
  assert.equal(await statusOf(before), 'removed');
});
