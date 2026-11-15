process.env.SESSION_SECRET = 'test-session-secret';
process.env.LTI_BRIDGE_SECRET = 'test-bridge-secret';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { signAdminSession, verifyAdminSession, parseCookies } = require('../src/security/tokens');

test('signAdminSession round-trips through verifyAdminSession', () => {
  const token = signAdminSession();
  assert.equal(verifyAdminSession(token), true);
});

test('verifyAdminSession rejects a tampered signature', () => {
  const token = signAdminSession();
  const [body] = token.split('.');
  const tampered = `${body}.deadbeef`;
  assert.equal(verifyAdminSession(tampered), false);
});

test('verifyAdminSession rejects a tampered body', () => {
  const token = signAdminSession();
  const [, sig] = token.split('.');
  const fakeBody = Buffer.from(JSON.stringify({ type: 'admin', exp: Date.now() + 100000 })).toString('base64url');
  assert.equal(verifyAdminSession(`${fakeBody}.${sig}`), false);
});

test('verifyAdminSession rejects an expired token', () => {
  // Can't sign an already-expired token with the real signer (it always sets
  // a future exp), so build one directly with the same HMAC scheme.
  const crypto = require('crypto');
  const body = Buffer.from(JSON.stringify({ type: 'admin', exp: Date.now() - 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(body).digest('base64url');
  assert.equal(verifyAdminSession(`${body}.${sig}`), false);
});

test('verifyAdminSession rejects malformed tokens without throwing', () => {
  assert.equal(verifyAdminSession(undefined), false);
  assert.equal(verifyAdminSession(''), false);
  assert.equal(verifyAdminSession('not-a-real-token'), false);
  assert.equal(verifyAdminSession('a.b.c'), false);
});

test('parseCookies parses a simple cookie header', () => {
  const cookies = parseCookies('admin_session=abc123; other=xyz');
  assert.equal(cookies.admin_session, 'abc123');
  assert.equal(cookies.other, 'xyz');
});

test('parseCookies handles missing/empty header', () => {
  assert.deepEqual(parseCookies(undefined), {});
  assert.deepEqual(parseCookies(''), {});
});
