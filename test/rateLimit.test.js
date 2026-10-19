const { test } = require('node:test');
const assert = require('node:assert/strict');
const { isRateLimited, sweepRateLimits } = require('../src/rateLimit');
const { db } = require('../src/db');

test('allows requests under the threshold', async () => {
  const key = `test-under-${Date.now()}`;
  for (let i = 0; i < 5; i++) {
    assert.equal(await isRateLimited(key, 5, 60_000), false);
  }
});

test('blocks requests once over the threshold', async () => {
  const key = `test-over-${Date.now()}`;
  for (let i = 0; i < 3; i++) {
    assert.equal(await isRateLimited(key, 3, 60_000), false);
  }
  assert.equal(await isRateLimited(key, 3, 60_000), true);
});

test('a new window starts once the old one has ended', async () => {
  const key = `test-window-${Date.now()}`;
  for (let i = 0; i < 2; i++) await isRateLimited(key, 2, 50);
  assert.equal(await isRateLimited(key, 2, 50), true);
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.equal(await isRateLimited(key, 2, 50), false);
});

test('concurrent requests are all counted (shared across instances via Postgres)', async () => {
  const key = `test-concurrent-${Date.now()}`;
  const results = await Promise.all(Array.from({ length: 10 }, () => isRateLimited(key, 6, 60_000)));
  assert.equal(results.filter((limited) => limited).length, 4, 'exactly the requests beyond the limit are refused');
});

test('sweeping removes only ended windows', async () => {
  const live = `test-live-${Date.now()}`;
  const ended = `test-ended-${Date.now()}`;
  await isRateLimited(live, 5, 60_000);
  await isRateLimited(ended, 5, 1);
  await new Promise((resolve) => setTimeout(resolve, 20));
  await sweepRateLimits();
  const buckets = (await db.all('SELECT bucket FROM rate_limits WHERE bucket IN (?, ?)', [live, ended])).map((r) => r.bucket);
  assert.deepEqual(buckets, [live]);
});
