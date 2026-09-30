// NRPS roster paging: every page behind Link: rel="next" is read.
const http = require('http');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { fetchCourseMembership, nextPageUrl } = require('../src/lti/nrps');

test('nextPageUrl finds rel="next" among several links and resolves relative URLs', () => {
  const header = '<https://lms.test/m?page=1>; rel="first", <https://lms.test/m?page=3>; rel="next", <https://lms.test/m?page=9>; rel="last"';
  assert.equal(nextPageUrl(header, 'https://lms.test/m?page=2'), 'https://lms.test/m?page=3');
  assert.equal(nextPageUrl('</m?page=2>; rel=next', 'https://lms.test/m'), 'https://lms.test/m?page=2');
  assert.equal(nextPageUrl('<https://lms.test/m?page=1>; rel="prev"', 'https://lms.test/m'), null);
  assert.equal(nextPageUrl(null, 'https://lms.test/m'), null);
});

let server, base, hits = 0, sawAuth = true;
before(async () => {
  // 3 pages of 2 members each; page N links to N+1.
  server = http.createServer((req, res) => {
    hits += 1;
    if (req.headers.authorization !== 'Bearer tok') sawAuth = false;
    const page = Number(new URL(req.url, 'http://x').searchParams.get('page') || 1);
    if (page < 3) res.setHeader('Link', `<${base}/members?page=${page + 1}>; rel="next"`);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ id: 'c1', context: { id: 'course-1' }, members: [{ user_id: `u${page}a` }, { user_id: `u${page}b` }] }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => new Promise((r) => server.close(r)));

test('fetchCourseMembership follows every page and combines the members', async () => {
  const data = await fetchCourseMembership(`${base}/members`, 'tok');
  assert.equal(hits, 3);
  assert.ok(sawAuth, 'every page request carries the access token');
  assert.deepEqual(data.members.map((m) => m.user_id), ['u1a', 'u1b', 'u2a', 'u2b', 'u3a', 'u3b']);
  assert.equal(data.context.id, 'course-1');
});
