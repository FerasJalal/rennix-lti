// Deep Linking: picker catalog, several items at once, graded items created
// with a lineItem, the response answers the request's own deployment, and only
// offered items can be returned. A fake platform (JWKS) and a fake
// tutor-service (/content/lectures) stand in for the real ones.
const http = require('http');
const crypto = require('crypto');
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { SignJWT, generateKeyPair, exportJWK, decodeJwt } = require('jose');

process.env.TENANT_ADMIN_SECRET = 'dl-secret';
process.env.LTI_BRIDGE_SECRET = 'dl-bridge';

const ISSUER = 'https://moodle.dl.test';
const KID = 'dl-key';
const INSTRUCTOR = ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'];
let lastContentCourse = null;
let app, jwksServer, contentServer, appPort, privateKey, platform, db, buildCatalog, toContentItem;

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

before(async () => {
  const keyPair = await generateKeyPair('RS256', { extractable: true });
  privateKey = keyPair.privateKey;
  const jwk = { ...(await exportJWK(keyPair.publicKey)), kid: KID, alg: 'RS256', use: 'sig' };
  jwksServer = http.createServer((req, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ keys: [jwk] })); });
  const jwksPort = await listen(jwksServer);

  // The course 'linked-course' is linked to the loops lecture only; any other
  // course isn't linked (no inCourse flags, as tutor-service sends them then).
  contentServer = http.createServer((req, res) => {
    const course = new URL(req.url, 'http://x').searchParams.get('course');
    lastContentCourse = course;
    const linked = course === 'linked-course';
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      lectures: [
        { lecture_id: 'loops', title: 'For loops', chapterTitle: 'Week 6', knowledgeCheckQuestions: 4, ...(linked ? { inCourse: true } : {}) },
        { lecture_id: 'intro', title: 'Introduction', chapterTitle: 'Week 1', knowledgeCheckQuestions: 0, ...(linked ? { inCourse: false } : {}) },
      ],
      pdfs: [{ id: 7, title: 'JAVA Loops – Slides', ...(linked ? { inCourse: false } : {}) }],
      courseLinked: linked,
    }));
  });
  process.env.APP_BASE_URL = `http://127.0.0.1:${await listen(contentServer)}`;

  let registerPlatform, getPlatform, addDeployment;
  ({ db, registerPlatform, getPlatform, addDeployment } = require('../src/db'));
  ({ buildCatalog, toContentItem } = require('../src/lti/deepLinking'));
  await registerPlatform({
    product: 'tutor_bot', tenantKey: 'dl', tenantName: 'DL School', issuer: ISSUER, clientId: 'dl-client',
    deploymentId: 'deploy-1', authLoginUrl: `${ISSUER}/auth`, jwksUrl: `http://127.0.0.1:${jwksPort}/jwks`,
  });
  platform = await getPlatform({ issuer: ISSUER, clientId: 'dl-client' });
  await addDeployment(platform.id, 'deploy-2');

  app = http.createServer(require('../server'));
  appPort = await listen(app);
});

after(async () => {
  for (const s of [app, jwksServer, contentServer]) await new Promise((r) => s.close(r));
});

async function startDeepLink({ acceptMultiple = true, acceptLineItem, deploymentId = 'deploy-2', courseId } = {}) {
  const qs = new URLSearchParams({ iss: ISSUER, login_hint: 'x', target_link_uri: 'https://t/lti/launch', client_id: 'dl-client' });
  const login = await fetch(`http://127.0.0.1:${appPort}/lti/login?${qs}`, { redirect: 'manual' });
  const loc = new URL(login.headers.get('location'));
  const now = Math.floor(Date.now() / 1000);
  const idToken = await new SignJWT({
    nonce: loc.searchParams.get('nonce'),
    'https://purl.imsglobal.org/spec/lti/claim/message_type': 'LtiDeepLinkingRequest',
    'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
    'https://purl.imsglobal.org/spec/lti/claim/deployment_id': deploymentId,
    'https://purl.imsglobal.org/spec/lti/claim/roles': INSTRUCTOR,
    ...(courseId ? { 'https://purl.imsglobal.org/spec/lti/claim/context': { id: courseId } } : {}),
    'https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings': {
      deep_link_return_url: `${ISSUER}/mod/lti/contentitem_return.php`, accept_types: ['ltiResourceLink'],
      accept_multiple: acceptMultiple, ...(acceptLineItem === undefined ? {} : { accept_lineitem: acceptLineItem }), data: 'opaque-123',
    },
  }).setProtectedHeader({ alg: 'RS256', kid: KID }).setIssuer(ISSUER).setAudience('dl-client').setSubject('3')
    .setIssuedAt(now).setExpirationTime(now + 300).sign(privateKey);
  const resp = await fetch(`http://127.0.0.1:${appPort}/lti/launch`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: login.headers.get('set-cookie').split(';')[0] },
    body: new URLSearchParams({ id_token: idToken, state: loc.searchParams.get('state') }),
  });
  const html = await resp.text();
  return { status: resp.status, html, session: (html.match(/name="session" value="([0-9a-f]+)"/) || [])[1] };
}

async function select(session, items) {
  const body = new URLSearchParams({ session });
  for (const i of items) body.append('item', i);
  const resp = await fetch(`http://127.0.0.1:${appPort}/lti/deep-link/select`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  });
  const html = await resp.text();
  const jwt = (html.match(/name="JWT" value="([^"]+)"/) || [])[1];
  return { status: resp.status, html, claims: jwt ? decodeJwt(jwt) : null };
}

test('catalog: course-wide Tutor Bot, every lecture, knowledge checks only where questions exist, and PDFs', () => {
  const keys = buildCatalog({ product: 'tutor_bot' }, {
    lectures: [{ lecture_id: 'a', title: 'A', chapterTitle: 'W1', knowledgeCheckQuestions: 2 }, { lecture_id: 'b', title: 'B', chapterTitle: 'W2', knowledgeCheckQuestions: 0 }],
    pdfs: [{ id: 3, title: 'Doc' }],
  }).map((i) => i.key);
  assert.deepEqual(keys, ['general', 'lecture:a', 'lecture:b', 'kc:a', 'pdf:3']);
  assert.deepEqual(buildCatalog({ product: 'analytics' }, { lectures: [], pdfs: [] }).map((i) => i.key), ['general']);
});

test('content items: graded ones carry a lineItem unless the platform refuses line items', () => {
  const kc = buildCatalog({ product: 'tutor_bot' }, { lectures: [{ lecture_id: 'a', title: 'A', chapterTitle: 'W1', knowledgeCheckQuestions: 1 }], pdfs: [] })
    .find((i) => i.key === 'kc:a');
  const withLine = toContentItem(kc, 'https://t/lti/launch', { acceptLineItem: true });
  assert.deepEqual(withLine.lineItem, { scoreMaximum: 100, label: 'Knowledge check: A', resourceId: 'rennix:kc:a', tag: 'rennix' });
  assert.deepEqual(withLine.custom, { rennix_view: 'knowledge_check', rennix_lecture_id: 'a' });
  assert.equal(toContentItem(kc, 'https://t/lti/launch', { acceptLineItem: false }).lineItem, undefined);
});

test('the picker lists the real content as checkboxes when the platform accepts several items', async () => {
  const { status, html, session } = await startDeepLink();
  assert.equal(status, 200);
  assert.ok(session);
  assert.match(html, /type="checkbox" name="item" value="kc:loops"/);
  assert.match(html, /Knowledge check: For loops/);
  assert.doesNotMatch(html, /value="kc:intro"/, 'no knowledge check for a lecture without questions');
  assert.match(html, /value="pdf:7"/);
});

test('several items come back in one signed response, for the request\'s own deployment', async () => {
  const { session } = await startDeepLink();
  const { status, claims } = await select(session, ['general', 'kc:loops', 'pdf:7']);
  assert.equal(status, 200);
  assert.equal(claims['https://purl.imsglobal.org/spec/lti/claim/deployment_id'], 'deploy-2');
  assert.equal(claims['https://purl.imsglobal.org/spec/lti/claim/message_type'], 'LtiDeepLinkingResponse');
  assert.equal(claims['https://purl.imsglobal.org/spec/lti-dl/claim/data'], 'opaque-123');
  const items = claims['https://purl.imsglobal.org/spec/lti-dl/claim/content_items'];
  assert.equal(items.length, 3);
  assert.equal(items[0].lineItem.label, 'Rennix quick checks (overall)');
  assert.equal(items[1].lineItem.resourceId, 'rennix:kc:loops');
  assert.deepEqual(items[2].custom, { rennix_pdf_id: '7' });
  assert.equal(items[2].lineItem, undefined, 'PDFs are not graded');
});

test('only offered items can be returned, and a single-item platform gets one', async () => {
  let { session } = await startDeepLink();
  assert.equal((await select(session, ['kc:intro', 'pdf:999'])).status, 400, 'items that were not offered are ignored -> nothing chosen');
  ({ session } = await startDeepLink({ acceptMultiple: false }));
  assert.equal((await select(session, ['general', 'pdf:7'])).status, 400);
  const one = await select(session, ['pdf:7']);
  assert.equal(one.claims['https://purl.imsglobal.org/spec/lti-dl/claim/content_items'].length, 1);
});

test('a platform that refuses line items gets graded items without one', async () => {
  const { session } = await startDeepLink({ acceptLineItem: false });
  const items = (await select(session, ['kc:loops'])).claims['https://purl.imsglobal.org/spec/lti-dl/claim/content_items'];
  assert.equal(items[0].lineItem, undefined);
});

test('a selection session is single-use', async () => {
  const { session } = await startDeepLink();
  assert.equal((await select(session, ['general'])).status, 200);
  assert.equal((await select(session, ['general'])).status, 400);
});

test("a linked course's picker shows its own content first and the rest behind \"Show all\"", async () => {
  const { html, session } = await startDeepLink({ courseId: 'linked-course' });
  assert.equal(lastContentCourse, 'linked-course', 'the picker asks for the requesting course');
  assert.match(html, /Showing this course's content/);
  assert.match(html, /Show all DL School content/);
  assert.match(html, /<form class="card only-course"/);
  assert.match(html, /<label class="item">\s*<input type="checkbox" name="item" value="lecture:loops"/, 'in-course lecture is visible');
  assert.match(html, /<label class="item other">\s*<input type="checkbox" name="item" value="lecture:intro"/, 'other lecture starts hidden');
  assert.match(html, /<fieldset class="other">\s*<legend>Documents \(PDF\)<\/legend>/, 'a group with nothing in the course is hidden');

  // Still selectable once shown: every offered item stays in the catalog.
  const res = await select(session, ['lecture:intro']);
  assert.equal(res.status, 200);
});

test("an unlinked course's picker lists everything and says how to narrow it", async () => {
  const { html } = await startDeepLink({ courseId: 'some-other-course' });
  assert.match(html, /isn't linked to its content yet/);
  assert.doesNotMatch(html, /class="card only-course"|class="item other"/);
});
