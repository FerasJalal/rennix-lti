const { test } = require('node:test');
const assert = require('node:assert/strict');


const { db, registerPlatform, updatePlatform, getPlatform } = require('../src/db');

const PLATFORM = {
  product: 'tutor_bot',
  tenantKey: 'edit-tenant',
  tenantName: 'Edit Tenant',
  issuer: 'https://edit.test',
  clientId: 'edit-client',
  deploymentId: 'edit-deploy',
  authLoginUrl: 'https://edit.test/mod/lti/auth.php',
  jwksUrl: 'https://edit.test/mod/lti/certs.php',
};

test('manual registration stores the access token URL when given', async () => {
  const id = await registerPlatform({ ...PLATFORM, clientId: 'with-token', authTokenUrl: 'https://edit.test/mod/lti/token.php' });
  const row = (await db.one('SELECT auth_token_url FROM platforms WHERE id = ?', [id]));
  assert.equal(row.auth_token_url, 'https://edit.test/mod/lti/token.php');
});

test('updatePlatform fills in a missing token URL and reports what changed', async () => {
  const id = await registerPlatform(PLATFORM);
  assert.equal((await db.one('SELECT auth_token_url FROM platforms WHERE id = ?', [id])).auth_token_url, null);
  const { platform, changed } = await updatePlatform(id, { authTokenUrl: 'https://edit.test/mod/lti/token.php' });
  assert.equal(platform.auth_token_url, 'https://edit.test/mod/lti/token.php');
  assert.deepEqual(changed, ['auth_token_url']);
  // untouched fields keep their values
  assert.equal(platform.issuer, PLATFORM.issuer);
  assert.equal(platform.tenant_key, PLATFORM.tenantKey);
});

test('updatePlatform can fix a typo in the client ID, and launches find it under the new one', async () => {
  const id = await registerPlatform({ ...PLATFORM, clientId: 'typo-clent' });
  await updatePlatform(id, { clientId: 'typo-client' });
  assert.equal((await getPlatform({ issuer: PLATFORM.issuer, clientId: 'typo-clent' })), undefined);
  assert.equal((await getPlatform({ issuer: PLATFORM.issuer, clientId: 'typo-client' })).id, id);
});

test('a blank token URL clears it (disables roster sync / grade push)', async () => {
  const id = await registerPlatform({ ...PLATFORM, clientId: 'clear-token', authTokenUrl: 'https://edit.test/mod/lti/token.php' });
  const { platform } = await updatePlatform(id, { authTokenUrl: '  ' });
  assert.equal(platform.auth_token_url, null);
});

test('updatePlatform rejects missing required fields, non-URLs, and issuer/client ID clashes', async () => {
  const id = await registerPlatform({ ...PLATFORM, clientId: 'validate-me' });
  await assert.rejects(() => updatePlatform(id, { issuer: '' }), /Missing fields: issuer/);
  await assert.rejects(() => updatePlatform(id, { jwksUrl: 'not a url' }), /jwksUrl must be an http\(s\) URL/);
  await registerPlatform({ ...PLATFORM, clientId: 'taken' });
  await assert.rejects(() => updatePlatform(id, { clientId: 'taken' }), /already registered/);
  await assert.rejects(() => updatePlatform(999999, { tenantName: 'x' }), /not found/);
});

test('tenant key and product cannot be changed through updatePlatform', async () => {
  const id = await registerPlatform({ ...PLATFORM, clientId: 'fixed-tenant' });
  const { platform } = await updatePlatform(id, { tenantKey: 'someone-else', product: 'analytics', tenantName: 'Renamed' });
  assert.equal(platform.tenant_key, PLATFORM.tenantKey);
  assert.equal(platform.product, 'tutor_bot');
  assert.equal(platform.tenant_name, 'Renamed');
});
