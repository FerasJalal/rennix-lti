const { test } = require('node:test');
const assert = require('node:assert/strict');

const { registerPlatform, getPlatform, setPlatformActive } = require('../src/db');

const PLATFORM = {
  product: 'tutor_bot',
  tenantKey: 'lifecycle-tenant',
  tenantName: 'Lifecycle Tenant',
  issuer: 'https://lifecycle.test',
  clientId: 'lifecycle-client',
  deploymentId: 'lifecycle-deploy',
  authLoginUrl: 'https://lifecycle.test/auth',
  jwksUrl: 'https://lifecycle.test/jwks',
};

test('a freshly registered platform is active by default', async () => {
  await registerPlatform(PLATFORM);
  const platform = await getPlatform({ issuer: PLATFORM.issuer, clientId: PLATFORM.clientId });
  assert.ok(platform);
  assert.equal(platform.active, 1);
});

test('deactivating a platform makes getPlatform stop returning it', async () => {
  const platform = await getPlatform({ issuer: PLATFORM.issuer, clientId: PLATFORM.clientId });
  await setPlatformActive(platform.id, false);
  assert.equal(await getPlatform({ issuer: PLATFORM.issuer, clientId: PLATFORM.clientId }), undefined);
});

test('reactivating makes it visible again', async () => {
  // Look it up by the ambiguous-issuer path this time (no clientId), which
  // also filters on active -- registering a fresh one first is simplest
  // since the platform above is currently deactivated.
  await registerPlatform({ ...PLATFORM, tenantKey: 'lifecycle-tenant-2', issuer: 'https://lifecycle2.test', clientId: 'lifecycle-client-2', deploymentId: 'd2' });
  const before = await getPlatform({ issuer: 'https://lifecycle2.test' });
  assert.ok(before);
  await setPlatformActive(before.id, false);
  assert.equal(await getPlatform({ issuer: 'https://lifecycle2.test' }), null);
  await setPlatformActive(before.id, true);
  const after = await getPlatform({ issuer: 'https://lifecycle2.test' });
  assert.ok(after);
  assert.equal(after.active, 1);
});
