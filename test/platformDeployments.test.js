const { test } = require('node:test');
const assert = require('node:assert/strict');

const { db, registerPlatform, getPlatform, isKnownDeployment, addDeployment } = require('../src/db');

test('registerPlatform seeds platform_deployments with the registered deployment_id', async () => {
  await registerPlatform({
    product: 'tutor_bot',
    tenantKey: 'deploy-tenant',
    tenantName: 'Deploy Tenant',
    issuer: 'https://deploy.test',
    clientId: 'deploy-client',
    deploymentId: 'deploy-1',
    authLoginUrl: 'https://deploy.test/auth',
    jwksUrl: 'https://deploy.test/jwks',
  });
  const platform = await getPlatform({ issuer: 'https://deploy.test', clientId: 'deploy-client' });
  assert.ok(platform);
  assert.equal(await isKnownDeployment(platform.id, 'deploy-1'), true);
  assert.equal(await isKnownDeployment(platform.id, 'not-registered'), false);
});

test('addDeployment adds an additional deployment id without disturbing the first', async () => {
  const platform = await getPlatform({ issuer: 'https://deploy.test', clientId: 'deploy-client' });
  await addDeployment(platform.id, 'deploy-2');
  assert.equal(await isKnownDeployment(platform.id, 'deploy-1'), true);
  assert.equal(await isKnownDeployment(platform.id, 'deploy-2'), true);
  assert.equal(await isKnownDeployment(platform.id, 'deploy-3'), false);
});

test('addDeployment is idempotent (adding the same id twice does not throw or duplicate)', async () => {
  const platform = await getPlatform({ issuer: 'https://deploy.test', clientId: 'deploy-client' });
  await addDeployment(platform.id, 'deploy-2');
  await addDeployment(platform.id, 'deploy-2');
  const { c } = await db.one('SELECT COUNT(*) AS c FROM platform_deployments WHERE platform_id = ? AND deployment_id = ?', [platform.id, 'deploy-2']);
  assert.equal(c, 1);
});

test('re-registering the same issuer + client ID updates the row instead of duplicating it', async () => {
  const first = await registerPlatform({
    product: 'tutor_bot', tenantKey: 'deploy-tenant', tenantName: 'Old Name', issuer: 'https://deploy.test',
    clientId: 'deploy-client', deploymentId: 'deploy-1', authLoginUrl: 'https://deploy.test/auth', jwksUrl: 'https://deploy.test/jwks',
  });
  const second = await registerPlatform({
    product: 'tutor_bot', tenantKey: 'deploy-tenant', tenantName: 'New Name', issuer: 'https://deploy.test',
    clientId: 'deploy-client', deploymentId: 'deploy-1', authLoginUrl: 'https://deploy.test/auth', jwksUrl: 'https://deploy.test/jwks',
  });
  assert.equal(first, second);
  assert.equal((await db.one('SELECT tenant_name FROM platforms WHERE id = ?', [first])).tenant_name, 'New Name');
});
