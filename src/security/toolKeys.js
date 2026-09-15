const crypto = require('crypto');
const express = require('express');
const { generateKeyPair, exportJWK, importPKCS8, exportPKCS8 } = require('jose');
const { db } = require('../db');

// ---- Our own key pair ----
// Persisted in this service's own database (same trust boundary as every
// other secret this service already holds -- ADMIN_SECRET, LTI_BRIDGE_SECRET
// -- none of which are encrypted at rest either). Stable across restarts,
// which matters because NRPS/AGS service calls require this tool to sign its
// own JWT client assertions with it -- a key that changed on every restart
// would break the platform's cached copy of /lti/jwks.
let toolKeyPairCache = null; // { privateKey: CryptoKey, publicJwk, kid }
async function getToolKeyPair() {
  if (toolKeyPairCache) return toolKeyPairCache;
  const row = db.prepare('SELECT * FROM tool_keys ORDER BY created_at ASC LIMIT 1').get();
  if (row) {
    const privateKey = await importPKCS8(row.private_key_pem, 'RS256');
    toolKeyPairCache = { privateKey, publicJwk: JSON.parse(row.public_jwk), kid: row.kid };
    return toolKeyPairCache;
  }
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const kid = 'rennix-lti-' + crypto.randomBytes(4).toString('hex');
  const jwk = await exportJWK(publicKey);
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  jwk.kid = kid;
  const pem = await exportPKCS8(privateKey);
  db.prepare('INSERT INTO tool_keys (kid, private_key_pem, public_jwk, created_at) VALUES (?, ?, ?, ?)')
    .run(kid, pem, JSON.stringify(jwk), Date.now());
  toolKeyPairCache = { privateKey, publicJwk: jwk, kid };
  return toolKeyPairCache;
}

const router = express.Router();
router.get('/lti/jwks', async (req, res) => {
  const { publicJwk } = await getToolKeyPair();
  res.json({ keys: [publicJwk] });
});

module.exports = { getToolKeyPair, router };
