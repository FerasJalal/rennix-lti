const crypto = require('crypto');
const express = require('express');
const { generateKeyPair, exportJWK, importPKCS8, exportPKCS8 } = require('jose');
const { db } = require('../db');
const { encrypt, decrypt } = require('./keyEncryption');
const { KEY_ENCRYPTION_SECRET } = require('../config');
const log = require('../log');

// ---- Our own signing keys ----
// Platforms verify everything this tool signs (Deep Linking responses, the
// client assertions behind NRPS/AGS service calls) against the public keys at
// /lti/jwks, so keys must stay stable -- and be replaceable without breaking
// any school. Each key moves through:
//
//   next     published in /lti/jwks ahead of use, so platforms learn it early
//   active   signs everything (exactly one)
//   retired  no longer signs; still published until retire_after
//   removed  gone from /lti/jwks
//
// Scheduled rotation (automatic every KEY_ROTATION_DAYS, or the admin
// "Rotate key" button): next -> active, active -> retired for a grace period,
// then a fresh next. Nothing a platform has cached breaks.
// Emergency rotation (admin button, "the key may have leaked"): the stored
// keys are presumed compromised -- including the pre-published next, which
// sits in the same database -- so a brand-new active key is generated and
// every old key is removed from /lti/jwks immediately.
//
// Private keys are encrypted at rest (AES-256-GCM, keyEncryption.js) whenever
// KEY_ENCRYPTION_SECRET is set; enc_iv/enc_tag on a row mark it encrypted.

const DAY_MS = 24 * 60 * 60 * 1000;
const KEY_ROTATION_DAYS = Number(process.env.KEY_ROTATION_DAYS || 90);
const RETIRED_GRACE_MS = Number(process.env.KEY_RETIRED_GRACE_HOURS || 24) * 60 * 60 * 1000;
// Instances re-read the active key this often, so a rotation made by any one
// of them is picked up by all within a minute.
const CACHE_TTL_MS = 60 * 1000;
// Postgres advisory lock id: only one instance rotates at a time.
const ROTATION_LOCK = 72410001;

async function newKeyRow(runner, status) {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const kid = `rennix-lti-${crypto.randomBytes(6).toString('hex')}`;
  const jwk = { ...(await exportJWK(publicKey)), alg: 'RS256', use: 'sig', kid };
  const pem = await exportPKCS8(privateKey);
  const stored = KEY_ENCRYPTION_SECRET ? encrypt(pem, KEY_ENCRYPTION_SECRET) : { ciphertext: pem, iv: null, tag: null };
  const now = Date.now();
  await runner.run(
    'INSERT INTO tool_keys (kid, private_key_pem, public_jwk, enc_iv, enc_tag, created_at, status, activated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [kid, stored.ciphertext, JSON.stringify(jwk), stored.iv, stored.tag, now, status, status === 'active' ? now : null]
  );
  return kid;
}

async function privateKeyOf(row) {
  let pem = row.private_key_pem;
  if (row.enc_iv && row.enc_tag) {
    pem = decrypt({ ciphertext: row.private_key_pem, iv: row.enc_iv, tag: row.enc_tag }, KEY_ENCRYPTION_SECRET);
  } else if (KEY_ENCRYPTION_SECRET) {
    // Legacy plaintext row, encryption now configured -- migrate it in place on first read.
    const wrapped = encrypt(pem, KEY_ENCRYPTION_SECRET);
    await db.run('UPDATE tool_keys SET private_key_pem = ?, enc_iv = ?, enc_tag = ? WHERE kid = ?',
      [wrapped.ciphertext, wrapped.iv, wrapped.tag, row.kid]);
  }
  return importPKCS8(pem, 'RS256');
}

// Makes sure there is an active key and a pre-published next key.
async function ensureKeys() {
  await db.tx(async (tx) => {
    await tx.run('SELECT pg_advisory_xact_lock(?)', [ROTATION_LOCK]);
    const active = await tx.one("SELECT kid FROM tool_keys WHERE status = 'active' LIMIT 1");
    if (!active) {
      const next = await tx.one("SELECT kid FROM tool_keys WHERE status = 'next' ORDER BY created_at LIMIT 1");
      if (next) await tx.run("UPDATE tool_keys SET status = 'active', activated_at = ? WHERE kid = ?", [Date.now(), next.kid]);
      else await newKeyRow(tx, 'active');
    }
    if (!(await tx.one("SELECT 1 FROM tool_keys WHERE status = 'next'"))) await newKeyRow(tx, 'next');
  });
}

let cache = null; // { privateKey, publicJwk, kid, loadedAt }

// Forget this instance's cached signing key (the next signature re-reads it).
function clearKeyCache() {
  cache = null;
}

// The key everything is signed with.
async function getToolKeyPair() {
  if (cache && Date.now() - cache.loadedAt < CACHE_TTL_MS) return cache;
  let row = await db.one("SELECT * FROM tool_keys WHERE status = 'active' LIMIT 1");
  if (!row) {
    await ensureKeys();
    row = await db.one("SELECT * FROM tool_keys WHERE status = 'active' LIMIT 1");
  }
  cache = { privateKey: await privateKeyOf(row), publicJwk: JSON.parse(row.public_jwk), kid: row.kid, loadedAt: Date.now() };
  return cache;
}

// Everything platforms should trust right now: the active key, the next one,
// and retired keys still inside their grace period.
async function getPublishedJwks() {
  await getToolKeyPair(); // guarantees at least an active key exists
  const rows = await db.all(
    "SELECT public_jwk FROM tool_keys WHERE status IN ('active', 'next') OR (status = 'retired' AND retire_after > ?) ORDER BY created_at",
    [Date.now()]
  );
  return { keys: rows.map((r) => JSON.parse(r.public_jwk)) };
}

// onlyIfActiveKid: rotate only if that key is still the active one once the
// lock is held (so two instances that both decided "rotation is due" rotate once).
async function rotateKeys({ emergency = false, onlyIfActiveKid = null } = {}) {
  const now = Date.now();
  const result = await db.tx(async (tx) => {
    await tx.run('SELECT pg_advisory_xact_lock(?)', [ROTATION_LOCK]);
    const old = await tx.one("SELECT kid FROM tool_keys WHERE status = 'active' LIMIT 1");
    if (onlyIfActiveKid && (!old || old.kid !== onlyIfActiveKid)) return null;
    let activeKid;
    if (emergency) {
      // Presume every stored key leaked: unpublish them all now, start fresh.
      await tx.run("UPDATE tool_keys SET status = 'removed', retire_after = ? WHERE status IN ('active', 'next', 'retired')", [now]);
      activeKid = await newKeyRow(tx, 'active');
    } else {
      const next = await tx.one("SELECT kid FROM tool_keys WHERE status = 'next' ORDER BY created_at LIMIT 1");
      if (old) await tx.run("UPDATE tool_keys SET status = 'retired', retire_after = ? WHERE kid = ?", [now + RETIRED_GRACE_MS, old.kid]);
      if (next) {
        await tx.run("UPDATE tool_keys SET status = 'active', activated_at = ? WHERE kid = ?", [now, next.kid]);
        activeKid = next.kid;
      } else {
        activeKid = await newKeyRow(tx, 'active');
      }
    }
    await newKeyRow(tx, 'next');
    return { previousKid: old ? old.kid : null, activeKid, emergency };
  });
  if (result) cache = null;
  return result;
}

// Retired keys whose grace period is over leave /lti/jwks for good.
async function removeExpiredRetiredKeys() {
  await db.run("UPDATE tool_keys SET status = 'removed' WHERE status = 'retired' AND retire_after <= ?", [Date.now()]);
}

// Called periodically by every instance (server.js); the advisory lock and the
// age check inside the transaction mean only one of them actually rotates.
async function rotateIfDue(logEvent) {
  await removeExpiredRetiredKeys();
  const active = await db.one("SELECT kid, COALESCE(activated_at, created_at) AS since FROM tool_keys WHERE status = 'active' LIMIT 1");
  if (!active || Date.now() - active.since < KEY_ROTATION_DAYS * DAY_MS) return null;
  // Another instance may rotate first; then this is a no-op.
  const result = await rotateKeys({ onlyIfActiveKid: active.kid });
  if (!result) return null;
  log.info(`[toolKeys] scheduled rotation: ${result.previousKid} -> ${result.activeKid}`);
  if (logEvent) logEvent('tool_key_rotated', `scheduled previous=${result.previousKid} active=${result.activeKid}`, null);
  return result;
}

// For the admin page: every key that is or was recently published.
async function listKeys() {
  return db.all(
    "SELECT kid, status, created_at, activated_at, retire_after FROM tool_keys WHERE status <> 'removed' OR retire_after > ? ORDER BY created_at DESC",
    [Date.now() - 30 * DAY_MS]
  );
}

function nextScheduledRotation(activeRow) {
  if (!activeRow) return null;
  return (activeRow.activated_at || activeRow.created_at) + KEY_ROTATION_DAYS * DAY_MS;
}

const router = express.Router();
router.get('/lti/jwks', async (req, res) => {
  try {
    res.set('Cache-Control', 'public, max-age=300');
    res.json(await getPublishedJwks());
  } catch (err) {
    log.error('[toolKeys] JWKS failed:', err.message);
    res.status(500).json({ error: 'JWKS unavailable' });
  }
});

module.exports = {
  getToolKeyPair, getPublishedJwks, ensureKeys, rotateKeys, rotateIfDue, removeExpiredRetiredKeys, clearKeyCache,
  listKeys, nextScheduledRotation, KEY_ROTATION_DAYS, router,
};
