const crypto = require('crypto');
const { SignJWT } = require('jose');
const { getToolKeyPair } = require('../security/toolKeys');
const { db, getOrAllocateUserId, setMembership, hasActiveMembership, findMappedUserId } = require('../db');
const { mapLtiRolesToInternalRole } = require('./roles');
const { logAdminEvent } = require('../audit');
const log = require('../log');
const { APP_BASE_URL, TENANT_ADMIN_SECRET } = require('../config');

// ---- LTI Advantage service calls (NRPS today, AGS later reuses the same
// token exchange) ----
// A service call means: sign a short-lived JWT asserting this tool's own
// identity (client_id) using OUR private key, trade it for an OAuth access
// token at the platform's token endpoint, then use that token as a normal
// Bearer credential against the actual service URL. Cached per
// platform+scope until shortly before expiry, rather than requesting a fresh
// token on every single service call -- the standard pattern for LTI
// Advantage service calls.
const serviceTokenCache = new Map(); // "platformId:scope" -> { token, expiresAt }
async function getServiceAccessToken(platform, scope) {
  const cacheKey = `${platform.id}:${scope}`;
  const cached = serviceTokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 30_000) return cached.token;

  if (!platform.auth_token_url) {
    throw new Error(`Platform ${platform.tenant_key} has no auth_token_url registered -- cannot request a service token.`);
  }
  const { privateKey, kid } = await getToolKeyPair();
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({
    sub: platform.client_id,
    aud: platform.auth_token_url,
    jti: crypto.randomBytes(16).toString('hex'),
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(platform.client_id)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: assertion,
    scope,
  });
  const resp = await fetch(platform.auth_token_url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Token request failed (${resp.status}): ${text.slice(0, 200)}`);
  }
  const data = await resp.json();
  serviceTokenCache.set(cacheKey, { token: data.access_token, expiresAt: Date.now() + (data.expires_in || 3600) * 1000 });
  return data.access_token;
}

// ---- Names and Role Provisioning Service ----
// The launch-time roster (who has actually clicked into the tool) is a subset
// of the real course membership -- NRPS is what lets the instructor dashboard
// eventually distinguish "enrolled but never used the tutor" from "not
// enrolled at all", instead of only ever knowing about students who happened
// to launch.
const NRPS_SCOPE = 'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly';
// Safety cap on pages followed, so a platform that keeps returning a `next`
// link can't loop us forever (at typical page sizes this is thousands of members).
const NRPS_MAX_PAGES = 100;

// The URL of the Link header's rel="next" entry, or null.
function nextPageUrl(linkHeader, baseUrl) {
  if (!linkHeader) return null;
  for (const part of linkHeader.split(',')) {
    const m = part.match(/<([^>]+)>\s*;(.*)$/);
    if (m && /\brel\s*=\s*"?next"?/i.test(m[2])) return new URL(m[1].trim(), baseUrl).toString();
  }
  return null;
}

// NRPS pages large rosters (Canvas uses small pages by default): the rest of
// the membership is behind Link: <...>; rel="next". Follows every page and
// returns the combined container.
async function fetchCourseMembership(membershipsUrl, accessToken) {
  let url = membershipsUrl;
  let container = null;
  const members = [];
  for (let page = 0; url && page < NRPS_MAX_PAGES; page++) {
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.ims.lti-nrps.v2.membershipcontainer+json',
      },
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      throw new Error(`NRPS request failed (${resp.status}): ${text.slice(0, 200)}`);
    }
    const data = await resp.json(); // { id, context, members: [{ user_id, roles, status, name, email, ... }] }
    container = container || data;
    members.push(...(data.members || []));
    url = nextPageUrl(resp.headers.get('link'), url);
  }
  if (url) log.warn(`[NRPS] stopped after ${NRPS_MAX_PAGES} pages; roster may be incomplete`);
  // `complete` = every page was read; only then may absence from the roster mean "left".
  return { ...(container || {}), members, complete: !url };
}

// Fire-and-forget from /lti/launch -- never blocks the student/instructor's
// redirect on a roster sync. Pushes the full membership into tutor-service via
// the same /students/sync endpoint the legacy Moodle-native path uses, so both
// roster sources land in one place rather than needing two parallel systems.
// Students who left are kept (history) but taken off the roster: tutor-service
// lists and bills role 'student' only, and flips 'dropped' back when they
// return. Platforms signal leaving differently -- Canvas-style rosters list the
// member with status "Inactive", Moodle's simply stops listing a suspended or
// unenrolled student -- so both count, the latter only when the whole roster
// was read. Rosters are per course, so a student is only reported as dropped
// once they have no active membership in any course of this tenant.
async function syncRosterViaNrps(platform, membershipsUrl, launchContextId) {
  const accessToken = await getServiceAccessToken(platform, NRPS_SCOPE);
  const data = await fetchCourseMembership(membershipsUrl, accessToken);
  const members = data.members || [];
  const contextId = String((data.context && data.context.id) || launchContextId || '');
  const tenant = platform.tenant_key;
  const issuer = platform.issuer;

  const students = [];
  const leftThisCourse = new Set();
  const listed = new Set();
  let skippedObservers = 0;
  for (const m of members) {
    const subject = String(m.user_id);
    listed.add(subject);
    const internalRole = mapLtiRolesToInternalRole(m.roles || []);
    // Observers have no Rennix account (see launch.js) -- not synced, not billed.
    if (internalRole === 'observer') { skippedObservers += 1; continue; }
    if (m.status === 'Inactive') {
      if (contextId) await setMembership(tenant, issuer, contextId, subject, false);
      leftThisCourse.add(subject);
      continue;
    }
    if (contextId) await setMembership(tenant, issuer, contextId, subject, true);
    const userid = await getOrAllocateUserId(tenant, issuer, m.user_id, m.email);
    students.push({
      userid,
      username: m.email ? m.email.split('@')[0] : `nrps-${m.user_id}`,
      fullname: m.name || [m.given_name, m.family_name].filter(Boolean).join(' ') || 'Unknown',
      email: m.email || null,
      role: internalRole,
    });
  }
  // Previously active here but no longer listed in a complete roster -> left this course.
  if (contextId && data.complete) {
    const wasActive = await db.all(
      'SELECT subject FROM lti_memberships WHERE tenant_key = ? AND platform_issuer = ? AND context_id = ? AND active = 1',
      [tenant, issuer, contextId]);
    for (const { subject } of wasActive) {
      if (!listed.has(subject)) { await setMembership(tenant, issuer, contextId, subject, false); leftThisCourse.add(subject); }
    }
  }
  // Report as dropped only those with no active membership left anywhere, and
  // only people who actually have a Rennix account (never create one for them).
  let dropped = 0;
  for (const subject of leftThisCourse) {
    if (await hasActiveMembership(tenant, issuer, subject)) continue;
    const mappedId = await findMappedUserId(tenant, issuer, subject);
    if (!mappedId) continue;
    students.push({ userid: mappedId, username: `lti-${mappedId}`, fullname: null, email: null, role: 'dropped' });
    dropped += 1;
  }

  if (!TENANT_ADMIN_SECRET) {
    throw new Error('TENANT_ADMIN_SECRET is not configured -- cannot push the roster to tutor-service.');
  }
  const resp = await fetch(`${APP_BASE_URL}/students/sync`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-tenant-admin-secret': TENANT_ADMIN_SECRET },
    body: JSON.stringify({ tenant: platform.tenant_key, students }),
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`tutor-service /students/sync returned ${resp.status}: ${text.slice(0, 200)}`);
  }
  logAdminEvent('nrps_roster_synced',
    `tenant=${platform.tenant_key} members=${students.length} dropped=${dropped} observers_skipped=${skippedObservers}`, null);
}

module.exports = { getServiceAccessToken, fetchCourseMembership, syncRosterViaNrps, nextPageUrl, NRPS_SCOPE };
