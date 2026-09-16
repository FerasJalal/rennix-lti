# rennix-lti

LTI 1.3 Tool (the "Tool" side of the spec) that any institution's LMS launches into as a standard
**External Tool** — no custom plugin install, no backend access on their side. Separate from
`tutor-service` (the single-tenant HTU pilot); this is the multi-tenant connector.

Two independently purchasable products, registered as two separate External Tools per
institution (each gets its own `client_id` from their LMS admin):

- **Rennix Analytics**
- **Rennix Tutor Bot**

**Status: live-tested against HTU's real Moodle.** Both tools are registered there (via
`mod_lti`'s own `lti_add_type()`, not hand-rolled DB rows) and a real signed launch was verified
end-to-end as `teacher1` for both. Two real bugs were caught by that test and are fixed on `main`:
Moodle sends the OIDC login-initiation request via POST (the spec allows either GET or POST;
only GET was implemented at first), and `req.protocol` needs `app.set('trust proxy', true')` or
it reports `http` behind Caddy, breaking `redirect_uri` matching.

## How a launch works

1. Institution's admin adds an External Tool in their LMS pointing at
   `https://<this-service>/lti/login`, using a `client_id`/`deployment_id` we issue them, and
   configures their platform's own `auth_login_url` / `jwks_url` (standard LTI registration
   fields their LMS provides).
2. We record that registration via `POST /admin/platforms` (manual registration for now — no
   Dynamic Registration support yet).
3. A user launches the tool from their course. Their LMS redirects the browser to `/lti/login`,
   we redirect to the LMS's own auth endpoint, the LMS POSTs back a signed `id_token` to
   `/lti/launch`, we verify it against the LMS's published JWKS, and only then trust the
   identity/role/course claims inside it.

## Setup

```bash
cp .env.example .env   # set ADMIN_SECRET, SESSION_SECRET, and KEY_ENCRYPTION_SECRET to real random values
docker compose up -d --build
```

Admin pages: `/admin` (onboard/manage platforms) and `/admin/audit` (audit log), both behind
`/admin/login`.

## Registering a platform (manual, until Dynamic Registration is built)

```bash
curl -X POST https://<this-service>/admin/platforms \
  -H "x-admin-secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "product": "tutor_bot",
    "tenantKey": "htu",
    "tenantName": "Al-Hussein Technical University",
    "issuer": "https://edu.rennix.ai",
    "clientId": "<from their LMS admin External Tool config>",
    "deploymentId": "<from their LMS admin External Tool config>",
    "authLoginUrl": "https://edu.rennix.ai/mod/lti/auth.php",
    "jwksUrl": "https://edu.rennix.ai/mod/lti/certs.php"
  }'
```

## Data

SQLite (`better-sqlite3`), persisted via the `lti_data` Docker volume — just platform
registrations and short-lived login state/nonces, nothing else.

## How a verified launch reaches the real app

A verified launch mints a signed bridge token (`LTI_BRIDGE_SECRET`, shared with tutor-service —
separate from block_criterio's `IDENTITY_SECRET`) and redirects straight to tutor-service's real
`/app/instructor` or `/app/home`. tutor-service is multi-tenant as of the corresponding change
there: each institution gets its own fully isolated database, resolved only from this signed
token, never a client-suppliable parameter. LTI's own user identifier (`sub`, an opaque
platform-chosen string) is mapped to a stable per-tenant integer id on first launch and reused on
every later one; first-time users are auto-provisioned from the platform's own verified
name/email/role claims, since there's no Moodle-style manual roster sync for institutions that
connect this way.

`/lti/launched` (the old proof-of-concept identity page) is still there but no longer used by the
real flow — harmless to keep as a debug page.

## Architecture

`server.js` is only the composition root (middleware + router mounting + listen). The actual
routes and business logic live in `src/`:

- `src/config.js`, `src/db.js`, `src/audit.js` -- shared config, SQLite schema/access, admin audit
  logging.
- `src/security/` -- token signing/verification (bridge token, admin session, this tool's own
  RS256 key pair for signing outbound JWTs).
- `src/rateLimit.js` -- in-memory per-process rate limiting (single-instance only, see below).
- `src/lti/` -- the LTI protocol itself: login, launch/verification, Deep Linking, NRPS roster
  sync, role mapping, and the cached-per-platform JWKS lookup.
- `src/admin/` -- the admin auth/session, platform registration API, and onboarding UI.

Run `npm test` (Node's built-in test runner, `test/`) to exercise the JWT verification, nonce/
replay, deployment-id, and role-mapping logic end-to-end against a locally generated key pair --
no real LMS needed for that layer.

## Known limitations

- **Single-instance only.** Rate-limit buckets (`src/rateLimit.js`) and the NRPS/AGS service-token
  cache (`src/lti/nrps.js`) are in-memory per process, same as the SQLite database itself (a local
  Docker volume, not a shared store). None of this is safe to run as multiple replicas behind a
  load balancer without moving all three to a shared store together.
- The four cross-service secrets (`ADMIN_SECRET`, `SESSION_SECRET`, `LTI_BRIDGE_SECRET`,
  `TENANT_ADMIN_SECRET`) are still plain env vars -- no secrets manager or rotation story yet. This
  tool's own RSA private key, the one thing actually persisted to disk, is encrypted at rest when
  `KEY_ENCRYPTION_SECRET` is set (see `src/security/keyEncryption.js`); it stays plaintext if that
  var is left unset, with a startup warning.

## Multi-deployment support

A single registration (`issuer` + `client_id`) can now launch from more than one
`deployment_id` -- not all platforms tie the two 1:1 the way Moodle's `mod_lti` does (Canvas, for
example, can mint a fresh `deployment_id` per course/account that installs the same client). The
`deployment_id` given at registration is always accepted; `POST /admin/platforms/:id/deployments`
adds more, and each registered platform's `/admin` row shows how many it has. This is groundwork
for Dynamic Registration (below), which will auto-discover additional deployments the same way.

## Not yet built

- Dynamic Registration (auto-onboarding instead of manual `/admin/platforms` calls)
- Assignment and Grade Services (Deep Linking and Names and Roles Provisioning are implemented)
