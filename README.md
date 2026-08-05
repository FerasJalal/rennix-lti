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
cp .env.example .env   # set ADMIN_SECRET and SESSION_SECRET to real random values
docker compose up -d --build
```

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

## Not yet built

- Dynamic Registration (auto-onboarding instead of manual `/admin/platforms` calls)
- Deep Linking, Names and Roles Provisioning, Assignment and Grade Services (only a basic
  resource-link launch is implemented)
- Wiring a verified launch into the real product UI — right now it lands on a proof-of-concept
  page showing the verified identity, not the actual app
