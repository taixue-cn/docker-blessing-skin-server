# Taixue OIDC for Blessing Skin

This plugin is an OIDC relying party for Blessing Skin 6. It deliberately maps accounts only by the stable OIDC `sub`; email and nickname are never used to merge existing accounts.

Required environment variables:

- `TAIXUE_OIDC_ENABLED=false` (enable only after a client and callback are configured)
- `TAIXUE_OIDC_ISSUER=https://auth.taixue.cc`
- `TAIXUE_OIDC_CLIENT_ID`
- `TAIXUE_OIDC_CLIENT_SECRET`
- `TAIXUE_OIDC_REDIRECT_URI=https://skin.taixue.cc/auth/taixue/callback` (must exactly match the Hydra client; it is never derived from the request host)
- `TAIXUE_OIDC_AUTO_REGISTER=false`
- `TAIXUE_OIDC_ROLLOUT_MODE=allowlist` (`allowlist`, `bound`, or `all`)
- `TAIXUE_OIDC_ALLOWED_SUBJECTS=` (comma-separated stable OIDC subjects)
- `TAIXUE_OIDC_SHOW_LOGIN_BUTTON=false`
- `TAIXUE_OIDC_AUTO_REDIRECT=false` (after acceptance, redirect the ordinary login page directly to Taixue OIDC)
- `TAIXUE_OIDC_REVOCATION_SECRET=` (at least 32 random bytes; shared only with the user-service revocation worker)
- `TAIXUE_OIDC_PROVISIONING_URL=https://auth.taixue.cc/api/v1/internal/blessing-skin/provisioning` (the user-service HTTPS provisioning receipt endpoint; the public auth host must use its `/api` reverse proxy)
- `TAIXUE_OIDC_PROVISIONING_SECRET=` (a separate secret of at least 32 random bytes; never reuse the client or revocation secret)
- `TAIXUE_OIDC_CREATE_ENABLED=false` (enable after the user-service durable provisioning worker is configured)
- `TAIXUE_OIDC_CREATE_SECRET=` (a fourth, independent secret of at least 32 random bytes for account-creation requests)
- `TAIXUE_OIDC_PASSWORD_SYNC_SECRET=` (an independent secret of at least 32 random bytes used only for password synchronization; readiness rejects reuse of the creation, provisioning-receipt, or revocation secret)
- `TAIXUE_OIDC_CREATE_CLOCK_SKEW_SECONDS=300`
- `TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY=false` (after migration acceptance, redirect registration/recovery/contact management to Taixue and lock the one-player identity boundary)
- `SESSION_SECURE_COOKIE=true` (required; the plugin fails closed without a Secure session cookie)

Rejected provisioning receipts log only the internal request ID, HTTP status,
bounded machine error code, and completion flag. Response bodies, credentials,
tokens, signatures, subjects, player names, and account IDs are never logged.

Provisioning receipts use a signed v2 account snapshot so the user service can
atomically reconcile its restricted read mirror before committing BS and
PLAYER bindings. This closes the MySQL-success/PostgreSQL-lag crash window.
Password verifiers are HMAC-covered and sent only over HTTPS; they are never
written to migration jobs, audit metadata, or application logs.

Register the exact callback URL `https://skin.taixue.cc/auth/taixue/callback`. During migration, keep local password login enabled while the user service automatically imports or binds verified accounts. The plugin exposes no ordinary-user link/unlink page: repairs belong to the CheckUserPermission-gated unified administration flow. Auto-registration must remain disabled until collision and rollback metrics have been reviewed.

Password synchronization is idempotent: replaying the account's current `$SHA$` verifier confirms and advances the signed version without treating MySQL's zero changed-row count as a missing account.

An account that has entered through OIDC is already managed by Taixue even before the global unified-only switch. Its profile replaces local password, email and deletion forms with links to the unified account center, and its local player cardinality cannot be changed. Legacy users entering through the explicit local recovery path keep those controls until they migrate. Native Blessing Skin administrator endpoints for password, email, ownership, rename and identity deletion are always rejected while the plugin is enabled; permissioned repairs must use the Taixue administration flow.

Also register `https://skin.taixue.cc/auth/taixue/backchannel-logout` as the client's `backchannel_logout_uri` with `backchannel_logout_session_required=false`. The endpoint validates signed OIDC Logout Tokens and records a bounded revocation marker. OIDC-created Blessing Skin sessions check that marker at most every 30 seconds, so revocation works with file, database, or Redis session drivers without scanning or deleting raw session storage.

After updating an already-enabled plugin, disable and re-enable it once during the maintenance window so `PluginWasEnabled` creates `taixue_oidc_revocations` before accepting OIDC logins. If the table is unexpectedly missing, only OIDC-created sessions fail closed; local Blessing Skin sessions and the rest of the site remain available.

For password-change and password-recovery revocation, enable the user service's `session-revocation.blessing-skin` target with URL `https://skin.taixue.cc/auth/taixue/coordinated-logout` and the same secret. The durable user-service outbox signs the subject, request ID, and timestamp; retries keep the same idempotency identity. Leave the target disabled until both sides and the shared secret are deployed.

Existing-account login requests only `openid profile blessing_skin`. The plugin adds `email` only if automatic registration is explicitly enabled, so the gray migration does not ask users for data it does not use.

For the first gray release, enable the plugin while keeping both UI switches off and add only test identities to `TAIXUE_OIDC_ALLOWED_SUBJECTS`. An empty allowlist or an unknown rollout mode fails closed. Switch the mode to `all` only after the gray acceptance gates pass.

Enable `TAIXUE_OIDC_AUTO_REDIRECT` only after the full login and rollback journey has passed. During gray rollout, the ordinary `GET /auth/login` then returns a server-side redirect to the Taixue authorization flow, so the legacy password form never flashes before navigation. The local form remains reachable at `/auth/login?local=1` for migration recovery, but the ordinary UI does not advertise that URL. Turning the flag off immediately restores the normal local login page without deleting sessions, links, or account data. The redirect middleware is registered only after the plugin's Secure-cookie gate passes, so a bad cookie configuration cannot hide the fallback form.

Callback failures never link “retry” back to the automatically redirected login page. They provide a direct unified-login retry and, while unified-only mode is still disabled, a clearly labelled `/auth/login?local=1` recovery action. This prevents migration conflicts and temporary provider failures from trapping a user in an OIDC redirect loop. Unified-only mode omits the local recovery action entirely.

After `TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY=true`, `/auth/login?local=1` also redirects to OIDC and direct local password POSTs are rejected by Blessing Skin's `can_login` domain filter. Hydra is then the only browser authentication source. Emergency rollback is configuration-based: set unified-only and automatic redirect to `false`, verify readiness and the local login journey, and leave all OIDC links and account data intact. There is no user-visible secret bypass in unified-only mode.

Use `scripts/update-rollout-env.php` instead of editing rollout variables by hand. The command requires the expected current mode and subject list, defaults to dry-run, validates UTF-8, and changes only `TAIXUE_OIDC_ROLLOUT_MODE` plus `TAIXUE_OIDC_ALLOWED_SUBJECTS`. Applying additionally requires a new backup path and performs a final content-hash comparison before an atomic replacement. Pass `-` as the subject-list value for an empty list; allowlist mode requires comma-separated IDs.

```sh
php scripts/update-rollout-env.php --env=/var/www/html/.env \
  --expect-mode=allowlist --expect-allowed-subjects=63719050877927426 \
  --set-mode=bound --set-allowed-subjects=-
# Re-run with --backup=/private/path/before-bound.env --apply after reviewing the hashes.
```

Use `scripts/update-identity-mode-env.php` for the five non-secret browser and provisioning gates. It has the same expected-value CAS, dry-run, UTF-8, private backup, metadata-preserving atomic replacement, and idempotency guarantees. It refuses unified-only mode unless automatic redirect is enabled and the current rollout is exactly `all` with no retained subject list. This makes `GET /auth/taixue/ready` fail closed for a configuration that would lock unbound users out.

```sh
php scripts/update-identity-mode-env.php --env=/var/www/html/.env \
  --expect-auto-redirect=false --set-auto-redirect=true \
  --expect-unified-identity-only=false --set-unified-identity-only=false \
  --expect-auto-register=false --set-auto-register=false \
  --expect-create-enabled=true --set-create-enabled=true \
  --expect-show-login-button=true --set-show-login-button=false
# Re-run with --backup=/private/path/before-automatic-entry.env --apply after review.
```

Use `scripts/update-redirect-uri-env.php` to pin the callback without exposing or rewriting unrelated secrets. Pass `-` to `--expect` only when the key is currently absent. The command is a UTF-8-preserving dry-run by default and requires a new private backup path for the atomic apply.

```bash
php scripts/update-redirect-uri-env.php --env=/var/www/html/.env \
  --expect=- --set=https://skin.taixue.cc/auth/taixue/callback
# Re-run with --backup=/private/path/before-redirect-uri.env --apply after review.
```

Unified-only mode also blocks the native web and OAuth API endpoints that let Blessing Skin role administrators change local passwords or emails, delete users, or rename/reassign/delete players. Those identity repairs belong to the Taixue administration page and its existing `CheckUserPermission` authorization. Native skin-site operations such as texture management, score, nickname and reports remain available; the plugin does not pretend that a local Blessing Skin role is a Taixue identity administrator.

After the one-account allowlist passes, use `TAIXUE_OIDC_ROLLOUT_MODE=bound` to admit only identities whose signed ID Token contains a valid `bs_uid` from the dedicated `blessing_skin` scope. This expands unified login to already-associated skin-site users without matching by email/nickname or enabling automatic registration. Keep local login and recovery visible. `bound` fails closed for missing, zero, malformed, or unsigned binding claims.

Migration conflicts and repairs are reviewed in the unified auth administration page, whose authorization is backed by `CheckUserPermission`. The plugin deliberately exposes no separate role-based administrator page.

Deployment automation should probe `GET /auth/taixue/ready` after the plugin is enabled. It returns `204` only when the required secrets, Secure session cookies and all migration tables are available, otherwise `503`. Do not probe logout endpoints with fabricated tokens: rejected logout traffic is deliberately retained as a security audit event and would corrupt operational failure metrics.

Run `php plugins/taixue-oidc/scripts/audit-unified-only-acceptance.php --require-ready`
before enabling unified-only mode. Its secret-free JSON fails closed until both logout endpoints have
resolved a real linked UID and a live OIDC session has independently observed each revocation source.

For a zero-click migration, the dedicated Taixue `blessing_skin` scope should emit an integer `bs_uid` claim from the accepted `BS` identity binding. The internal UID is deliberately excluded from the general `profile` scope. Because the claim is inside the signed ID Token, the plugin may use it to create the local `sub` mapping. A conflicting `bs_uid`, local UID, or `sub` is rejected; email and nickname remain display-only attributes.

## Migration acceptance gates

Keep local password login and recovery available throughout the migration. Do not switch `TAIXUE_OIDC_ROLLOUT_MODE` to `all` or enable `TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY` until all of these gates have passed for the allowlist:

When the plugin is enabled, the skin-site login page shows separate recovery links for the Taixue unified account and the legacy skin-site account. The local recovery link remains available even if OIDC is temporarily disabled by the Secure-cookie safety gate, provided Blessing Skin mail delivery is configured. Deployment smoke tests verify both links so rollback cannot strand existing users.

- Every successful login preserves the same Blessing Skin `uid`; no account is matched by email or nickname.
- Every provisioned skin account owns exactly one player whose name is the signed Taixue `name` claim. Historical users with zero or multiple players are conflicts and are never guessed or silently repaired. This is a Blessing Skin account invariant only: a Taixue identity may still bind multiple MC accounts, while exactly one canonical player maps to this BS UID.
- A signed `bs_uid` that disagrees with the stored `sub` mapping is rejected and investigated instead of silently choosing either account.
- Existing local passwords still work before unified-only mode, and Taixue password recovery can issue a fresh code after an older code expires. OIDC login must create only a session-scoped Blessing Skin login, never an implicit remember-me cookie. Standard provider-initiated logout must invalidate an already-issued OIDC Blessing Skin session within 30 seconds. Password reset/change must additionally trigger provider logout or the coordinated subject-revocation outbox before full rollout.
- Logout evidence counts only when the audit event resolves to a real linked local `uid`. A valid logout for an unknown subject is replay-safe endpoint evidence, not proof that a user's Blessing Skin session was revoked. Standard back-channel logout and password-change coordinated logout must pass independently.
- Endpoint success proves delivery only. Full acceptance also requires a later `SESSION_REVOKED/SUCCEEDED` event with the same linked subject and UID, emitted when an already-authenticated OIDC session observes the revocation. Its bounded `source` is `BACKCHANNEL_LOGOUT` or `COORDINATED_LOGOUT`, so both journeys can be accepted independently. This evidence stores only whether a `sid` existed; it never stores cookies, tokens, `jti`, or the `sid` value.
- In unified-only mode, registration, recovery, email and password management redirect to Taixue; direct password, email, and local-account deletion mutations are rejected server-side. The self-service delete card is removed, while permissioned administrator repair remains available. Player add/delete/rename operations are rejected while skin and cape operations remain available.
- Failed, cancelled, expired, replayed, wrong-audience, and wrong-`azp` authorization responses leave the local account and link table unchanged.
- Operators can correlate callback failures without logging authorization codes, tokens, client secrets, passwords, or recovery codes.
- Login, registration, rejection and revocation events are written to `taixue_oidc_audit_events` with a request ID, actor UID when known, stable subject when verified, IP, user agent, and bounded non-secret metadata. Error pages expose the same request ID.

Rollback is intentionally data-preserving: first set `TAIXUE_OIDC_UNIFIED_IDENTITY_ONLY=false` and `TAIXUE_OIDC_AUTO_REDIRECT=false`, then set the rollout mode back to an allowlist (or disable the plugin), and keep `taixue_oidc_links` intact. Users then continue with their existing local login while operators investigate. Do not delete link rows as part of an operational rollback.

Uninstalling the plugin also preserves `taixue_oidc_links` and `taixue_oidc_audit_events`. Purging migration identity or audit data is a separate, deliberate database operation and is never part of routine rollback or reinstall.
