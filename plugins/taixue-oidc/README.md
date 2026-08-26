# Taixue OIDC for Blessing Skin

This plugin is an OIDC relying party for Blessing Skin 6. It deliberately maps accounts only by the stable OIDC `sub`; email and nickname are never used to merge existing accounts.

Required environment variables:

- `TAIXUE_OIDC_ENABLED=false` (enable only after a client and callback are configured)
- `TAIXUE_OIDC_ISSUER=https://auth.taixue.cc`
- `TAIXUE_OIDC_CLIENT_ID`
- `TAIXUE_OIDC_CLIENT_SECRET`
- `TAIXUE_OIDC_AUTO_REGISTER=false`
- `TAIXUE_OIDC_ROLLOUT_MODE=allowlist` (`allowlist`, `bound`, or `all`)
- `TAIXUE_OIDC_ALLOWED_SUBJECTS=` (comma-separated stable OIDC subjects)
- `TAIXUE_OIDC_SHOW_LOGIN_BUTTON=false`
- `TAIXUE_OIDC_SHOW_ACCOUNT_MENU=false`
- `TAIXUE_OIDC_REVOCATION_SECRET=` (at least 32 random bytes; shared only with the user-service revocation worker)
- `SESSION_SECURE_COOKIE=true` (required; the plugin fails closed without a Secure session cookie)

Register the exact callback URL `https://skin.taixue.cc/auth/taixue/callback`. During migration, keep local password login enabled and ask existing users to link from the authenticated account page. Auto-registration must remain disabled until collision and rollback metrics have been reviewed.

Also register `https://skin.taixue.cc/auth/taixue/backchannel-logout` as the client's `backchannel_logout_uri` with `backchannel_logout_session_required=false`. The endpoint validates signed OIDC Logout Tokens and records a bounded revocation marker. OIDC-created Blessing Skin sessions check that marker at most every 30 seconds, so revocation works with file, database, or Redis session drivers without scanning or deleting raw session storage.

After updating an already-enabled plugin, disable and re-enable it once during the maintenance window so `PluginWasEnabled` creates `taixue_oidc_revocations` before accepting OIDC logins. If the table is unexpectedly missing, only OIDC-created sessions fail closed; local Blessing Skin sessions and the rest of the site remain available.

For password-change and password-recovery revocation, enable the user service's `session-revocation.blessing-skin` target with URL `https://skin.taixue.cc/auth/taixue/coordinated-logout` and the same secret. The durable user-service outbox signs the subject, request ID, and timestamp; retries keep the same idempotency identity. Leave the target disabled until both sides and the shared secret are deployed.

Existing-account login and linking request only `openid profile blessing_skin`. The plugin adds `email` only if automatic registration is explicitly enabled, so the gray migration does not ask users for data it does not use.

For the first gray release, enable the plugin while keeping both UI switches off and add only test identities to `TAIXUE_OIDC_ALLOWED_SUBJECTS`. An empty allowlist or an unknown rollout mode fails closed. Switch the mode to `all` only after the gray acceptance gates pass.

After the one-account allowlist passes, use `TAIXUE_OIDC_ROLLOUT_MODE=bound` to admit only identities whose signed ID Token contains a valid `bs_uid` from the dedicated `blessing_skin` scope. This expands unified login to already-associated skin-site users without matching by email/nickname or enabling automatic registration. Keep local login and recovery visible. `bound` fails closed for missing, zero, malformed, or unsigned binding claims.

Skin-site administrators can review `/admin/taixue-oidc` before expanding the rollout. It shows aggregate mappings, fallback-password readiness, recent outcomes and bounded failure reasons without exposing client secrets, tokens or allowlist subjects.

Deployment automation should probe `GET /auth/taixue/ready` after the plugin is enabled. It returns `204` only when the required secrets, Secure session cookies and all migration tables are available, otherwise `503`. Do not probe logout endpoints with fabricated tokens: rejected logout traffic is deliberately retained as a security audit event and would corrupt operational failure metrics.

For a zero-click migration, the dedicated Taixue `blessing_skin` scope should emit an integer `bs_uid` claim from the accepted `BS` identity binding. The internal UID is deliberately excluded from the general `profile` scope. Because the claim is inside the signed ID Token, the plugin may use it to create the local `sub` mapping. A conflicting `bs_uid`, local UID, or `sub` is rejected; email and nickname remain display-only attributes.

## Migration acceptance gates

Keep local password login and recovery available throughout the migration. Do not switch `TAIXUE_OIDC_ROLLOUT_MODE` to `all` until all of these gates have passed for the allowlist:

- Every successful login preserves the same Blessing Skin `uid`; no account is matched by email or nickname.
- A signed `bs_uid` that disagrees with the stored `sub` mapping is rejected and investigated instead of silently choosing either account.
- Existing local passwords still work, and Taixue password recovery can issue a fresh code after an older code expires. OIDC login must create only a session-scoped Blessing Skin login, never an implicit remember-me cookie. Standard provider-initiated logout must invalidate an already-issued OIDC Blessing Skin session within 30 seconds. Password reset/change must additionally trigger provider logout or the coordinated subject-revocation outbox before full rollout; deleting only Hydra's remembered login/consent session is not sufficient evidence that an RP logout notification was sent.
- Blessing Skin's own forgot-password flow marks the recovered local password as a usable fallback credential, so a provisioned user can safely unlink after recovery instead of being trapped in the provisioned state.
- Provisioned accounts cannot unlink OAuth until a usable Blessing Skin local password has been established. They can create that fallback credential only after a fresh Taixue reauthentication; the one-time grant is bound to the same local UID and OIDC subject and expires after five minutes. Changing the Taixue unified-account password does not satisfy this gate; only a Blessing Skin local password update marks the account safe to unlink.
- Tightening or emptying the rollout allowlist may block new login and linking, but must never block an already authenticated user from fresh-authenticated local-password setup or unlinking. Recovery must remain available during rollback.
- Failed, cancelled, expired, replayed, wrong-audience, and wrong-`azp` authorization responses leave the local account and link table unchanged.
- Operators can correlate callback failures without logging authorization codes, tokens, client secrets, passwords, or recovery codes.
- Link, login, registration, rejection, and unlink events are written to `taixue_oidc_audit_events` with a request ID, actor UID when known, stable subject when verified, IP, user agent, and bounded non-secret metadata. Error pages expose the same request ID.
- Unlinking requires a fresh Taixue login (`prompt=login`, `max_age=0`); a remembered SSO session alone is not accepted.

Rollback is intentionally data-preserving: hide the login and account-menu entries, set the rollout mode back to an allowlist (or disable the plugin), and keep `taixue_oidc_links` intact. Users then continue with their existing local login while operators investigate. Do not delete link rows as part of an operational rollback.

Uninstalling the plugin also preserves `taixue_oidc_links` and `taixue_oidc_audit_events`. Purging migration identity or audit data is a separate, deliberate database operation and is never part of routine rollback or reinstall.
