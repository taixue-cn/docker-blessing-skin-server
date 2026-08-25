# Taixue OIDC for Blessing Skin

This plugin is an OIDC relying party for Blessing Skin 6. It deliberately maps accounts only by the stable OIDC `sub`; email and nickname are never used to merge existing accounts.

Required environment variables:

- `TAIXUE_OIDC_ENABLED=false` (enable only after a client and callback are configured)
- `TAIXUE_OIDC_ISSUER=https://auth.taixue.cc`
- `TAIXUE_OIDC_CLIENT_ID`
- `TAIXUE_OIDC_CLIENT_SECRET`
- `TAIXUE_OIDC_AUTO_REGISTER=false`
- `TAIXUE_OIDC_ROLLOUT_MODE=allowlist`
- `TAIXUE_OIDC_ALLOWED_SUBJECTS=` (comma-separated stable OIDC subjects)
- `TAIXUE_OIDC_SHOW_LOGIN_BUTTON=false`
- `TAIXUE_OIDC_SHOW_ACCOUNT_MENU=false`

Register the exact callback URL `https://skin.taixue.cc/auth/taixue/callback`. During migration, keep local password login enabled and ask existing users to link from the authenticated account page. Auto-registration must remain disabled until collision and rollback metrics have been reviewed.

For the first gray release, enable the plugin while keeping both UI switches off and add only test identities to `TAIXUE_OIDC_ALLOWED_SUBJECTS`. An empty allowlist or an unknown rollout mode fails closed. Switch the mode to `all` only after the gray acceptance gates pass.

For a zero-click migration, the dedicated Taixue `blessing_skin` scope should emit an integer `bs_uid` claim from the accepted `BS` identity binding. The internal UID is deliberately excluded from the general `profile` scope. Because the claim is inside the signed ID Token, the plugin may use it to create the local `sub` mapping. A conflicting `bs_uid`, local UID, or `sub` is rejected; email and nickname remain display-only attributes.

## Migration acceptance gates

Keep local password login and recovery available throughout the migration. Do not switch `TAIXUE_OIDC_ROLLOUT_MODE` to `all` until all of these gates have passed for the allowlist:

- Every successful login preserves the same Blessing Skin `uid`; no account is matched by email or nickname.
- A signed `bs_uid` that disagrees with the stored `sub` mapping is rejected and investigated instead of silently choosing either account.
- Existing local passwords still work, Taixue password recovery can issue a fresh code after an older code expires, and resetting a Taixue password revokes remembered and OAuth sessions.
- Provisioned accounts cannot unlink OAuth until a usable Blessing Skin local password has been established. They can create that fallback credential only after a fresh Taixue reauthentication; the one-time grant is bound to the same local UID and OIDC subject and expires after five minutes. Changing the Taixue unified-account password does not satisfy this gate; only a Blessing Skin local password update marks the account safe to unlink.
- Tightening or emptying the rollout allowlist may block new login and linking, but must never block an already authenticated user from fresh-authenticated local-password setup or unlinking. Recovery must remain available during rollback.
- Failed, cancelled, expired, replayed, wrong-audience, and wrong-`azp` authorization responses leave the local account and link table unchanged.
- Operators can correlate callback failures without logging authorization codes, tokens, client secrets, passwords, or recovery codes.
- Link, login, registration, rejection, and unlink events are written to `taixue_oidc_audit_events` with a request ID, actor UID when known, stable subject when verified, IP, user agent, and bounded non-secret metadata. Error pages expose the same request ID.
- Unlinking requires a fresh Taixue login (`prompt=login`, `max_age=0`); a remembered SSO session alone is not accepted.

Rollback is intentionally data-preserving: hide the login and account-menu entries, set the rollout mode back to an allowlist (or disable the plugin), and keep `taixue_oidc_links` intact. Users then continue with their existing local login while operators investigate. Do not delete link rows as part of an operational rollback.

Uninstalling the plugin also preserves `taixue_oidc_links` and `taixue_oidc_audit_events`. Purging migration identity or audit data is a separate, deliberate database operation and is never part of routine rollback or reinstall.
