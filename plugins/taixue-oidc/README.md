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
