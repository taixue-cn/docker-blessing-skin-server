# Taixue OIDC for Blessing Skin

This plugin is an OIDC relying party for Blessing Skin 6. It deliberately maps accounts only by the stable OIDC `sub`; email and nickname are never used to merge existing accounts.

Required environment variables:

- `TAIXUE_OIDC_ENABLED=false` (enable only after a client and callback are configured)
- `TAIXUE_OIDC_ISSUER=https://auth.taixue.cc`
- `TAIXUE_OIDC_CLIENT_ID`
- `TAIXUE_OIDC_CLIENT_SECRET`
- `TAIXUE_OIDC_AUTO_REGISTER=false`

Register the exact callback URL `https://skin.taixue.cc/auth/taixue/callback`. During migration, keep local password login enabled and ask existing users to link from the authenticated account page. Auto-registration must remain disabled until collision and rollback metrics have been reviewed.

For a zero-click migration, the dedicated Taixue `blessing_skin` scope should emit an integer `bs_uid` claim from the accepted `BS` identity binding. The internal UID is deliberately excluded from the general `profile` scope. Because the claim is inside the signed ID Token, the plugin may use it to create the local `sub` mapping. A conflicting `bs_uid`, local UID, or `sub` is rejected; email and nickname remain display-only attributes.
