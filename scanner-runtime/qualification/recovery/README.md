These controls qualify binaries from CI run 36883982986 at source
5c5ac0665b8c308ac7efa05ee397ef5f9e02c255. They do not qualify a consumer loader.
Downloaded executable permissions must be restored only after archive/checksum
and OIDC verification. Every control checks the exact file SHA256, absolute path,
version and Go build metadata before invoking that absolute path. PATH fallback
results from the interrupted earlier local harness are invalid and excluded.
