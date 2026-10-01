# Native ARM policy qualification: exact-input boundary

Tracking: https://github.com/StackVista/stackstate/issues/717

Request: yaml-migration-scanner-native-arm-policy-controls-20261001.

No native ARM real-image policy controls were executed. The recovered host is
x86_64; it is not a substitute for a native ARM runner. Existing amd64 policy
receipts and successful native source/build/contracts remain valid and were not
rerun. This evidence-only change leaves scanners, evaluator, actions and workflows
unchanged.

## Verified available capability and candidates

The existing approved `ubuntu-24.04-arm` lane succeeded for newer source
5c5ac0665b8c308ac7efa05ee397ef5f9e02c255 (run 36883982986, runner
GitHub Actions 1002114848) and older source
906ee014101bb9a1697e91b0ba44e86d5b9044cc (run 36894751503, runner
GitHub Actions 1002116339). These are source/contracts, not image-policy receipts.

The original signed candidate bundles were recovered. Both ARM checksum and
provenance signatures verified with the exact GitHub workflow certificate identity
and GitHub OIDC issuer. Every SHA256SUMS entry verified; ARM archive digests match
the earlier receipts. Extracted binaries have ELF machine 183 (AArch64); Go metadata
matches the original candidate revision, maintained YAML and absence of archived
parser module identities. They were not executed on this x86_64 host.

`verified-arm-candidates.json`, signature bundles, artifact API receipts and native
job receipts retain the exact associations and expiry. Artifacts expire October 15,
2026; access/retention outside this repository remains separately unqualified.
Original Grype ARM archives also match their officially signed release checksums;
their binary hashes/module metadata are in `original-arm-grype.json`. No upstream
ARM binary was executed here.

## Failed exact frozen-input reconstruction

The official Grype archive is still public and its SHA256 matches
c0d0263192d91df04b242e9a91e34cb289118fb08f1ed56eb0239eb57d7a517f.
The unpacked DB does not equal the accepted hydrated DB. Two bounded original-tool
preparation routes were attempted: direct 0.118 import, and 0.112 import followed by
0.118 reader rehydration. All completed successfully, but neither reproduced the
required accepted hash:

`d16211e678fbd9fa8da33145c1eedbefa6ac3f3f2e0dd8c6acddb36bd29f027e`.

`reconstruction.json` records all resulting hashes, commands and exits.
Original release checksum signatures were verified before executing those
preparation commands; original binary hashes, versions and Go metadata were
checked. These commands reconstruct a database, not repeat amd64 scanner controls.
No altered DB was accepted, frozen or used for an ARM policy claim.

The original Grype sources at
`scanner-runtime/sources/grype-0.118.0/grype/db/v6/installation/curator.go`
(`Reader`, `isRehydrationNeeded`, `hydrate`) and `grype/db/v6/db.go` (`Hydrater`)
show client-version-dependent schema/index auto-migration and regenerated import
metadata. Matching database records or version is insufficient for the required
byte identity. These attempts do not establish the cause of every byte difference
or that future exact reconstruction is impossible.

The immutable Trivy layer and extracted SQLite DB reproduced their recorded hashes.
Its published metadata differs from the locally frozen metadata; the latter's
exact bytes are already retained in the input archive and must be restored.
VEX/config/fixtures are also retained there. The missing input is specifically
the accepted hydrated Grype SQLite file, not all frozen inputs.

## Supported minimal lane proposal

Once the exact accepted Grype DB bytes are recovered and retained through an
approved existing artifact lane, add a separate PR policy workflow; do not attach
controls to source-build jobs or dispatch completed builds. Use the existing
`ubuntu-24.04-arm` runner and a serial two-generation matrix, same-repository PR
guard, pinned existing checkout/download/upload/Cosign actions, no persistent git
credentials, workflow permissions empty and only contents/actions read in the
policy job. A separate signing job may use the existing OIDC path only after
successful prerequisite controls. No runner provisioning or new credential.

Download the exact original signed candidate artifacts by original run/source,
verify artifact/archive hashes, checksum and provenance signature identities before
restoring executable modes. Download exact same-version upstream Trivy/Grype ARM
release archives and verify official signatures/checksums before execution.
Build only the small evaluator at signed source 0a1619a8 using the existing signed
BCI builder and its required toolchain; do not rebuild scanners or owner contracts.

Extend identity guards explicitly for native ARM: require host aarch64, ELF machine
183, expected mode/path/SHA/version, exact source/module metadata and symbol audit
before every invocation, including identity/version subprocesses. No emulation or
PATH fallback. Materialize exact input bytes and verify every accepted manifest
entry, with separate writable caches for every invocation and full before/after
checks that reject rehydration or mutation.

Run only the missing original/candidate clean, vulnerable, BCI, actual secret-policy,
malformed exception, broken DB and both absent/unreachable VEX controls in both
modes. Preserve the newer canonical and older A policy snapshots independently.
Retain every raw report/command/exit/identity/input receipt with an always-upload
step even when comparisons fail. Compare original/candidate within ARM first;
record cross-architecture differences separately. Only existing approved volatile
timestamps/report IDs/output paths may be normalized, never substantive fields.
Older Grype strict JSON/SARIF remains unqualified pending root disposition.

No workflow was added which would silently replace the required DB or pretend a
skipped lane passed. Root's next action is to recover the exact hydrated snapshot,
or explicitly select a different frozen snapshot and separately authorize a new
matched amd64 baseline. Neither decision is assumed here. Historical B/D policy,
consumer loader/pins, publication/access/expiry, Toolbox/Kafka and real-image ARM
qualification remain separate boundaries.
