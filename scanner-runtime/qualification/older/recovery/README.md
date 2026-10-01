# Older runtime recovery — 2026-10-01

Tracking: https://github.com/StackVista/stackstate/issues/717

PR50 is stacked on PR49. Native run 36894751503 built source
906ee014101bb9a1697e91b0ba44e86d5b9044cc on amd64 and arm64; both native jobs
and the signing job succeeded. Security run 36894751155 succeeded.
The recovery commit changes evidence only, not the tested source or action pins.

`native-verification.json` records independently downloaded archive checksums,
binary checksums, all manifest-file checks and contract counts. Each architecture
passed 8,443 test/subtest events, with one existing Testify skip. Both checksum
and provenance manifests verified with Cosign against:

- Identity: `https://github.com/StackVista/image-pipeline/.github/workflows/older-scanner-runtime-ci.yml@refs/pull/50/merge`
- Issuer: `https://token.actions.githubusercontent.com`

`ci-artifacts.json` records actual artifact IDs, GitHub artifact digests and expiry.
Archives contain inventories, patch attribution, licenses, builder proof, effective
package/module graphs, binary build metadata, audit symbols and contract logs.
Trivy retains maintained v2.4.3 and v3.0.5; Grype retains maintained v3.0.5.
Neither actual binary metadata nor audit symbols contain archived YAML identities.
No global parser replacement, tool generation update or policy change is included.

## Interrupted local control evidence

The runner replacement removed the unpushed local harness, frozen DB/VEX inputs,
raw JSON/SARIF and identity logs. Earlier session results reported all 28 primary
policy cases and B/D action-block controls matching. Those observations remain
session history, **not newly recovered durable test evidence**. No passing native
lane was rerun. Do not claim complete consumer or output equivalence from this file.

The earlier frozen inputs were Trivy DB SHA256
`c39ee6b7f92119e7fadd7bc626d15ca8de69a56522529eeab027f6c9c433a27a`
and Grype DB SHA256
`02f2ce94a439267f0735d2e27c46dffbb991cb42330408d794bd75dade93eeb8`.
Grype import archive:
`c0d0263192d91df04b242e9a91e34cb289118fb08f1ed56eb0239eb57d7a517f`.
These values identify the lost input; they do not establish its current availability.

## Grype output boundary

The preceding exact-input investigation reported 535 matches for original and
candidate Grype 0.112.0/Syft 1.44.0. An original repeat changed 35 exact match
objects; original versus candidate changed 36. CVE/artifact/severity multisets,
artifact records, match details and related vulnerabilities matched. Differences
included namespace, metadata source, descriptions, URLs and fix-date metadata.
Strict vulnerable-fixture JSON and evaluator SARIF equality failed. Clean/BCI
outputs and policy exits matched in that session. These substantive fields were
not normalized away, and the lost reports cannot now be independently rechecked.

Unchanged primary source supports a nondeterministic metadata-winner explanation:
`grype/vulnerability_matcher.go` enumerates matches before CVE normalization;
`grype/match/matches.go` enumerates a Go map; `grype/match/match.go` merges details
into the existing match while retaining its primary vulnerability record.
Those files have no attributed migration edits. This is source evidence of a
possible baseline cause, not proof that every observed delta is harmless.

Root must disposition this output contract and recover the exact frozen inputs/raw
reports, or explicitly authorize fresh paired controls with separately identified
inputs, before approving adoption. Preserve severity, applicability, VEX, ignores,
secrets and failure exits in that comparison. Do not suppress real BCI findings.
Any control must verify absolute executable path, version, file SHA256 and module/
VCS metadata before every invocation; downloaded artifact mode must be restored
only after archive and manifest verification.

Native arm64 build/contracts are verified; local real-image arm64 controls are not.
There is no loader or action-consumer pin rollout. Artifact readability through
consumer credentials and retention are separate unresolved adoption requirements.
PR49/newer 5c5ac artifacts and PR39–47 policy selections remain separate.
Toolbox/Kafka access correction remains deferred.
