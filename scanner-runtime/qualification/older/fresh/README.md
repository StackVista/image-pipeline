# Accepted older fresh amd64 controls

Tracking: https://github.com/StackVista/stackstate/issues/717

This run uses exact original Trivy 0.70.0/Grype 0.112.0 and verified native candidate
source 906ee014. Older family A policy is exact scan-image revision
5dabd41a1cecfea5f865d844ea7febec4ab4f38b; no action policy or pin changed.
The shared input bundle/provenance is in qualification/recovery/fresh. Both
independent generation caches contained identical frozen DB/VEX bytes after
original-client DB hydration, before accepted controls started. Database hashes
were checked before/after every scanner invocation and again at completion.

The earlier shared-cache run was invalidated because a newer Grype client
rehydrated an older-prepared DB. Its raw reports/input changes are retained in
invalidated-shared-cache.tar.gz and are not counted as qualification passes.

qualification-result.json records 28 accepted primary policy cases, 32 actual
scanner calls and eight explicit VEX preflight calls. Actual secret-failure blocks
ran in both modes for original and candidate and returned 1. Clean passes both
modes; vulnerable/BCI rejects gate and passes inform. Malformed exceptions return
2; missing DB returns 1. Family A rejects absent usable VEX and active unreachable
endpoints in BOTH modes. B/D action selections retain their independent unchanged
policies; this run does not silently substitute canonical inform behavior for them.

raw-reports.tar.gz preserves every actual JSON/SARIF/log, fixture, command/exit and
executable identity receipt. raw-report-file-sha256.json identifies every file.
The secret control is synthetic and never issued; keep its literal out of status
notes. Real BCI findings remain present and rejected. These are amd64 controls,
not real-image ARM qualification or a consumer loader/distribution rollout.

## Strict Grype output remains unqualified

One additional original run and one additional candidate run used the SAME frozen
inputs. All four Grype reports retain 535 CVE/artifact/severity identities. Package
records, match details/applicability and related vulnerabilities match. Only the
primary vulnerability records vary: original repeat changes 31 records; candidate
repeat changes 31; primary migration pair changes 29; repeated pair changes 37.

Namespace, data source, descriptions, URLs, fix-availability metadata, CVSS and
risk fields differ. Full gate/inform SARIF also differs. These substantive fields
were NOT removed or normalized into equality. Every differing path and both
values are retained in the raw archive for all four comparisons. Fix-version
lists remain unchanged; availability date/kind metadata varies.

Original source evidence: grype/vulnerability_matcher.go enumerates matches before
CVE normalization; grype/match/matches.go enumerates a map; grype/match/match.go
merges into the existing match without replacing its primary vulnerability
record. These source files have no migration attribution. Repeated baseline AND
candidate variability supports an inherited metadata-winner explanation, but
does not prove all output deltas harmless or eliminate a migration-specific
contribution. Root/humans must disposition this output contract before adoption.
No unrelated matcher/algorithm changes or suppressions were made.

Native source/contracts and both-architecture receipts remain separate, already
qualified, and were not manually rerun. Native artifacts expire October 15, 2026.
Consumer artifact access, loader trust/distribution, real-image ARM controls and
Toolbox/Kafka access correction remain outside this qualification.
