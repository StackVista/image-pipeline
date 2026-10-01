# Fresh amd64 policy qualification inputs

Tracking: https://github.com/StackVista/stackstate/issues/717

This is a separately identified fresh input set, not a recovery of lost older
reports. Both generations use byte-identical frozen DB/VEX contents in isolated
caches. Trivy DB is independently checked against the immutable OCI layer in
trivy-oci-source.json. Grype uses the checksum-addressed official archive recorded
in the import metadata inside frozen-inputs.tar.gz, with client hydration v6.1.9
completed before freezing. Original source grype/db/v6/installation/curator.go
explains index rehydration when a newer client opens an older-prepared DB.

input-file-sha256.json identifies every frozen DB/VEX file. The archive contains
VEX, repository configuration, DB metadata/import receipts and exact synthetic
fixtures; large SQLite databases are reproducible from their official sources,
not duplicated in Git. Reconstruct/import before freezing, then verify the exact
file hashes. Any mismatch fails qualification; a later DB is not the same input.
DB source retention is external and remains a reproducibility limitation.

The initial shared-cache run changed Grype's DB/import metadata and is invalidated.
Its reports are retained separately on PR50. The corrected harness fails closed on
input mutation before/after every scanner invocation, including shell-invoked
secret policy. VEX preflight absence/unreachable controls freeze their own precise
configuration/policy inputs; they do not read vulnerability databases.

The fixture archive contains only a synthetic never-issued secret control, not a
real credential. Keep its literal out of status notes. Real BCI findings remain
unsuppressed. Clean scratch success does not establish BCI cleanliness.

Qualified source/build artifacts remain 5c5ac066 (newer) and 906ee014 (older).
No cold native build was manually restarted. ARM has native source/contracts,
not real-image controls. No loader, action/consumer rollout or stable publication.
Fresh complete results/raw reports will be recorded separately after guards pass.

## Completed fresh controls

qualification-result.json and raw-reports.tar.gz record the accepted run. All
28 primary policy cases passed, with 32 actual scanner calls and eight additional
VEX preflight calls. The four secret mode/variant policy subprocesses actually
returned 1; outcomes are not assigned from finding counts. Every scanner call
verified absolute executable path/mode/SHA/version/Go metadata and checksummed
its applicable frozen inputs before and after invocation. Final full-set hashes
also remained unchanged. raw-report-file-sha256.json identifies every archived
report, fixture, command/exit log and identity receipt.

Clean passes both modes. Vulnerable/BCI controls fail gate and pass inform;
malformed exceptions return 2, missing Grype DB returns 1 in both modes. VEX
preflight gate fails for both absent usable material and active unreachable
endpoints; canonical inform fallback succeeds in both conditions. The legacy
primary results key `missing-vex-*` denotes the active unreachable fixture;
vex-controls.json separately names both conditions.

Newer Trivy/Grype JSON matches after only volatile report timestamps/identifiers
and the asserted harness output path are normalized. Full evaluator SARIF matches.
Raw reports are retained unchanged. Trivy reports 36 HIGH/CRITICAL findings on the
vulnerable control, Grype 522 matches. BCI micro retains seven Grype matches,
including HIGH findings, and is rejected; no BCI findings were suppressed.

Reproduction requires the exact official archives, native artifacts and evaluator
source 0a1619a8, verified before executable modes are restored. Extract input/report
archives in a disposable directory; restore the generation-specific cache paths
recorded in frozen-manifest.json. Materialize the official DB sources before
freezing and validate every recorded hash. Set FROZEN_INPUTS_MANIFEST to that
manifest before running controls.py. Database rehydration must finish before the
freeze. Matching SQLite bytes on a future reconstruction is a requirement, not
an assumption; source availability or a hash mismatch remains an explicit boundary.
