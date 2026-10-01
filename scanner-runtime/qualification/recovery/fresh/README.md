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
