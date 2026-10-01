# Scanner runtime YAML candidate

Review candidate under https://github.com/StackVista/stackstate/issues/717 (Borg).
This adds complete original Trivy 0.74.0 and Grype 0.118.0 source trees and their
selected parser owners. It does not change any composite action pin, scan policy,
consumer loader, historical candidate or release workflow.

`original-inventory.json` records original revisions, complete archive checksums,
file checksums, executable modes and symlinks. `candidate-attribution.json` records
every allowed upstream delta. Original licenses, fixtures, generated/embedded
assets and upstream `.github` trees remain intact. Nested upstream workflows and
actions are inert source assets, not repository automation. The security audit
collects the root `.github` tree explicitly; its active input inventory is checked.

The source delta migrates matching v3 imports and selects maintained v3.0.5.
Executable-root module replacements select complete owning backports; there is no
parser identity replacement. Testify stays at its original 1.11.1 API with its
single YAML import migrated. Syft package-identity fixtures remain unchanged.
Original minimum Go 1.26.3 and Trivy's `GOEXPERIMENT=jsonv2` are retained.

This is the newer family only. The older Trivy 0.70/Grype 0.112/Syft 1.44/Helm
family remains separate pending work. Candidate archives are temporary native
Actions artifacts, not production distribution. Consumer token readability and
artifact expiry must be qualified before any loader or scanner pin rollout.

Run `python3 scanner-runtime/scripts/inventory.py` to verify source attribution.
The builder is checksum pinned and signature verified using SUSE's published key;
its exact identity and verification evidence live in `provenance/`.
