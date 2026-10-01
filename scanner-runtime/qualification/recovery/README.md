These controls qualify binaries from CI run 36883982986 at source
5c5ac0665b8c308ac7efa05ee397ef5f9e02c255. They do not qualify a consumer loader.
Downloaded executable permissions must be restored only after archive/checksum
and OIDC verification. Every control checks the exact file SHA256, absolute path,
version and Go build metadata before invoking that absolute path. PATH fallback
results from the interrupted earlier local harness are invalid and excluded.

Recovered qualification results
-------------------------------

Both native build/contract jobs and the OIDC signature job passed in run
36883982986. Independent download verification passed for both checksum and
provenance manifests, using issuer `https://token.actions.githubusercontent.com`
and identity `https://github.com/StackVista/image-pipeline/.github/workflows/scanner-runtime-ci.yml@refs/pull/49/merge`.
Both effective graphs, binary build metadata and audit symbols exclude the old
parser. Native owner contracts: 8,488 passing test events and one existing
Testify skip per architecture. Testify retains the exact 1.11.1 owning API.

Corrected real scanner comparisons ran on amd64 with the native CI artifact.
Every scanner control checked absolute path, executable mode, exact SHA256,
version and Go source/parser metadata. `identity-evidence.json` records 28
verified invocations including the original canonical missing-VEX shell block.
A non-executable exact artifact and an installed fallback scanner were rejected
by the guard. Lost prior PATH-fallback results are invalid and excluded.

Clean: zero findings and both policy modes pass. Vulnerable BCI base: identical
36 Trivy HIGH/CRITICAL findings and 522 Grype matches, gate rejects and inform
passes. Unchanged BCI micro rejection control: identical seven Grype matches
including three HIGH, gate rejects and inform passes. Trivy reports zero
HIGH/CRITICAL findings on that micro control; this is preserved original tool
behavior, not a waived Grype finding. The earlier secret-case harness recorded a finding but assigned mode failures
without executing the action failure block. That claim is superseded by the
corrected harness and separately identified fresh evidence under fresh/. Malformed exceptions return 2 in both modes; real Grype missing-database
errors return 1 in both modes. Missing VEX rejects gate and preserves canonical
inform fallback. No scanner/database/rule/exception suppressions were added.

Full scanner JSON is equal after removing only volatile timestamps/report IDs
and the asserted harness output file path. Evaluator SARIF is semantically equal
in both modes. The evaluator is unchanged signed source
0a1619a8a8ac1235fdbbc3f224bf329cb80903cf, rebuilt solely to recover its executable.
The scratch clean fixture proves a benign successful path, not BCI cleanliness.
Real scanner integration controls were amd64 only; ARM64 has native binary,
module/symbol, and owning-contract evidence, not an ARM64 real-image comparison.

Fresh committed inventory: 12,367 original entries, 86 attributed owner/metadata
deltas and all 14 active security inputs. Six ignored original assets are tracked.
Official Go ZIP entries were independently checked against original inventory;
all pass. jd's generated submodule LICENSE equals the preserved root LICENSE.
No original inventoried paths contain spaces. Inert upstream workflows and assets
remain original bytes. Source/build trees are unchanged from qualified 5c5ac066;
recovery commits contain only harness corrections and evidence.

Artifacts from run 36883982986 expire October 15, 2026. No cross-repository loader,
consumer token readability, production artifact distribution or pin rollout is
qualified. Existing PR39–47 remain unchanged. The older scanner family now has separate source and qualification in PR50;
this earlier receipt is retained independently. Root/Borg owns independent review under
https://github.com/StackVista/stackstate/issues/717 before any adoption.
