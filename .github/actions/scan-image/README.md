# scan-image

Composite action: scan a container image with Trivy + Grype, evaluate
findings against per-consumer exception policy, emit SARIF, gate the
build.

Reference by **commit SHA** rather than tag or branch — tags are
mutable, SHAs aren't.

Input/output reference: [`action.yml`](./action.yml).

## What it does

1. Builds and installs the evaluator and Grype VEX adapter from this
   repo. The action ref pins both binaries.
2. Downloads the configured VEX repositories and prepares their indexed
   documents for Grype.
3. Runs **Trivy** secrets scan with bounded retries (no exception path —
   secrets fail closed).
4. Runs **Trivy** vuln scan with bounded retries, with `--vex repo`
   sourcing from `../../../vex/repository.yaml`.
5. Optionally runs **Grype** with `--only-fixed` and the indexed OpenVEX
   documents plus local conversions of indexed CSAF documents. Grype
   omits findings without an available fix.
6. Runs the evaluator against the merged findings + the consumer's
   exception files; emits SARIF.
7. Uploads SARIF to GHAS Code Scanning (best-effort; failure does
   not mask the gate).
8. Exits non-zero if any finding is unmanaged or has an expired
   exception.

## Scanner Retries

The action leaves scanner image-source behavior at the scanner defaults. Trivy
commands are retried up to three times with a short delay to absorb transient
registry or layer-read failures such as `unexpected EOF`.

This intentionally avoids forcing Trivy or Grype through Docker's local image
source. Docker can successfully pull image formats that a scanner's local
Docker extractor may still fail to analyze, so the retry is applied to the
previously working scanner path instead.

## VEX formats

Trivy reads the original hubs with `--vex repo`. Grype's tested CSAF parsers
do not apply Rancher's image/component relationships, and mixed formats can
fail depending on input order. Its adapter reads each enabled hub's `index.json`,
passes through OpenVEX, and converts CSAF to local OpenVEX with image products
and package subcomponents. Published reports remain unchanged; standalone
`reports/` exports are unused.

All indexed documents are considered, regardless of the scanned image.
Rancher's `skip_invalid_documents: true` skips rejected documents with a
filename/reason warning; their suppressions are unavailable to Grype.
Internal StackVista documents remain strict. Download/index failures, missing
files, unsafe paths, output errors, or a hub with no usable documents fail in
either mode.

Conversion rejects nested relationships, relationship identification helpers,
unrepresentable extra identifiers, conflicting statuses, and affected
assessments without remediation. Supported mappings retain PURL scopes,
CVE/GHSA/GO identifiers, group-scoped justifications and impacts, and affected
remediation text with its latest date.

Conversion omits other advisory identifiers, CVSS rescoring, assessment dates,
revision history, and other metadata. See the
[input/expected-output examples](../../../evaluator/internal/grypevex/testdata/conversion/README.md)
for details.

## Skipping upstream binaries

Use the `skip-files` input to exclude specific in-image paths from the
vulnerability scanners when a binary is shipped from upstream and we don't
maintain a per-CVE audit trail for it (e.g. statically-linked Go binaries
like `sops` or `terraform`). Paths are passed to Trivy as `--skip-files`
and to Grype as `--exclude`. The Trivy **secrets** scan deliberately
ignores this list — secret coverage stays comprehensive across every file.

## Exception files

Consumer repos write YAML files matching
[`../../../schemas/exception.schema.json`](../../../schemas/exception.schema.json)
and pass the containing directory via `exceptions-path`. Each file
explicitly accepts a `(image, CVE)` pair with a reason, owner, and
expiry. Expired exceptions surface as live findings rather than
silently passing.

## Implementation

The evaluator binary (`image-pipeline-evaluate`) is the policy engine
behind the gate. See [`../../../evaluator/README.md`](../../../evaluator/README.md)
for its CLI, SARIF output format, and how to add new scanner adapters.

The repository's `Action unit tests` workflow also runs the full composite
action on every relevant PR. It scans a locally built clean image, a
digest-pinned vulnerable BCI image, and a digest-pinned published SUSE
Observability image. The published-image canary runs in `inform` mode: it is
there to catch scanner compatibility regressions against real consumer image
formats, not to make the unit workflow depend on today's CVE surface.
