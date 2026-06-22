# scan-image

Composite action: scan a container image with Trivy + Grype, evaluate
findings against per-consumer exception policy, emit SARIF, gate the
build.

Reference by **commit SHA** rather than tag or branch — tags are
mutable, SHAs aren't.

Input/output reference: [`action.yml`](./action.yml).

## What it does

1. Builds and installs the `image-pipeline-evaluate` binary from this
   repo (single-version contract — the action ref pins the evaluator
   version).
2. Downloads the configured VEX repositories and prepares the OpenVEX
   documents for both scanners.
3. Runs **Trivy** secrets scan (no exception path — secrets fail
   closed).
4. Runs **Trivy** vuln scan, with `--vex repo`
   sourcing from `../../../vex/repository.yaml`.
5. Optionally runs **Grype** with the same downloaded OpenVEX
   documents (multi-scanner coverage).
6. Runs the evaluator against the merged findings + the consumer's
   exception files; emits SARIF.
7. Uploads SARIF to GHAS Code Scanning (best-effort; failure does
   not mask the gate).
8. Exits non-zero if any finding is unmanaged or has an expired
   exception.

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
