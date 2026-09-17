# image-pipeline

Reusable GitHub Actions for building, scanning, attesting, and publishing container images.

## What's here

| Path | Purpose |
|------|---------|
| `.github/actions/scan-image/` | Composite action: scan an image with Trivy + Grype, gate on policy, emit SARIF |
| `evaluator/` | Go binary (`image-pipeline-evaluate`) that applies exception policy to scanner output |
| `schemas/exception.schema.json` | JSON Schema for per-consumer exception files |
| `vex/repository.yaml` | Trivy VEX hub config |
| `.github/workflows/` | CI for the actions and evaluator; release pipeline for the evaluator binary |

Exception YAMLs themselves live in **consumer repositories**, not
here, and are pointed at via the `exceptions-path` input on the
scan-image action.

Per-action docs live alongside the action: see
[`.github/actions/scan-image/README.md`](./.github/actions/scan-image/README.md).

## Local development

[mise](https://mise.jdx.dev) handles tool versions:

```bash
mise run build           # builds ./bin/image-pipeline-evaluate
mise run test            # go test ./...
mise run lint            # gofmt + go vet + zizmor
mise run lint-workflows  # zizmor on workflows + composite actions
```

Evaluator details: [`evaluator/README.md`](./evaluator/README.md).

## Dependency Updates

Upstream pins are tracked with [updatecli](https://www.updatecli.io/) under
`.updatecli/`.

- `.github/workflows/updatecli-ci.yml` runs `updatecli pipeline diff` for PRs that change
  updatecli config or workflows. It is read-only validation and does not open
  update PRs.
- `.github/workflows/bump-upstream-pins.yml` runs `updatecli pipeline apply` weekly and
  on manual dispatch. It uses the updatecli GitHub App token to open or update
  separate PRs per updatecli pipeline, such as `[updatecli] bump Go
  dependencies` and `[updatecli] bump GitHub Actions pins`.
- The updatecli manifest tracks Go module updates, GitHub Actions SHA pins, and
  tool pins embedded in `.github/actions/scan-image/action.yml`.

## Releases

The evaluator binary is released by pushing a SemVer tag from `main`:

```bash
git tag -a v0.1.0 -m "evaluator v0.1.0"
git push origin v0.1.0
```

This triggers `.github/workflows/evaluator-release.yml`, which runs
goreleaser to build linux/darwin × amd64/arm64 archives + checksums
and publish a GitHub Release.

The `v*` tag namespace currently belongs to the evaluator. If a
second releasable artifact is added (e.g. a build action), the
tagging scheme will need to be revisited.

## Roadmap

- Reusable build workflow (image build + SBOM attestation)
- Cosign keyless OIDC attestation of SBOM + vuln report per platform
- Publish workflow (registry push with provenance)

### Recovering interrupted image publication

`merge-multiarch` accepts an optional `receipts` directory containing one JSON file
per architecture. Each records `image`, `tag`, `arch`, `digest`, `repository`,
`sha` and `run_id`; source values must match the current GitHub run. Consumers
should upload receipts only after `push-single-arch` succeeds, using its `digest`
output, and download artifacts from the same run when merging.

With receipts, merging reads immutable digests and verifies their signatures.
An existing release can resume only when its full manifest matches those inputs;
completed signatures are retained and missing signatures are completed. A
conflicting release is never overwritten. Without receipts, the existing-tag
refusal remains. Registry errors are not treated as missing tags.

Rerun **failed jobs**, keeping successful architecture jobs and their artifacts.
Expired/missing receipts require investigation, not reconstruction from mutable
tags. The maintained Cosign installer retains its verified download and bounded
retries; a persistent download outage remains a retryable failed job.

The recovery fixture uses the same Docker Distribution registry as the existing
publication smoke test, pinned by digest. BCI provides no ready-to-run OCI registry
service; this test needs its registry API, not a general-purpose base image.
Fixture images use `FROM scratch`, and publication stays in the job's local registry.
