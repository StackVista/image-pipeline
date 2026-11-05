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

See [VEX formats](.github/actions/scan-image/README.md#vex-formats)
for the conversion rationale, supported mappings, and failure handling.

## Scan an image manually

The [Manual image scan](.github/workflows/scan-image.yml) workflow accepts an
image reference, architecture, mode, severities, optional Grype scanning, file
exclusions and an exception directory. It runs the scan action from the selected
workflow revision. Defaults are `inform`, both scanners, and all severities.
Secret findings and scanner errors still fail the run.

Once the workflow is on `main`, open **Actions → Manual image scan → Run
workflow**, select the branch to test and enter an image. Enable
`compare-without-vex` to also scan without VEX using the downloaded databases.
The comparison runs after vulnerability scanning has produced a Trivy report,
including when the vulnerability gate fails.

For example:

```bash
gh workflow run scan-image.yml --repo StackVista/image-pipeline --ref main \
  -f image=quay.io/stackstate/zookeeper:3.9.5-so16 \
  -f mode=inform \
  -f architecture=amd64 \
  -f severity=UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
  -f with-grype=true \
  -f compare-without-vex=true
```

The job summary shows raw finding counts. Its artifact contains vulnerability
reports, SARIF, scan settings, the Grype document list and converted VEX files,
including available reports from failed scans. Raw secret reports are excluded.
Use an image digest and compare vulnerability identities in the JSON reports
when investigating VEX effects; a clean result alone does not demonstrate that
an exception was applied. Grype reports findings with available fixes.

`skip-files` accepts newline-separated paths, and `exceptions-path` is relative
to the repository checkout. Optional registry authentication uses variables
`REGISTRY_HOST` and `REGISTRY_USER`, and secret `REGISTRY_PASSWORD`.
When `REGISTRY_HOST` is unset, public images are scanned anonymously.

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

The actions and evaluator share fixed `vMAJOR.MINOR.PATCH` release tags.
Merging a PR changes `main`; publishing a tag releases that revision.
Never move or reuse a published release tag.

```bash
git fetch origin main --tags
git tag -s v1.0.1 origin/main -m "image-pipeline v1.0.1"
git push origin v1.0.1
```

Tag a reviewed `main` revision after its action and evaluator checks pass.
Use a patch release for compatible fixes, a minor release for compatible
features, and a major release for breaking action inputs or outputs.

The tag makes all actions available at that revision and triggers
`.github/workflows/evaluator-release.yml` to publish evaluator archives,
checksums and a GitHub Release.

Consumers must pin the tag's full commit SHA and retain the exact tag in
the trailing comment:

```yaml
uses: StackVista/image-pipeline/.github/actions/scan-image@6869879307d976158fa07ee5bff27ceb8eb031af # v1.0.0
```

Resolve a tag with `gh api repos/StackVista/image-pipeline/commits/v1.0.0 --jq .sha`.
Keep the SHA and comment together in dependency update PRs. Do not use
`# main` or a moving major-version tag. Existing Renovate and Updatecli
GitHub Actions discovery can track these release tags.

Nested action calls use GitHub's self-repository syntax, such as
`uses: $/.github/actions/scan-image`. Sibling actions resolve from the same
repository and commit as the containing action, covered by the consumer's
outer SHA pin. They need no separate version or release.

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
