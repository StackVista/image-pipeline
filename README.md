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

## Reusable workflow usage

The reusable workflow builds, scans and publish a multi-arch image for you.

```yaml
jobs:
  image-pipeline:
    uses: StackVista/image-pipeline/.github/workflows/reusable-image-pipeline.yml@v0.1.0
    with:
      image: quay.io/stackstate/stackstate-k8s-process-agent
      tag: latest
      scan-mode: gate
      scan-severity: HIGH,CRITICAL
      exceptions-path: ./exceptions
      source_registry: quay.io
    secrets:
      source_registry_user: ${{ secrets.QUAY_USERNAME }}
      source_registry_password: ${{ secrets.QUAY_PASSWORD }}
```

An alternative is to call single action directly in your workflow:

```yaml
jobs:
  build:
    strategy:
      matrix:
        arch: [amd64, arm64]
        include:
          - arch: amd64
            runner: ubuntu-24.04
          - arch: arm64
            runner: ubuntu-24.04-arm
    permissions:
      contents: read
    runs-on: ${{ matrix.runner }}
    steps:
      - name: Checkout code
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          persist-credentials: false
      - name: Build image
        uses: StackVista/image-pipeline/.github/actions/build-push-image@v0.1.0
        with:
          image: quay.io/stackstate/stackstate-k8s-process-agent
          arch: ${{ matrix.arch }}
          dockerfile: ./Dockerfile
          source_registry: quay.io
          source_registry_user: ${{ secrets.QUAY_USERNAME }}
          source_registry_password: ${{ secrets.QUAY_PASSWORD }}
  merge:
    runs-on: ubuntu-24.04
    needs: [build]
    permissions:
      contents: read
    steps:
      - name: Merge images
        uses: StackVista/image-pipeline/.github/actions/merge-multiarch-image@v0.1.0
        with:
          image: quay.io/stackstate/stackstate-k8s-process-agent
          # depends on where is called, could be latest/${{ github.ref_name }}...
          tag: latest
          source_registry: quay.io
          source_registry_user: ${{ secrets.QUAY_USERNAME }}
          source_registry_password: ${{ secrets.QUAY_PASSWORD }}
```
