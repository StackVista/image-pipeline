# scan-sign-push

Gate, publish, and cosign-sign a multi-arch container image in one step.

The action takes per-arch images, scans each one (secret scanning **fail-closed**,
CVE scanning **inform-only**), pushes the per-arch manifests, assembles a
multi-arch manifest list under every requested tag, then keyless-signs and
verifies the assembled digest against the caller's GitHub Actions OIDC identity.
The registry never sees bytes that have not passed the secret gate first.

## What it does

1. Log in to the target registry.
2. (Optional) Fail if any target tag already exists — see `fail-on-existing-tags`.
3. Materialize one image per architecture as `scan-target:<arch>`, either by
   loading a tarball (`source-mode: tarball`) or from images already in the
   docker daemon (`source-mode: local`).
4. Run `scan-image` per arch: Trivy secret scan (fail-closed) + Trivy/Grype CVE
   scan (inform-only), uploading SARIF to GitHub Code Scanning.
5. Push each per-arch manifest and assemble a multi-arch manifest list under
   every tag in `tags`.
6. `cosign sign` the manifest-list digest (both bundle formats) and `cosign
   verify` it against `https://token.actions.githubusercontent.com` with the
   caller's repo/ref identity.

Because signing is done by **digest**, all tags on that digest — and any tag
later re-pointed at it (retag) — are covered by the same signature.

## Requirements

The calling job must grant:

```yaml
permissions:
  contents: read
  id-token: write          # keyless cosign signing (Fulcio OIDC)
  security-events: write   # SARIF upload to Code Scanning
```

A buildx-capable Docker daemon must be available on the runner. For cross-arch
builds, install QEMU/binfmt before this action.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `image` | yes | – | Full image name without tag, e.g. `quay.io/stackstate/stackstate-server`. |
| `tags` | yes | – | Tags to publish under. JSON array or newline-separated list; bare tags or full refs. |
| `arches` | no | `amd64,arm64` | Comma-separated architectures. One image per arch is expected. |
| `source-mode` | no | `tarball` | `tarball` (load `image-<arch>.tar`) or `local` (images already in the daemon). |
| `tarball-dir` | when `tarball` | `""` | Directory holding the per-arch tarballs. |
| `tarball-prefix` | no | `image-` | Tarball filename prefix; path is `<tarball-dir>/<prefix><arch>.tar`. |
| `local-image-prefix` | when `local` | `sts-local:` | Per-arch local ref is `<prefix><arch>` (e.g. `sts-local:amd64`). |
| `severity` | no | `HIGH,CRITICAL` | Severities reported by the CVE scan (non-blocking). |
| `with-grype` | no | `true` | Also run Grype during the CVE scan. |
| `exceptions-path` | no | `""` | Path to CVE exception YAML files. |
| `skip-files` | no | `""` | Newline-separated in-image paths to skip during CVE scan. Secret scanning is never skipped. |
| `upload-sarif` | no | `true` | Upload CVE SARIF to Code Scanning. |
| `sarif-category-prefix` | no | `release-gate` | SARIF category prefix; per-arch category is `<prefix>-<arch>`. |
| `target-registry` | yes | – | Registry to log in to before pushing, e.g. `quay.io`. |
| `target-registry-user` | no | `""` | Registry username. Empty skips login (e.g. local test registry). |
| `target-registry-password` | no | `""` | Registry password/token. |
| `fail-on-existing-tags` | no | `false` | Fail if any target tag already exists (immutable-release behavior). Keep `false` for branch/PR builds that re-point moving tags each commit. |

## Source modes

The action needs one single-arch image per architecture. Produce them however
the build allows, then pick a mode:

- **`tarball`** — the build wrote `image-amd64.tar`, `image-arm64.tar` (e.g.
  `docker buildx build --output type=docker,dest=…`). Point `tarball-dir` at them.
- **`local`** — the build already loaded per-arch images into the daemon tagged
  `<local-image-prefix><arch>` (e.g. `sts-local:amd64`). Useful when a tool
  builds each arch with `--load`.

Multi-arch cannot be built in one `--load`/one tarball, which is why the action
takes per-arch inputs and assembles the manifest list itself.

## Usage

### tarball mode

```yaml
permissions:
  contents: read
  id-token: write
  security-events: write

steps:
  - uses: actions/checkout@v6

  - name: Set up QEMU
    uses: docker/setup-qemu-action@v4
  - name: Set up Docker Buildx
    uses: docker/setup-buildx-action@v4

  - name: Build per-arch tarballs (no push)
    run: |
      for arch in amd64 arm64; do
        docker buildx build --platform "linux/${arch}" \
          --output "type=docker,dest=image-${arch}.tar" .
      done

  - name: Scan, sign, and push
    uses: StackVista/image-pipeline/.github/actions/scan-sign-push@<sha>
    with:
      image: quay.io/stackstate/my-image
      tags: |
        2.10.3
        latest
      source-mode: tarball
      tarball-dir: .
      target-registry: quay.io
      target-registry-user: ${{ vars.QUAY_USER }}
      target-registry-password: ${{ secrets.QUAY_PASSWORD }}
```

### local mode

```yaml
  - name: Build per-arch local images
    run: |
      for arch in amd64 arm64; do
        docker buildx build --platform "linux/${arch}" \
          --tag "sts-local:${arch}" --load .
      done

  - name: Scan, sign, and push
    uses: StackVista/image-pipeline/.github/actions/scan-sign-push@<sha>
    with:
      image: quay.io/stackstate/my-image
      tags: my-branch-tag
      source-mode: local
      local-image-prefix: "sts-local:"
      target-registry: quay.io
      target-registry-user: ${{ vars.QUAY_USER }}
      target-registry-password: ${{ secrets.QUAY_PASSWORD }}
```

## Verifying a signature

```bash
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='^https://github.com/StackVista/<repo>/.*' \
  quay.io/stackstate/my-image:<tag>
```

Any tag on the signed digest verifies, including tags added later by a retag
(retag re-points a tag to an existing digest, so the existing signature applies).

## Notes

- **Secret scanning always blocks**; CVE scanning is inform-only and never fails
  the job (it is uploaded as Code Scanning alerts for visibility).
- The action leaves temporary `sig-handle-<run>-<attempt>-<arch>` tags used to
  address the per-arch children by digest during assembly.
- Signing is keyless (Sigstore/Fulcio) — no long-lived keys. It requires
  `id-token: write` and a public Rekor/Fulcio reachable from the runner.
