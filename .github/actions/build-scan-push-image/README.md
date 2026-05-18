# build-scan-push

Composite action: build a container image, scan it with Trivy + Grype (via scan-image action), and push it to a registry if the scan passes.

Input/output reference: [`action.yml`](./action.yml).

## What it does

1. Sets up Docker Buildx for advanced build features and multi-arch support.
2. Builds the image locally (single-arch, no push) and loads it into the Docker daemon.
3. Scans the built image using the [`scan-image`](../scan-image) composite action (Trivy + Grype, policy evaluation, SARIF output).
4. Generates Docker image metadata labels (with [docker/metadata-action](https://github.com/docker/metadata-action)).
5. Builds and pushes the image to the registry, reusing the build cache and applying labels.
6. Fails the workflow if the scan step does not pass the policy gate.

## Inputs

See [`action.yml`](./action.yml) for all supported inputs.
