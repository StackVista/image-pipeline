# syntax=docker/dockerfile:1.7
#
# Minimal Dockerfile consumed by .github/workflows/apply-oci-labels-ci.yml to
# exercise the action's Dockerfile-parsing path. The image is never built; the
# action only reads the last FROM line and substitutes the ARG default to
# resolve org.opencontainers.image.base.name.

ARG BCI_VERSION=15.7-56.15
FROM registry.suse.com/bci/bci-micro:${BCI_VERSION}
