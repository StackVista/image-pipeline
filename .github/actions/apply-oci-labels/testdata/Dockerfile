# syntax=docker/dockerfile:1.7
#
# Minimal Dockerfile consumed by .github/workflows/apply-oci-labels-ci.yml to
# exercise the action's Dockerfile-parsing path. The image is never built; the
# action only reads the first `ARG BASE_IMAGE=...` line to resolve
# org.opencontainers.image.base.name.

ARG BASE_IMAGE=registry.suse.com/bci/bci-micro:15.7-56.15
FROM ${BASE_IMAGE}
