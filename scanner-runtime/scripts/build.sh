#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
arch=$(go env GOARCH)
if [[ "${EXPECTED_ARCH:-$arch}" != "$arch" ]]; then
  echo 'Native builder architecture mismatch' >&2
  exit 1
fi
out="$repo_root/scanner-runtime/out/$arch"
mkdir -p "$out"
export GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 GOGC=50 GOMEMLIMIT=4GiB
export GOFLAGS='-p=2 -mod=readonly'
source_commit=$(git -C "$repo_root" rev-parse HEAD)
if [[ -n "${SOURCE_COMMIT:-}" && "$SOURCE_COMMIT" != "$source_commit" ]]; then
  echo 'Source commit mismatch' >&2
  exit 1
fi
go version > "$out/toolchain.txt"
for tool in trivy grype; do
  if [[ "$tool" == trivy ]]; then
    tree=trivy-0.74.0
    export GOEXPERIMENT=jsonv2
    flags="-s -w -extldflags '-static' -X github.com/aquasecurity/trivy/pkg/version/app.ver=0.74.0"
    audit_flags="-extldflags '-static' -X github.com/aquasecurity/trivy/pkg/version/app.ver=0.74.0"
  else
    tree=grype-0.118.0
    unset GOEXPERIMENT
    flags="-w -s -extldflags '-static' -X main.version=0.118.0 -X main.gitCommit=756eb9a24f7beeafb6871a24e943e8a3ae210695 -X main.buildDate=2026-08-27T19:58:02Z -X main.gitDescription=v0.118.0"
    audit_flags="${flags/-w -s /}"
  fi
  (
    cd "$repo_root/scanner-runtime/sources/$tree"
    go mod verify > "$out/$tool-module-verification.txt"
    go list -deps -json "./cmd/$tool" > "$out/$tool-packages.json"
    go list -m -json all > "$out/$tool-modules.json"
    go build -buildvcs=true -ldflags "$flags" -o "$out/$tool" "./cmd/$tool"
    go version -m "$out/$tool" > "$out/$tool-buildinfo.txt"
    go build -buildvcs=true -ldflags "$audit_flags" -o "$out/$tool-audit" "./cmd/$tool"
    go tool nm "$out/$tool-audit" > "$out/$tool-symbols.txt"
    rm "$out/$tool-audit"
    "$out/$tool" version > "$out/$tool-version.txt"
  )
  if grep -E 'gopkg\.in/yaml\.(v2|v3)|github\.com/(go-yaml/yaml|ghodss/yaml)' \
      "$out/$tool-buildinfo.txt" "$out/$tool-symbols.txt"; then
    echo 'Archived parser linked into candidate' >&2
    exit 1
  fi
done
printf '%s\n' "$source_commit" > "$out/source-commit.txt"
sha256sum "$out/trivy" "$out/grype" > "$out/binary-sha256.txt"
