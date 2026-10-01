#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../.." && pwd)
family=${SCANNER_FAMILY:-newer}
case "$family" in
  newer) trivy_version=0.74.0; syft_version=1.51.1 ;;
  older) trivy_version=0.70.0; syft_version=1.44.0 ;;
  *) echo "Unknown scanner family" >&2; exit 1 ;;
esac
out="$repo_root/scanner-runtime/out/$(go env GOARCH)"
if [[ "$family" == older ]]; then out="$repo_root/scanner-runtime/out/older/$(go env GOARCH)"; fi
mkdir -p "$out/contracts"
export GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 GOGC=50 GOMEMLIMIT=4GiB
export GOFLAGS='-p=2 -mod=readonly'
run_contract() {
  local name=$1 directory=$2
  shift 2
  (cd "$repo_root/$directory" && go test -count=1 -json "$@") > "$out/contracts/$name.jsonl" 2> "$out/contracts/$name.stderr"
}
run_contract yaml scanner-runtime/qualification ./...
run_contract assertion-mock scanner-runtime/sources/testify-1.11.1 ./assert/... ./mock/... ./require/...
if [[ "$family" == older ]]; then
  run_contract syft scanner-runtime/sources/syft-1.44.0 ./syft/pkg/cataloger/snap
  run_contract helm scanner-runtime/sources/helm-3.20.2 ./pkg/action -run "TestInstallRelease_HookOutputLogs|TestInstallRelease_HooksOutputLogs|TestHooksCleanUp"
else
  run_contract syft scanner-runtime/sources/syft-1.51.1 ./syft/pkg/cataloger/ai ./syft/pkg/cataloger/snap
fi
run_contract openvex-027 scanner-runtime/sources/go-vex-0.2.7 ./pkg/vex
run_contract openvex-028 scanner-runtime/sources/go-vex-0.2.8 ./pkg/vex
run_contract squealer scanner-runtime/sources/squealer-1.2.12 ./pkg/config
run_contract compliance scanner-runtime/sources/trivy-checks-79d27547baf5 ./pkg/compliance
run_contract kubernetes scanner-runtime/sources/trivy-kubernetes-0.9.1 ./pkg/jobs
run_contract jd scanner-runtime/sources/jd-2.3.0/v2 .
export GOEXPERIMENT=jsonv2
run_contract trivy "scanner-runtime/sources/trivy-$trivy_version" \
 ./pkg/result ./pkg/fanal/secret ./pkg/vex/repo \
 ./pkg/iac/scanners/ansible/parser ./pkg/iac/scanners/ansible/orderedmap \
 ./pkg/iac/scanners/kubernetes/parser ./pkg/iac/scanners/cloudformation/parser \
 ./pkg/dependency/parser/conda/environment ./pkg/dependency/parser/dart/pub \
 ./pkg/dependency/parser/nodejs/pnpm ./pkg/dependency/parser/swift/cocoapods
