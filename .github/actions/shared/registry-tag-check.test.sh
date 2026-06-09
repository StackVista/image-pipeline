#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/docker" <<'DOCKER'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-} ${2:-}" == "manifest inspect" ]]; then
  case "${3:-}" in
    registry.example.com/app:existing|registry.example.com/app:staging-present-amd64)
      echo '{}'
      exit 0
      ;;
    registry.example.com/app:missing|registry.example.com/app:resolver-stale|registry.example.com/app:resolver-stale-amd64)
      echo "no such manifest"
      exit 1
      ;;
    registry.example.com/app:unknown)
      echo "unauthorized"
      exit 1
      ;;
  esac
fi

if [[ "${1:-} ${2:-} ${3:-}" == "buildx imagetools inspect" ]]; then
  case "${4:-}" in
    registry.example.com/app:resolver-stale|registry.example.com/app:resolver-stale-amd64)
      echo '{}'
      exit 0
      ;;
    *)
      echo "not found"
      exit 1
      ;;
  esac
fi

echo "unexpected docker invocation: $*" >&2
exit 2
DOCKER
chmod +x "${TMP_DIR}/docker"
export PATH="${TMP_DIR}:${PATH}"

# shellcheck source=.github/actions/shared/registry-tag-check.sh
source "${SCRIPT_DIR}/registry-tag-check.sh"

assert_fails() {
  if "$@"; then
    echo "expected command to fail: $*" >&2
    exit 1
  fi
}

assert_contains() {
  local text="$1"
  local pattern="$2"

  if ! grep -Fq "${pattern}" <<< "${text}"; then
    echo "expected output to contain: ${pattern}" >&2
    echo "actual output:" >&2
    echo "${text}" >&2
    exit 1
  fi
}

assert_fails require_release_tag_absent registry.example.com/app:existing

missing_output="$(require_release_tag_absent registry.example.com/app:missing 2>&1)"
assert_contains "${missing_output}" "does not exist in target registry; push allowed."

stale_output="$(require_release_tag_absent registry.example.com/app:resolver-stale 2>&1)"
assert_contains "${stale_output}" "Docker buildx resolver reports registry.example.com/app:resolver-stale exists"
assert_contains "${stale_output}" "allowing publish"

staging_present_output="$(warn_staging_tag_state registry.example.com/app:staging-present-amd64 2>&1)"
assert_contains "${staging_present_output}" "Architecture staging tag registry.example.com/app:staging-present-amd64 already exists in target registry"
assert_contains "${staging_present_output}" "overwriting is allowed"

staging_stale_output="$(warn_staging_tag_state registry.example.com/app:resolver-stale-amd64 2>&1)"
assert_contains "${staging_stale_output}" "Docker buildx resolver reports staging tag registry.example.com/app:resolver-stale-amd64 exists"
assert_contains "${staging_stale_output}" "continuing"

assert_fails require_release_tag_absent registry.example.com/app:unknown
