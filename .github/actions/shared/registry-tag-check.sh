#!/usr/bin/env bash

registry_manifest_status() {
  local ref="$1"
  local output
  local status

  set +e
  output="$(docker manifest inspect "${ref}" 2>&1)"
  status=$?
  set -e

  if [ "${status}" -eq 0 ]; then
    echo "exists"
    return 0
  fi

  if printf '%s\n' "${output}" | grep -Eiq '(manifest unknown|no such manifest|name unknown|not[[:space:]]+found|404)'; then
    echo "missing"
    return 0
  fi

  echo "::error::Unable to determine whether ${ref} exists in the target registry with docker manifest inspect." >&2
  printf '%s\n' "${output}" >&2
  echo "unknown"
}

resolver_manifest_exists() {
  local ref="$1"

  docker buildx imagetools inspect "${ref}" >/dev/null 2>&1
}

require_release_tag_absent() {
  local ref="$1"
  local status

  status="$(registry_manifest_status "${ref}")"
  case "${status}" in
    exists)
      echo "Image ${ref} already exists in target registry; refusing to overwrite." >&2
      return 1
      ;;
    missing)
      if resolver_manifest_exists "${ref}"; then
        echo "::warning::Docker buildx resolver reports ${ref} exists, but target registry manifest check did not find it; allowing publish."
      else
        echo "Image ${ref} does not exist in target registry; push allowed."
      fi
      ;;
    *)
      return 1
      ;;
  esac
}

warn_staging_tag_state() {
  local ref="$1"
  local status

  status="$(registry_manifest_status "${ref}")"
  case "${status}" in
    exists)
      echo "::warning::Architecture staging tag ${ref} already exists in target registry; overwriting is allowed because the final release tag is absent."
      ;;
    missing)
      if resolver_manifest_exists "${ref}"; then
        echo "::warning::Docker buildx resolver reports staging tag ${ref} exists, but target registry manifest check did not find it; continuing."
      else
        echo "Architecture staging tag ${ref} does not exist in target registry."
      fi
      ;;
    *)
      echo "::warning::Could not determine target registry state for staging tag ${ref}; continuing because only final release tags are immutable."
      ;;
  esac
}
