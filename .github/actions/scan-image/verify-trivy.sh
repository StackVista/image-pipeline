#!/usr/bin/env bash
set -euo pipefail
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64) arch=arm64 ;;
  *) echo "::error::Unsupported Trivy installation platform"; exit 1 ;;
esac
binary="${TRIVY_INSTALL_CACHE}/trivy"
if [ ! -s "${binary}" ]; then
  binary="${RUNNER_TEMP}/image-pipeline-trivy-download/trivy-bin/trivy"
fi
checksum="$(awk -v name="trivy_${TRIVY_VERSION}_linux_${arch}" \
  '$2 == name { print $1; count++ } END { if (count != 1) exit 1 }' \
  "${ACTION_PATH}/scanner-checksums.txt")"
printf '%s  %s\n' "${checksum}" "${binary}" | sha256sum --check --strict
verified_dir="$(mktemp -d "${RUNNER_TEMP}/trivy-verified.XXXXXX")"
install -m 0755 "${binary}" "${verified_dir}/trivy"
mkdir -p "${TRIVY_INSTALL_CACHE}"
cp "${verified_dir}/trivy" "${TRIVY_INSTALL_CACHE}/trivy"
echo "${verified_dir}" >> "$GITHUB_PATH"
