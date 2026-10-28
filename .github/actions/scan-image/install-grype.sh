#!/usr/bin/env bash
set -euo pipefail
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64) arch=arm64 ;;
  *) echo "::error::Unsupported Grype installation platform"; exit 1 ;;
esac
archive="grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"
checksums="grype_${GRYPE_VERSION}_checksums.txt"
release="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}"
download_dir="$(mktemp -d "${RUNNER_TEMP}/grype-install.XXXXXX")"
trap 'rm -rf -- "${download_dir}"' EXIT
for file in "${archive}" "${checksums}"; do
  curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors --connect-timeout 10 --max-time 120 \
    "${release}/${file}" --output "${download_dir}/${file}"
  test -s "${download_dir}/${file}"
done
# Require exactly one checksum for this archive and enforce rejection
# before extracting or installing anything. The upstream installer's
# download function does not propagate checksum verification failures.
awk -v archive="${archive}" \
  '$2 == archive { print; count++ } END { if (count != 1) exit 1 }' \
  "${download_dir}/${checksums}" > "${download_dir}/verify.sha256"
(cd "${download_dir}" && sha256sum --check --strict verify.sha256)
tar -xzf "${download_dir}/${archive}" --directory "${download_dir}" grype
sudo install -m 0755 "${download_dir}/grype" /usr/local/bin/grype
grype version
test "$(grype version -o json | jq -r .version)" = "${GRYPE_VERSION}"
