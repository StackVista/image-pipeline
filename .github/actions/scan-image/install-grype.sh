#!/usr/bin/env bash
set -euo pipefail
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64) arch=arm64 ;;
  *) echo "::error::Unsupported Grype installation platform"; exit 1 ;;
esac
archive="grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"
release="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}"
download_dir="$(mktemp -d "${RUNNER_TEMP}/grype-install.XXXXXX")"
trap 'rm -rf -- "${download_dir}"' EXIT
if [ -n "${GRYPE_INSTALL_CACHE:-}" ] &&
   [ -s "${GRYPE_INSTALL_CACHE}/grype.tar.gz" ]; then
  cp "${GRYPE_INSTALL_CACHE}/grype.tar.gz" "${download_dir}/${archive}"
else
  curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors --connect-timeout 10 --max-time 120 \
    "${release}/${archive}" --output "${download_dir}/${archive}"
  test -s "${download_dir}/${archive}"
fi
awk -v archive="${archive}" \
  '$2 == archive { print; count++ } END { if (count != 1) exit 1 }' \
  "${ACTION_PATH}/scanner-checksums.txt" > "${download_dir}/verify.sha256"
(cd "${download_dir}" && sha256sum --check --strict verify.sha256)
tar -xzf "${download_dir}/${archive}" --directory "${download_dir}" grype
sudo install -m 0755 "${download_dir}/grype" /usr/local/bin/grype
grype version
test "$(grype version -o json | jq -r .version)" = "${GRYPE_VERSION}"
if [ -n "${GRYPE_INSTALL_CACHE:-}" ]; then
  mkdir -p "${GRYPE_INSTALL_CACHE}"
  cp "${download_dir}/${archive}" "${GRYPE_INSTALL_CACHE}/grype.tar.gz"
fi
