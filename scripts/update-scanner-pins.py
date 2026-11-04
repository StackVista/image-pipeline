#!/usr/bin/env python3
"""Update scanner versions and their independently verified checksum pins."""

import argparse
import hashlib
import io
from pathlib import Path
import re
import tarfile
import urllib.request

ACTION_DIR = Path(__file__).resolve().parents[1] / ".github/actions/scan-image"


def download(url):
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def update_scanners(trivy_version, grype_version):
    action_path = ACTION_DIR / "action.yml"
    checksum_path = ACTION_DIR / "scanner-checksums.txt"
    action = action_path.read_text()
    pins = dict(line.split()[::-1] for line in checksum_path.read_text().splitlines())
    changed = False
    for scanner, requested, owner in (
        ("trivy", trivy_version, "aquasecurity"),
        ("grype", grype_version, "anchore"),
    ):
        version = requested.removeprefix("v")
        if not re.fullmatch(r"0\.\d+\.\d+", version):
            raise ValueError(f"Invalid {scanner} version: {requested}")
        pattern = rf"^        {scanner.upper()}_VERSION: (0\.\d+\.\d+)$"
        matches = re.findall(pattern, action, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError(f"Expected one {scanner} version declaration")
        if matches[0] == version:
            continue
        release = f"https://github.com/{owner}/{scanner}/releases/download/v{version}"
        checksums = download(f"{release}/{scanner}_{version}_checksums.txt").decode().splitlines()
        new_pins = {}
        for arch, trivy_arch in (("amd64", "64bit"), ("arm64", "ARM64")):
            archive = (f"trivy_{version}_Linux-{trivy_arch}.tar.gz" if scanner == "trivy"
                       else f"grype_{version}_linux_{arch}.tar.gz")
            records = [line.split() for line in checksums
                       if len(line.split()) == 2 and line.split()[1] == archive]
            if len(records) != 1 or not re.fullmatch(r"[a-f0-9]{64}", records[0][0]):
                raise ValueError(f"Expected one valid upstream checksum for {archive}")
            checksum = records[0][0]
            if scanner == "trivy":
                data = download(f"{release}/{archive}")
                if hashlib.sha256(data).hexdigest() != checksum:
                    raise ValueError(f"Checksum mismatch for {archive}")
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                    member = tar.getmember("trivy")
                    if not member.isfile():
                        raise ValueError(f"Missing regular Trivy binary in {archive}")
                    checksum = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
                new_pins[f"trivy_{version}_linux_{arch}"] = checksum
            else:
                new_pins[archive] = checksum
        pins = {name: digest for name, digest in pins.items()
                if not name.startswith(scanner + "_")}
        pins.update(new_pins)
        action = re.sub(pattern, f"        {scanner.upper()}_VERSION: {version}",
                        action, flags=re.MULTILINE)
        changed = True
    if changed:
        checksum_path.write_text("".join(f"{digest}  {name}\n" for name, digest in pins.items()))
        action_path.write_text(action)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trivy_version")
    parser.add_argument("grype_version")
    args = parser.parse_args()
    update_scanners(args.trivy_version, args.grype_version)
