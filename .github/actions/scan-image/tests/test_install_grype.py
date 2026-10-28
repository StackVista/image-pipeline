"""Run the installer directly; isolate downloads and privileged installation."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / "install-grype.sh"


class GrypeInstallation(unittest.TestCase):
    def test_release_verification(self):
        for case in ("amd64", "arm64", "empty archive", "empty checksums",
                     "download failure", "checksum mismatch", "missing checksum",
                     "duplicate checksum", "malformed checksum", "install failure",
                     "missing binary", "wrong version"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tools = root / "tools"
                tools.mkdir()
                arch = "arm64" if case == "arm64" else "amd64"
                version = "0.117.0" if case == "wrong version" else "0.118.0"
                (root / "grype").write_text(
                    '#!/bin/sh\ntouch "$TASK_ROOT/executed"\n'
                    f"""printf '%s\\n' '{{"version":"{version}"}}'\n"""
                )
                archive = f"grype_0.118.0_linux_{arch}.tar.gz"
                subprocess.run(["tar", "-czf", str(root / archive), "-C", str(root), "grype"], check=True)
                digest = hashlib.sha256((root / archive).read_bytes()).hexdigest()
                checksums = f"{digest}  {archive}\n"
                if case == "checksum mismatch":
                    checksums = f'{"0" * 64}  {archive}\n'
                elif case == "missing checksum":
                    checksums = checksums.replace("_linux_", "_darwin_")
                elif case == "duplicate checksum":
                    checksums *= 2
                elif case == "malformed checksum":
                    checksums = f"invalid  {archive}\n"
                (root / "grype_0.118.0_checksums.txt").write_text(checksums)
                stubs = {
                    "curl": """#!/bin/bash
set -eu
test "$TASK_CASE" != "download failure"
url="${@: -3:1}"
case "$url" in
  "https://github.com/anchore/grype/releases/download/v0.118.0/$TASK_ARCHIVE") empty="empty archive";;
  "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_checksums.txt") empty="empty checksums";;
  *) exit 99;;
esac
while [ "$1" != --output ]; do shift; done
if [ "$TASK_CASE" = "$empty" ]; then : > "$2"; else cp "$TASK_ROOT/${url##*/}" "$2"; fi
""",
                    "sudo": """#!/bin/sh
set -eu
touch "$TASK_ROOT/install-called"
test "$1" = install && test "$2" = -m && test "$3" = 0755
test "$5" = /usr/local/bin/grype
test "$TASK_CASE" != "install failure"
if [ "$TASK_CASE" != "missing binary" ]; then install -m 0755 "$4" "$TASK_ROOT/installed"; fi
""",
                    # A missing install cannot be masked by a host Grype.
                    "grype": '#!/bin/sh\nexec "$TASK_ROOT/installed" "$@"\n',
                    "uname": '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo '
                             + ("aarch64" if arch == "arm64" else "x86_64") + ";; *) exit 99;; esac\n",
                }
                for name, content in stubs.items():
                    path = tools / name
                    path.write_text(content)
                    path.chmod(0o755)
                result = subprocess.run(
                    ["bash", str(INSTALLER)], cwd=root, capture_output=True, text=True,
                    env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                         "RUNNER_TEMP": str(root), "GRYPE_VERSION": "0.118.0",
                         "TASK_ROOT": str(root), "TASK_CASE": case, "TASK_ARCHIVE": archive},
                )
                self.assertEqual(result.returncode == 0, case in ("amd64", "arm64"), result.stdout + result.stderr)
                if "checksum" in case or case.startswith("empty") or case == "download failure":
                    for marker in ("install-called", "installed", "executed"):
                        self.assertFalse((root / marker).exists(), result.stdout + result.stderr)
                if case == "checksum mismatch":
                    self.assertIn("FAILED", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
