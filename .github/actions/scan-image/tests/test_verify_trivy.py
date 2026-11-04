"""Reject untrusted cached binaries before exposing an executable path."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

VERIFIER = Path(__file__).resolve().parents[1] / "verify-trivy.sh"


class TrivyVerification(unittest.TestCase):
    def test_binary_verification(self):
        for case in ("amd64", "arm64", "cache hit", "corrupt cache", "tampered cache",
                     "missing binary", "missing checksum", "duplicate checksum",
                     "malformed checksum", "unsupported platform"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tools = root / "tools"
                tools.mkdir()
                cache = root / "cache with spaces"
                cache.mkdir()
                downloaded = root / "image-pipeline-trivy-download/trivy-bin"
                downloaded.mkdir(parents=True)
                binary = b'#!/bin/sh\ntouch "$TASK_ROOT/executed"\n'
                digest = hashlib.sha256(binary).hexdigest()
                arch = "arm64" if case == "arm64" else "amd64"
                checksums = f"{digest}  trivy_0.76.0_linux_{arch}\n"
                if case == "missing checksum":
                    checksums = checksums.replace("0.76.0", "0.75.0")
                elif case == "duplicate checksum":
                    checksums *= 2
                elif case == "malformed checksum":
                    checksums = checksums.replace(digest, "invalid")
                (root / "scanner-checksums.txt").write_text(checksums)
                target = cache / "trivy" if "cache" in case else downloaded / "trivy"
                if case != "missing binary":
                    target.write_bytes(binary)
                if case in ("corrupt cache", "tampered cache"):
                    target.write_bytes(b'#!/bin/sh\ntouch "$TASK_ROOT/poisoned"\n')
                    if case == "tampered cache":
                        fake_digest = hashlib.sha256(target.read_bytes()).hexdigest()
                        (cache / "scanner-checksums.txt").write_text(
                            f"{fake_digest}  trivy_0.76.0_linux_{arch}\n")
                        (cache / "sha256sum").write_text('#!/bin/sh\nexit 0\n')
                        (cache / "sha256sum").chmod(0o755)
                (tools / "uname").write_text(
                    '#!/bin/sh\ncase "$1" in -s) echo '
                    + ("Darwin" if case == "unsupported platform" else "Linux")
                    + ';; -m) echo ' + ("aarch64" if arch == "arm64" else "x86_64")
                    + ';; *) exit 99;; esac\n')
                (tools / "uname").chmod(0o755)
                output = root / "github-path"
                result = subprocess.run(
                    ["bash", str(VERIFIER)], capture_output=True, text=True,
                    env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
                         "RUNNER_TEMP": str(root), "TRIVY_VERSION": "0.76.0",
                         "TRIVY_INSTALL_CACHE": str(cache), "ACTION_PATH": str(root),
                         "GITHUB_PATH": str(output), "TASK_ROOT": str(root)},
                )
                success = case in ("amd64", "arm64", "cache hit")
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                self.assertFalse((root / "executed").exists())
                self.assertFalse((root / "poisoned").exists())
                self.assertEqual(output.exists(), success)
                if success:
                    verified_dir = Path(output.read_text().strip())
                    self.assertEqual((verified_dir / "trivy").read_bytes(), binary)
                    self.assertEqual(list(verified_dir.iterdir()), [verified_dir / "trivy"])
                    self.assertEqual((cache / "trivy").read_bytes(), binary)


if __name__ == "__main__":
    unittest.main()
