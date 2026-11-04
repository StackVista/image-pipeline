"""Keep automated scanner version changes consistent with trusted checksums."""

import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[4] / "scripts/update-scanner-pins.py"
spec = importlib.util.spec_from_file_location("update_scanner_pins", SCRIPT)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class ScannerPinUpdates(unittest.TestCase):
    def test_updates_and_failures(self):
        for case in ("both", "trivy only", "grype only", "unchanged",
                     "bad archive", "missing checksum", "duplicate checksum",
                     "malformed checksum", "missing binary", "invalid version",
                     "missing declaration", "late download failure"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                action = root / "action.yml"
                original = ("        TRIVY_VERSION: 0.76.0\n"
                            "        GRYPE_VERSION: 0.118.0\n"
                            "        GRYPE_VERSION: ${{ steps.paths.outputs.grype_version }}\n")
                if case == "missing declaration":
                    original = original.replace("        TRIVY_VERSION: 0.76.0\n", "")
                action.write_text(original)
                manifest = root / "scanner-checksums.txt"
                old_pins = (
                    f'{"1"*64}  trivy_0.76.0_linux_amd64\n'
                    f'{"2"*64}  trivy_0.76.0_linux_arm64\n'
                    f'{"3"*64}  grype_0.118.0_linux_amd64.tar.gz\n'
                    f'{"4"*64}  grype_0.118.0_linux_arm64.tar.gz\n'
                )
                manifest.write_text(old_pins)
                downloads = {}
                expected = {}
                records = []
                for arch, label in (("amd64", "64bit"), ("arm64", "ARM64")):
                    binary = f"trivy {arch}".encode()
                    stream = io.BytesIO()
                    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                        entry = tarfile.TarInfo("other" if case == "missing binary" else "trivy")
                        entry.size = len(binary)
                        tar.addfile(entry, io.BytesIO(binary))
                    blob = stream.getvalue()
                    archive = f"trivy_0.77.0_Linux-{label}.tar.gz"
                    records.append(f"{hashlib.sha256(blob).hexdigest()}  {archive}\n")
                    downloads[f"https://github.com/aquasecurity/trivy/releases/download/v0.77.0/{archive}"] = (
                        b"bad" if case == "bad archive" else blob)
                    expected[f"trivy_0.77.0_linux_{arch}"] = hashlib.sha256(binary).hexdigest()
                checksums = "".join(records)
                if case == "missing checksum":
                    checksums = records[0]
                elif case == "duplicate checksum":
                    checksums += records[0]
                elif case == "malformed checksum":
                    checksums = checksums.replace(records[0].split()[0], "invalid")
                downloads["https://github.com/aquasecurity/trivy/releases/download/v0.77.0/trivy_0.77.0_checksums.txt"] = checksums.encode()
                grype_checksums = ""
                for arch, digit in (("amd64", "a"), ("arm64", "b")):
                    name = f"grype_0.119.0_linux_{arch}.tar.gz"
                    expected[name] = digit * 64
                    grype_checksums += f"{digit*64}  {name}\n"
                downloads["https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_checksums.txt"] = grype_checksums.encode()

                def download(url):
                    if case == "late download failure" and "/anchore/" in url:
                        raise OSError("download failed")
                    return downloads[url]

                trivy = "v0.76.0" if case in ("unchanged", "grype only") else "v0.77.0"
                grype = "0.118.0" if case in ("unchanged", "trivy only") else "0.119.0"
                if case == "invalid version":
                    trivy = "v0.77.0; echo unsafe"
                success = case in ("both", "trivy only", "grype only", "unchanged")
                with patch.object(updater, "ACTION_DIR", root), patch.object(updater, "download", side_effect=download) as fetch:
                    if success:
                        updater.update_scanners(trivy, grype)
                    else:
                        with self.assertRaises((ValueError, KeyError, OSError)):
                            updater.update_scanners(trivy, grype)
                    if case == "unchanged":
                        fetch.assert_not_called()
                if not success or case == "unchanged":
                    self.assertEqual(action.read_text(), original)
                    self.assertEqual(manifest.read_text(), old_pins)
                    continue
                self.assertIn("        TRIVY_VERSION: " + trivy.removeprefix("v") + "\n", action.read_text())
                self.assertIn("        GRYPE_VERSION: " + grype + "\n", action.read_text())
                self.assertIn("        GRYPE_VERSION: ${{ steps.paths.outputs.grype_version }}", action.read_text())
                pins = dict(line.split()[::-1] for line in manifest.read_text().splitlines())
                self.assertEqual(len(pins), 4)
                for name, digest in expected.items():
                    if (name.startswith("trivy_") and case == "grype only" or
                            name.startswith("grype_") and case == "trivy only"):
                        continue
                    self.assertEqual(pins[name], digest)


if __name__ == "__main__":
    unittest.main()
