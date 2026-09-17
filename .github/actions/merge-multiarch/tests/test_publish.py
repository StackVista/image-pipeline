import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("publish", Path(__file__).parents[1] / "publish.py")
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)
DIGEST = "sha256:" + "a" * 64
MANIFEST = {
    "manifests": [
        {"digest": "sha256:" + char * 64, "platform": {"os": "linux", "architecture": arch}}
        for arch, char in (("amd64", "b"), ("arm64", "c"))
    ]
}
ENV = {
    "GITHUB_REPOSITORY": "StackVista/docker-images",
    "GITHUB_RUN_ID": "42",
    "GITHUB_SHA": "abc",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REF": "refs/heads/main",
}


class PublisherTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.env = patch.dict(os.environ, ENV)
        self.env.start()
        self.addCleanup(self.env.stop)
        for arch, char in (("amd64", "b"), ("arm64", "c")):
            (self.directory / f"{arch}.json").write_text(
                json.dumps(
                    {
                        "image": "registry/image",
                        "tag": "v1",
                        "arch": arch,
                        "digest": "sha256:" + char * 64,
                        "repository": ENV["GITHUB_REPOSITORY"],
                        "sha": "abc",
                        "run_id": "42",
                    }
                )
            )
        self.existing = None
        self.signatures = set()
        self.created = 0
        self.commands = []
        self.fail_sign = False
        self.fail_create = False

    def command(self, *args, **kwargs):
        self.commands.append(args)
        output = ""
        code = 0
        error = ""
        if args[0] == "docker" and "create" in args:
            for target in args[args.index("registry/image:v1") + 1 :]:
                self.assertIn("@sha256:", target)
            if "--dry-run" in args:
                output = json.dumps(MANIFEST)
            else:
                if self.fail_create:
                    raise publish.PublicationError("injected before manifest")
                self.existing = json.dumps(MANIFEST)
                self.created += 1
        elif "--format" in args:
            output = DIGEST
        elif args[:2] == ("cosign", "verify"):
            output = json.dumps(
                [
                    {
                        "critical": {
                            "type": "https://sigstore.dev/cosign/sign/v1"
                            if args[2].endswith("=true")
                            else "cosign container image signature"
                        }
                    }
                ]
            )
            if args[-1] == "registry/image@" + DIGEST and args[2] not in self.signatures:
                code, error = 1, "no signatures found"
        elif args[:2] == ("cosign", "sign"):
            if self.fail_sign and "--new-bundle-format=true" in args:
                raise publish.PublicationError("injected signing failure")
            self.signatures.add(args[3])
        return subprocess.CompletedProcess(args, code, output, error)

    def inspect(self, reference, missing_ok=False):
        return self.existing

    def run_publish(self):
        with (
            patch.object(publish, "command", self.command),
            patch.object(publish, "inspect", self.inspect),
        ):
            publish.publish("registry/image", "v1", ["amd64", "arm64"], self.directory)

    def test_failure_before_manifest_then_retry(self):
        self.fail_create = True
        with self.assertRaisesRegex(publish.PublicationError, "before manifest"):
            self.run_publish()
        self.assertIsNone(self.existing)
        self.fail_create = False
        self.run_publish()
        self.assertEqual(self.created, 1)

    def test_partial_signing_resumes_and_complete_retry_is_noop(self):
        self.fail_sign = True
        with self.assertRaisesRegex(publish.PublicationError, "signing failure"):
            self.run_publish()
        self.assertEqual(self.created, 1)
        self.fail_sign = False
        self.run_publish()
        self.assertEqual(self.created, 1)
        signs = len([c for c in self.commands if c[:2] == ("cosign", "sign")])
        self.run_publish()
        self.assertEqual(signs, len([c for c in self.commands if c[:2] == ("cosign", "sign")]))

    def test_existing_unsigned_exact_manifest_resumes(self):
        self.existing = json.dumps(MANIFEST)
        self.run_publish()
        self.assertEqual(self.created, 0)
        self.assertEqual(len(self.signatures), 2)

    def test_conflict_never_overwrites(self):
        self.existing = json.dumps({"manifests": []})
        with self.assertRaisesRegex(publish.PublicationError, "refusing overwrite"):
            self.run_publish()
        self.assertEqual(self.created, 0)
        self.assertFalse(self.signatures)

    def test_changed_mutable_tags_are_never_read(self):
        self.run_publish()
        self.assertFalse(any("v1-amd64" in str(c) or "v1-arm64" in str(c) for c in self.commands))

    def test_receipt_wrong_source_missing_and_duplicate(self):
        for field, value in (
            ("sha", "wrong"),
            ("run_id", "41"),
            ("image", "other"),
            ("repository", "other"),
        ):
            path = self.directory / "amd64.json"
            original = path.read_text()
            record = json.loads(original)
            record[field] = value
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(publish.PublicationError, "source mismatch"):
                self.run_publish()
            path.write_text(original)
        (self.directory / "duplicate.json").write_text((self.directory / "amd64.json").read_text())
        with self.assertRaisesRegex(publish.PublicationError, "duplicate"):
            self.run_publish()
        (self.directory / "duplicate.json").unlink()
        (self.directory / "arm64.json").unlink()
        with self.assertRaisesRegex(publish.PublicationError, "Missing architecture"):
            self.run_publish()

    def test_missing_platform_and_attestation(self):
        with self.assertRaises(publish.PublicationError):
            publish.validate_platforms({"manifests": MANIFEST["manifests"][:1]}, ["amd64", "arm64"])
        with_attestation = {
            "manifests": MANIFEST["manifests"]
            + [
                {
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
                }
            ]
        }
        publish.validate_platforms(with_attestation, ["amd64", "arm64"])

    def test_existing_without_receipts_remains_blocked(self):
        with patch.object(publish, "inspect", return_value=json.dumps(MANIFEST)):
            with self.assertRaisesRegex(publish.PublicationError, "requires architecture receipts"):
                publish.publish("registry/image", "v1", ["amd64", "arm64"], "")

    def test_registry_absence_differs_from_outage(self):
        for message in (
            "401 Unauthorized",
            "503 Service Unavailable",
            "timeout",
            "403 denied: not found",
            "503 upstream: not found",
        ):
            with patch.object(
                publish, "command", return_value=subprocess.CompletedProcess([], 1, "", message)
            ):
                with self.assertRaises(publish.PublicationError):
                    publish.inspect("image:tag", missing_ok=True)
        with patch.object(
            publish,
            "command",
            return_value=subprocess.CompletedProcess([], 1, "", "image:tag: not found\n"),
        ):
            self.assertIsNone(publish.inspect("image:tag", missing_ok=True))

    def test_legacy_fallback_is_not_a_new_format_signature(self):
        legacy = json.dumps([{"critical": {"type": "cosign container image signature"}}])
        with patch.object(
            publish, "command", return_value=subprocess.CompletedProcess([], 0, legacy, "")
        ):
            self.assertNotEqual(
                publish.verify_signature("image@digest", True, "identity").returncode, 0
            )

    def test_single_arch_guard_does_not_authorize_push_on_registry_error(self):
        action = Path(__file__).parents[2] / "push-single-arch" / "action.yml"
        guard = action.read_text().split("    - name: Fail if final tag already exists", 1)[1]
        script = textwrap.dedent(guard.split("      run: |\n", 1)[1].split("    - name:", 1)[0])
        docker = self.directory / "docker"
        docker.write_text('#!/bin/sh\nprintf "%s\\n" "$LOOKUP_ERROR" >&2\nexit 1\n')
        docker.chmod(0o755)
        env = dict(
            os.environ,
            PATH=str(self.directory) + os.pathsep + os.environ["PATH"],
            IMAGE="image",
            TAG="v1",
        )
        for message, allowed in (
            ("image:v1: not found", True),
            ("503 upstream: not found", False),
            ("401 denied: not found", False),
            ("unexpected EOF", False),
        ):
            with self.subTest(message=message):
                result = subprocess.run(
                    ["bash", "-c", script],
                    env=dict(env, LOOKUP_ERROR=message),
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode == 0, allowed)

    def test_timeout_retries_then_returns_success(self):
        success = subprocess.CompletedProcess([], 0, "manifest", "")
        with (
            patch.object(
                publish.subprocess,
                "run",
                side_effect=[subprocess.TimeoutExpired("docker", 300), success],
            ) as run,
            patch.object(publish.time, "sleep") as sleep,
        ):
            self.assertEqual(publish.command("docker", "inspect").stdout, "manifest")
            self.assertEqual(run.call_count, 2)
            sleep.assert_called_once_with(5)

    def test_timeout_retries_are_bounded(self):
        with (
            patch.object(
                publish.subprocess, "run", side_effect=subprocess.TimeoutExpired("docker", 300)
            ) as run,
            patch.object(publish.time, "sleep"),
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                publish.command("docker", "inspect")
            self.assertEqual(run.call_count, 4)

    def test_bounded_retry_only_transient(self):
        for error, expected_calls in (("503 Service Unavailable", 4), ("401 Unauthorized", 1)):
            with (
                patch.object(
                    publish.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 1, "", error),
                ) as run,
                patch.object(publish.time, "sleep"),
            ):
                with self.assertRaises(publish.PublicationError):
                    publish.command("docker", "inspect")
                self.assertEqual(run.call_count, expected_calls)


if __name__ == "__main__":
    unittest.main()
