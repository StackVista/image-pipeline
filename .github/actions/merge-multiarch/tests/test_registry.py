"""Opt-in isolated-registry test. CI uses real keyless signatures."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_publish import publish


@unittest.skipUnless(
    os.environ.get("PUBLICATION_TEST_REGISTRY"), "requires an isolated local registry"
)
class RegistryTest(unittest.TestCase):
    def test_resume_keeps_manifest_and_successful_signature(self):
        registry = os.environ["PUBLICATION_TEST_REGISTRY"]
        self.assertTrue(registry.startswith("localhost:"), "fixture must not publish externally")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = registry + "/publication-test"
            (root / "Dockerfile").write_text("FROM scratch\nCOPY hello /hello\n")
            (root / "hello").write_text("publication recovery fixture\n")
            receipts = root / "receipts"
            receipts.mkdir()
            real_command = publish.command
            signed = set()
            fake_signing = os.environ.get("PUBLICATION_FAKE_SIGNING") == "1"
            interrupted = False

            def command(*args, **kwargs):
                nonlocal interrupted
                if (
                    args[:2] == ("cosign", "sign")
                    and args[-1] == final_reference
                    and "--new-bundle-format=true" in args
                    and not interrupted
                ):
                    interrupted = True
                    raise publish.PublicationError("injected interruption during signing")
                if args[0] == "cosign" and fake_signing:
                    bundle = next(arg for arg in args if arg.startswith("--new-bundle-format="))
                    key = (args[-1], bundle)
                    if args[1] == "sign":
                        signed.add(key)
                    code = int(args[1] == "verify" and key not in signed)
                    payload = json.dumps(
                        [
                            {
                                "critical": {
                                    "type": "https://sigstore.dev/cosign/sign/v1"
                                    if bundle.endswith("=true")
                                    else "cosign container image signature"
                                }
                            }
                        ]
                    )
                    return subprocess.CompletedProcess(
                        args, code, payload, "no signatures found" if code else ""
                    )
                return real_command(*args, **kwargs)

            final_reference = None
            with patch.object(publish, "command", command):
                for arch in ("amd64", "arm64"):
                    metadata = root / f"{arch}-build.json"
                    real_command(
                        "docker",
                        "buildx",
                        "build",
                        "--platform",
                        "linux/" + arch,
                        "--provenance=mode=max",
                        "--sbom=false",
                        "--push",
                        "--metadata-file",
                        str(metadata),
                        "-t",
                        image + ":v1-" + arch,
                        str(root),
                    )
                    digest = json.loads(metadata.read_text())["containerimage.digest"]
                    command(
                        "cosign",
                        "sign",
                        "--yes",
                        "--new-bundle-format=true",
                        "--use-signing-config=true",
                        image + "@" + digest,
                    )
                    (receipts / f"{arch}.json").write_text(
                        json.dumps(
                            dict(
                                image=image,
                                tag="v1",
                                arch=arch,
                                digest=digest,
                                repository=os.environ["GITHUB_REPOSITORY"],
                                sha=os.environ["GITHUB_SHA"],
                                run_id=os.environ["GITHUB_RUN_ID"],
                            )
                        )
                    )
                # Inject only after the final manifest exists, preserving its exact digest.
                original_ensure = publish.ensure_signatures

                def interrupt_signing(reference, identity):
                    nonlocal final_reference
                    final_reference = reference
                    return original_ensure(reference, identity)

                with patch.object(publish, "ensure_signatures", interrupt_signing):
                    with self.assertRaisesRegex(publish.PublicationError, "injected interruption"):
                        publish.publish(image, "v1", ["amd64", "arm64"], receipts)
                before = real_command(
                    "docker", "buildx", "imagetools", "inspect", image + ":v1", "--raw"
                ).stdout
                publish.publish(image, "v1", ["amd64", "arm64"], receipts)
                publish.publish(image, "v1", ["amd64", "arm64"], receipts)
                after = real_command(
                    "docker", "buildx", "imagetools", "inspect", image + ":v1", "--raw"
                ).stdout
                self.assertEqual(before, after)
                # A mutated architecture tag cannot change the recorded publication.
                real_command(
                    "docker",
                    "buildx",
                    "imagetools",
                    "create",
                    "-t",
                    image + ":v1-amd64",
                    image + ":v1-arm64",
                )
                publish.publish(image, "v1", ["amd64", "arm64"], receipts)
                self.assertEqual(
                    before,
                    real_command(
                        "docker", "buildx", "imagetools", "inspect", image + ":v1", "--raw"
                    ).stdout,
                )
