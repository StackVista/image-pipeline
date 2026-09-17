"""Assemble recorded architecture digests and resume an interrupted signature."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


class PublicationError(RuntimeError):
    pass


def transient(message):
    return bool(re.search(r"\b(?:429|500|502|503|504)\b|timeout|timed out|connection reset|TLS handshake|temporary failure", message, re.I))


def command(*args, allow_failure=False):
    for attempt in range(4):
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 or not transient(result.stderr) or attempt == 3:
            break
        time.sleep(5 * 2**attempt)
    if result.returncode and not allow_failure:
        raise PublicationError(f"{args[0]} failed: {result.stderr.strip()}")
    return result


def inspect(reference, missing_ok=False):
    result = command("docker", "buildx", "imagetools", "inspect", reference, "--raw", allow_failure=True)
    if result.returncode == 0:
        return result.stdout
    error = result.stderr.lower()
    # Only an explicit manifest-not-found response means publication is absent.
    if missing_ok and not re.search(r"401|403|unauthorized|denied|forbidden", error) and (
        "manifest unknown" in error or "manifest_unknown" in error or
        re.search(r": not found\s*$", error)
    ):
        return None
    raise PublicationError(f"Cannot inspect {reference}: {result.stderr.strip()}")


def recorded_targets(directory, image, tag, arches):
    expected = {
        "image": image, "tag": tag, "repository": os.environ["GITHUB_REPOSITORY"],
        "sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
    }
    receipts = {}
    for path in Path(directory).rglob("*.json"):
        receipt = json.loads(path.read_text())
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise PublicationError(f"Receipt source mismatch: {path.name}")
        arch = receipt.get("arch")
        if arch not in arches or arch in receipts:
            raise PublicationError(f"Unexpected or duplicate architecture: {arch}")
        digest = receipt.get("digest", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise PublicationError(f"Invalid digest for {arch}")
        receipts[arch] = f"{image}@{digest}"
    if set(receipts) != set(arches):
        raise PublicationError("Missing architecture receipt")
    return [receipts[arch] for arch in arches]


def verify_signature(reference, bundle, identity):
    return command(
        "cosign", "verify", f"--new-bundle-format={str(bundle).lower()}",
        "--certificate-oidc-issuer=https://token.actions.githubusercontent.com",
        f"--certificate-identity-regexp={identity}", reference, allow_failure=True,
    )


def ensure_signatures(reference, identity):
    for bundle in (False, True):
        result = verify_signature(reference, bundle, identity)
        if result.returncode == 0:
            continue
        if transient(result.stderr) or re.search(r"401|403|unauthorized|denied|forbidden", result.stderr, re.I):
            raise PublicationError(f"Signature lookup unavailable: {result.stderr.strip()}")
        command("cosign", "sign", "--yes", f"--new-bundle-format={str(bundle).lower()}",
                f"--use-signing-config={str(bundle).lower()}", reference)
        result = verify_signature(reference, bundle, identity)
        if result.returncode:
            raise PublicationError(f"Signature verification failed: {result.stderr.strip()}")


def validate_platforms(manifest, arches):
    children = manifest.get("manifests", [])
    platforms = [(child.get("platform", {}).get("os", ""), child.get("platform", {}).get("architecture", ""))
                 for child in children if child.get("annotations", {}).get("vnd.docker.reference.type") != "attestation-manifest"]
    if sorted(platforms) != sorted(("linux", arch) for arch in arches):
        raise PublicationError(f"Unexpected manifest platforms: {platforms}")


def publish(image, tag, arches, receipt_dir):
    if not arches or len(set(arches)) != len(arches):
        raise PublicationError("Provide distinct architectures")
    release = f"{image}:{tag}"
    existing = inspect(release, missing_ok=True)
    if existing is not None and not receipt_dir:
        raise PublicationError("Release exists; safe resume requires architecture receipts")
    targets = recorded_targets(receipt_dir, image, tag, arches) if receipt_dir else [f"{release}-{arch}" for arch in arches]
    identity = ("^" + re.escape(os.environ["GITHUB_SERVER_URL"] + "/" + os.environ["GITHUB_REPOSITORY"])
                + r"/\.github/workflows/[^@]+@" + re.escape(os.environ["GITHUB_REF"]) + "$")
    if receipt_dir:
        for target in targets:
            result = verify_signature(target, True, identity)
            if result.returncode:
                raise PublicationError(f"Architecture signature invalid: {result.stderr.strip()}")
    expected_raw = command("docker", "buildx", "imagetools", "create", "--dry-run", "-t", release, *targets).stdout
    expected = json.loads(expected_raw)
    validate_platforms(expected, arches)
    if existing is not None and json.loads(existing) != expected:
        raise PublicationError("Existing release differs from recorded digests; refusing overwrite")
    if existing is None:
        command("docker", "buildx", "imagetools", "create", "-t", release, *targets)
    actual = inspect(release)
    if json.loads(actual) != expected:
        raise PublicationError("Published manifest differs from expected manifest")
    digest = command("docker", "buildx", "imagetools", "inspect", release,
                     "--format", "{{.Manifest.Digest}}").stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or json.loads(inspect(f"{image}@{digest}")) != expected:
        raise PublicationError("Published digest does not identify the expected manifest")
    ensure_signatures(f"{image}@{digest}", identity)
    print(f"Published and verified {release}@{digest}")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a") as stream:
            stream.write(f"digest={digest}\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as stream:
            stream.write(f"- Published and verified `{release}` (`{digest}`; {', '.join(arches)})\n")


if __name__ == "__main__":
    try:
        publish(os.environ["INPUTS_IMAGE"], os.environ["INPUTS_TAG"],
                [arch.strip() for arch in os.environ["INPUTS_ARCHES"].split(",") if arch.strip()],
                os.environ.get("INPUTS_RECEIPTS", ""))
    except (PublicationError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
