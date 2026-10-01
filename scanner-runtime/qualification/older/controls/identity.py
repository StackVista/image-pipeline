"""Fail closed on downloaded tool identity before every scanner control."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

HEAD = '906ee014101bb9a1697e91b0ba44e86d5b9044cc'
EXPECTED = {
    ('candidate', 'trivy'): 'e123a6ce7018c4ba09cdc1a7a0f49cb9572cd1295da6629d518774f815c92ed3',
    ('candidate', 'grype'): '71c5ce3e6abdf04f2ac89f6647e61afc0197f8d5ef5c48d83969482709e441f3',
    ('original', 'trivy'): '379d59f24a4a828c55de5f0b91b6805cc35d13580180b658820e648611256166',
    ('original', 'grype'): 'd515f53bd5ee4930e144c6ea14a2659084763c336a1833b723db0b05080fcaf5',
}


def verify(path, variant, tool):
    path = Path(path).resolve(strict=True)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != EXPECTED[variant, tool] or not os.access(path, os.X_OK):
        raise ValueError(f'unexpected or non-executable {variant} {tool}: {path}')
    metadata = subprocess.check_output(['go', 'version', '-m', str(path)], text=True)
    if variant == 'candidate':
        if ('vcs.revision=' + HEAD not in metadata or 'vcs.modified=false' not in metadata
                or 'go.yaml.in/yaml/v3\tv3.0.5' not in metadata or 'gopkg.in/yaml.' in metadata):
            raise ValueError('candidate source/parser identity mismatch')
    elif 'gopkg.in/yaml.v3\tv3.0.1' not in metadata:
        raise ValueError('original parser identity mismatch')
    version = subprocess.check_output([str(path), 'version'], text=True)
    expected_version={'trivy': '0.70.0', 'grype': '0.112.0'}[tool]
    if expected_version not in version:
        raise ValueError('scanner generation mismatch')
    return {'path': str(path), 'sha256': digest, 'version': version, 'build_metadata': metadata}


def execute(path, variant, tool, arguments, evidence, **kwargs):
    identity = verify(path, variant, tool)
    result = subprocess.run([identity['path'], *arguments], **kwargs)
    evidence.append({'identity': identity, 'arguments': arguments, 'exit': result.returncode})
    return result
