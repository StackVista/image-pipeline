"""Fail closed on downloaded tool identity before every scanner control."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

HEAD = '5c5ac0665b8c308ac7efa05ee397ef5f9e02c255'
EXPECTED = {
    ('candidate', 'trivy'): 'ea464f20867193e6aeabe17e82cb614c492ceb9ca8d2a661e34b470ccef029f6',
    ('candidate', 'grype'): '4c0ff7b02d9d7998c5beff088416ba514b916cc1047a6a261d751eed8b92c57d',
    ('original', 'trivy'): 'd89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791',
    ('original', 'grype'): '91705979c6ccb736b87e3250831f5e1a35f13767fd2032ffa85c55b1e6f58f90',
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
    expected_version={'trivy': '0.74.0', 'grype': '0.118.0'}[tool]
    if expected_version not in version:
        raise ValueError('scanner generation mismatch')
    return {'path': str(path), 'sha256': digest, 'version': version, 'build_metadata': metadata}


def execute(path, variant, tool, arguments, evidence, **kwargs):
    identity = verify(path, variant, tool)
    result = subprocess.run([identity['path'], *arguments], **kwargs)
    evidence.append({'identity': identity, 'arguments': arguments, 'exit': result.returncode})
    return result
