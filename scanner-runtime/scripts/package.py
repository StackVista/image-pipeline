#!/usr/bin/env python3
"""Archive native candidate binaries with reproducible source and build evidence."""
import hashlib
import json
import subprocess
import sys
import tarfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
arch = sys.argv[1]
out = root / 'scanner-runtime/out' / arch
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
if (out / 'source-commit.txt').read_text().strip() != commit:
    raise ValueError('build source differs from packaging source')
for tool in ('trivy', 'grype'):
    text = (out / f'{tool}-buildinfo.txt').read_text()
    if 'go.yaml.in/yaml/v3' not in text or 'v3.0.5' not in text:
        raise ValueError(f'{tool}: maintained parser metadata missing')
    if f'vcs.revision={commit}' not in text or 'vcs.modified=true' in text:
        raise ValueError(f'{tool}: clean candidate VCS provenance missing')
manifest = {'source_commit': commit, 'architecture': arch,
            'qualification': 'source/build candidate; consumer adoption not qualified',
            'files': {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in out.rglob('*') if p.is_file()},
            'source_inventory_sha256': hashlib.sha256((root / 'scanner-runtime/original-inventory.json').read_bytes()).hexdigest(),
            'patch_attribution_sha256': hashlib.sha256((root / 'scanner-runtime/candidate-attribution.json').read_bytes()).hexdigest()}
(out / 'provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
archive = out / f'scanner-runtime-{commit}-linux-{arch}.tar.gz'
with tarfile.open(archive, 'w:gz') as tar:
    for path in sorted(out.iterdir()):
        if path.is_file() and path != archive:
            tar.add(path, arcname=path.name)
    if (out / 'contracts').is_dir():
        tar.add(out / 'contracts', arcname='contracts')
    for name in ('original-inventory.json', 'candidate-attribution.json', 'import-attribution.json'):
        tar.add(root / 'scanner-runtime' / name, arcname=f'source/{name}')
    tar.add(root / 'scanner-runtime/provenance', arcname='source/builder')
    inventory = json.loads((root / 'scanner-runtime/original-inventory.json').read_text())
    for source in inventory['sources']:
        for rel in source['files']:
            if Path(rel).name.upper().startswith(('LICENSE', 'NOTICE', 'COPYING')):
                tar.add(root / 'scanner-runtime/sources' / source['name'] / rel,
                        arcname=f"licenses/{source['name']}/{rel}")
(out / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
print(archive.name)
