#!/usr/bin/env python3
"""Verify complete upstream trees, attributed deltas and active security inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AREA = ROOT / 'scanner-runtime'


def identity(path):
    if path.is_symlink():
        return {'mode': '120000', 'target': os.readlink(path)}
    return {'mode': '100755' if path.stat().st_mode & 0o111 else '100644',
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def security_inputs():
    paths = list((ROOT / '.github/workflows').glob('*.yml'))
    paths += list((ROOT / '.github/workflows').glob('*.yaml'))
    paths += list((ROOT / '.github/actions').rglob('action.yml'))
    paths += list((ROOT / '.github/actions').rglob('action.yaml'))
    paths += [ROOT / p for p in ('action.yml', 'action.yaml', '.github/dependabot.yml',
                               '.github/dependabot.yaml') if (ROOT / p).is_file()]
    return sorted(str(p.relative_to(ROOT)) for p in paths)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--record', action='store_true')
    args = parser.parse_args()
    original = json.loads((AREA / 'original-inventory.json').read_text())
    imports = json.loads((AREA / 'import-attribution.json').read_text())
    attributed = {}
    for source in original['sources']:
        base = AREA / 'sources' / source['name']
        actual = {str(p.relative_to(base)): identity(p) for p in base.rglob('*')
                  if p.is_symlink() or p.is_file()}
        if set(actual) != set(source['files']):
            raise ValueError(f"unattributed additions/removals: {source['name']}")
        for rel, expected in source['files'].items():
            if actual[rel] == expected:
                continue
            path = str((base / rel).relative_to(ROOT))
            if path in imports:
                reason = imports[path]
            elif rel in ('go.mod', 'go.sum', 'v2/go.mod', 'v2/go.sum'):
                reason = ['maintained v3 selection, explicit owning-module replacements and normal Go metadata']
            else:
                raise ValueError(f'unattributed upstream edit: {path}')
            if expected['mode'] != actual[rel]['mode']:
                raise ValueError(f'upstream mode changed: {path}')
            attributed[path] = {'original': expected, 'candidate': actual[rel], 'reason': reason}
    attribution = AREA / 'candidate-attribution.json'
    active = AREA / 'active-security-inputs.json'
    if args.record:
        attribution.write_text(json.dumps(attributed, indent=2, sort_keys=True) + '\n')
        active.write_text(json.dumps(security_inputs(), indent=2) + '\n')
    else:
        if json.loads(attribution.read_text()) != attributed:
            raise ValueError('candidate attribution differs from recorded source delta')
        if json.loads(active.read_text()) != security_inputs():
            raise ValueError('active workflow/action collection differs from recorded inventory')
    for path in security_inputs():
        if 'scanner-runtime/sources/' in (ROOT / path).read_text():
            raise ValueError(f'active security input references inert upstream workflow/action: {path}')
    print(f"Verified {sum(len(s['files']) for s in original['sources'])} original entries, "
          f"{len(attributed)} attributed deltas, {len(security_inputs())} active security inputs")


if __name__ == '__main__':
    main()
