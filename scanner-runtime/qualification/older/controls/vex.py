"""Execute unchanged VEX preflight for distinct absence and unreachable controls."""
import hashlib
import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path
import yaml

parser = argparse.ArgumentParser()
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--action', type=Path, required=True)
parser.add_argument('--original', type=Path, required=True)
parser.add_argument('--candidate', type=Path, required=True)
parser.add_argument('--family', choices=['older', 'newer'], required=True)
args = parser.parse_args()
action = yaml.safe_load(args.action.read_text())
block = next(s['run'] for s in action['runs']['steps']
             if s.get('name') == 'Configure and download VEX repos')
results = []
for variant in ['original', 'candidate']:
    binary = args.original/'trivy/trivy' if variant == 'original' else args.candidate/'trivy'
    for condition in ['absent-usable-material', 'active-unreachable-endpoint']:
        for mode in ['gate', 'inform']:
            case = args.work/variant/'vex-controls'/condition/mode
            case.mkdir(parents=True, exist_ok=True)
            repo = case/'repo/vex'
            repo.mkdir(parents=True, exist_ok=True)
            config = ('repositories: []\n' if condition == 'absent-usable-material' else
                      'repositories:\n  - name: unavailable\n    url: http://127.0.0.1:9\n    enabled: true\n')
            (repo/'repository.yaml').write_text(config)
            fixture_manifest=case/'fixture-manifest.json'
            fixture_manifest.write_text(json.dumps({str((repo/'repository.yaml').resolve()):hashlib.sha256(config.encode()).hexdigest(),str(args.action.resolve()):hashlib.sha256(args.action.read_bytes()).hexdigest()},indent=2)+'\n')
            bindir = case/'bin'
            bindir.mkdir(exist_ok=True)
            shim = bindir/'trivy'
            shim.write_text('#!/usr/bin/env bash\nexec python3 '+
                            shlex.quote(str(Path(__file__).with_name('invoke.py')))+' "$@"\n')
            shim.chmod(0o755)
            env = {**os.environ, 'PATH': str(bindir)+':'+os.environ['PATH'],
                   'HOME': str(case), 'TRIVY_CACHE_DIR': str(case/'cache'),
                   'REPO_ROOT': str(repo.parent), 'INPUT_MODE': mode,
                   'QUALIFIED_BINARY': str(binary.resolve()), 'QUALIFIED_VARIANT': variant,
                   'QUALIFIED_LOG': str(args.work/'vex-identities.jsonl'), 'FROZEN_INPUTS_MANIFEST':str(fixture_manifest)}
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', block],
                                    cwd=case, env=env, capture_output=True, text=True, timeout=90)
            (case/'policy.log').write_text(result.stdout+result.stderr)
            expected = 0 if args.family == 'newer' and mode == 'inform' else 1
            assert result.returncode == expected, (variant, condition, mode, result.stderr)
            results.append({'variant': variant, 'condition': condition, 'mode': mode,
                            'exit': result.returncode})
            (args.work/'vex-controls.json').write_text(json.dumps(results, indent=2)+'\n')
            print(variant, condition, mode, result.returncode, flush=True)
