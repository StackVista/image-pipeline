"""Retain bounded original/candidate Grype repeats on the primary frozen inputs."""
import argparse
import json
import os
import subprocess
from pathlib import Path
from identity import execute

parser = argparse.ArgumentParser()
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--evaluator', type=Path, required=True)
args = parser.parse_args()
work = args.work.resolve()
prior = json.loads((work/'identity-evidence.json').read_text())
rows = []
env = {**os.environ, 'HOME': str(work/'home'),
       'GRYPE_DB_CACHE_DIR': str(work/'cache/grype'), 'GRYPE_DB_AUTO_UPDATE': 'false'}
for variant in ['original', 'candidate']:
    call = next(row for row in prior if '/'+variant+'s/' in row['identity']['path']
                and row['arguments'][0].startswith('registry.suse.com/bci/bci-base')) if variant == 'original' else next(
                    row for row in prior if 'signed/' in row['identity']['path']
                    and row['arguments'][0].startswith('registry.suse.com/bci/bci-base'))
    case = work/variant/'repeat'
    case.mkdir(exist_ok=True)
    command = list(call['arguments'])
    command[-1] = 'json='+str(case/'grype.json')
    result = execute(call['identity']['path'], variant, 'grype', command, rows,
                     env=env, capture_output=True, text=True, timeout=300)
    (case/'scanner.log').write_text(result.stdout+result.stderr)
    assert result.returncode == 0
    for mode in ['gate', 'inform']:
        evaluation = [str(args.evaluator), '--image', command[0], '--severity',
                      'HIGH,CRITICAL', '--mode', mode, '--trivy-json',
                      str(work/variant/'vulnerable/trivy.json'), '--grype-json',
                      str(case/'grype.json'), '--sarif', str(case/(mode+'.sarif'))]
        result = subprocess.run(evaluation, capture_output=True, text=True)
        (case/(mode+'.log')).write_text(result.stdout+result.stderr)
        rows.append({'command': evaluation, 'exit': result.returncode})
        assert result.returncode == (1 if mode == 'gate' else 0)
    (work/'repeat-identities.json').write_text(json.dumps(rows, indent=2)+'\n')
    print(variant, 'repeat complete', flush=True)
