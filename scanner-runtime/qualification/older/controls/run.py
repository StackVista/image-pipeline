"""Pair original and checksum-verified native candidate scanners on frozen inputs."""
import argparse
import hashlib
import json
import os
import subprocess
import shlex
import yaml
from pathlib import Path
from identity import execute, verify, HEAD

parser = argparse.ArgumentParser()
parser.add_argument('--work', type=Path, required=True)
parser.add_argument('--candidate', type=Path, required=True)
parser.add_argument('--original', type=Path, required=True)
parser.add_argument('--evaluator', type=Path, required=True)
parser.add_argument('--action', type=Path)
args = parser.parse_args()
root=Path(__file__).resolve().parents[3]
action_path=args.action or root/'.github/actions/scan-image/action.yml'
action=yaml.safe_load(action_path.read_text())
secret_policy=next(step['run'] for step in action['runs']['steps'] if step.get('name')=='Trivy secrets scan')
work = args.work.resolve()
evidence = []
results = {}
images = {'clean': 'runtime-clean', 'secret': 'runtime-secret',
          'vulnerable': 'registry.suse.com/bci/bci-base:15.3@sha256:906ade16ed715fc25a4eb72afcabc51330b9c4f549bb48d752ca64369ba1e227',
          'bci': 'registry.suse.com/bci/bci-micro@sha256:e3a512199e98075db7d74ef9be486aea9ca6c841046330e5dc8c80d77c68df2b'}
base_env = {**os.environ, 'HOME': str(work/'home'),
            'TRIVY_CACHE_DIR': str(work/'cache/trivy'), 'TRIVY_SKIP_DB_UPDATE': 'true',
            'TRIVY_SKIP_JAVA_DB_UPDATE': 'true', 'GRYPE_DB_CACHE_DIR': str(work/'cache/grype'),
            'GRYPE_DB_AUTO_UPDATE': 'false'}
docs = sorted((work/'cache/trivy/vex/repositories').rglob('*openvex*.json'))
usable = []
for p in docs:
    try:
        document = json.loads(p.read_text())
        if isinstance(document, dict) and isinstance(document.get('statements'), list):
            usable.append(p)
    except json.JSONDecodeError:
        pass
docs = usable
if not docs:
    raise ValueError('usable frozen VEX unavailable')

def run(variant, tool, arguments, case, env=None):
    binary = args.candidate/tool if variant=='candidate' else args.original/tool/tool
    r = execute(binary, variant, tool, arguments, evidence, env=env or base_env,
                capture_output=True, text=True, timeout=300)
    (case/f'{tool}-{len(evidence)}.log').write_text(r.stdout+r.stderr)
    (work/'identity-evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
    return r

def evaluate(arguments, case, label):
    command=[str(args.evaluator),*arguments]
    r=subprocess.run(command,capture_output=True,text=True)
    (case/(label+'.log')).write_text(r.stdout+r.stderr)
    with (work/'evaluator-commands.jsonl').open('a') as out:
        out.write(json.dumps({'command':command,'exit':r.returncode,'binary_sha256':hashlib.sha256(args.evaluator.read_bytes()).hexdigest()})+'\n')
    return r

for variant in ['original','candidate']:
    results[variant] = {}
    for kind, image in images.items():
        case=work/variant/kind;case.mkdir(parents=True, exist_ok=True)
        secret=case/'secrets.json'
        r=run(variant,'trivy',['image','--scanners','secret','--format','json','--output',str(secret),'--exit-code','0',image],case)
        assert r.returncode==0
        secrets=sum(len(x.get('Secrets',[])) for x in json.loads(secret.read_text()).get('Results',[]))
        assert (secrets>0)==(kind=='secret')
        results[variant][kind]={'secrets':secrets}
        if kind=='secret':
            for mode in ['gate','inform']:
                policy_case=case/mode;policy_case.mkdir(exist_ok=True)
                bindir=policy_case/'bin';bindir.mkdir(exist_ok=True)
                binary=args.candidate/'trivy' if variant=='candidate' else args.original/'trivy/trivy'
                shim=bindir/'trivy'
                shim.write_text('#!/usr/bin/env bash\nexec python3 '+shlex.quote(str(Path(__file__).with_name('invoke.py')))+' "$@"\n')
                shim.chmod(0o755)
                env={**base_env,'PATH':str(bindir)+':'+os.environ['PATH'],'INPUT_MODE':mode,'INPUT_IMAGE':image,
                     'QUALIFIED_BINARY':str(binary.resolve()),'QUALIFIED_VARIANT':variant,
                     'QUALIFIED_LOG':str(work/'shell-identities.jsonl')}
                r=subprocess.run(['bash','-e','-o','pipefail','-c',secret_policy],cwd=policy_case,env=env,capture_output=True,text=True,timeout=300)
                (policy_case/'policy.log').write_text(r.stdout+r.stderr)
                assert r.returncode==1,(variant,mode,'secret policy failed to reject')
                results[variant][kind][mode]=r.returncode
            continue
        trivy=case/'trivy.json';grype=case/'grype.json'
        r=run(variant,'trivy',['image','--scanners','vuln','--format','json','--output',str(trivy),'--severity','HIGH,CRITICAL','--vex','repo','--skip-vex-repo-update','--exit-code','0',image],case)
        assert r.returncode==0
        vex=[]
        for p in docs:vex+=['--vex',str(p)]
        r=run(variant,'grype',[image,*vex,'--by-cve','-o','json='+str(grype)],case)
        assert r.returncode==0
        assert json.loads(grype.read_text())['descriptor']['version']=='0.112.0'
        for mode in ['gate','inform']:
            sarif=case/(mode+'.sarif')
            r=evaluate(['--image',image,'--severity','HIGH,CRITICAL','--mode',mode,'--trivy-json',str(trivy),'--grype-json',str(grype),'--sarif',str(sarif)],case,mode)
            expected=0 if kind=='clean' or mode=='inform' else 1
            assert r.returncode==expected,(variant,kind,mode,r.stderr)
            results[variant][kind][mode]=r.returncode
        if kind=='clean':
            malformed=case/'malformed';malformed.mkdir(exist_ok=True);(malformed/'bad.yaml').write_text('version: [unterminated\n')
            for mode in ['gate','inform']:
                r=evaluate(['--image',image,'--severity','HIGH,CRITICAL','--mode',mode,'--exceptions',str(malformed),'--trivy-json',str(trivy),'--sarif',str(case/('malformed-'+mode+'.sarif'))],case,'malformed-'+mode)
                assert r.returncode==2;results[variant][kind]['malformed-'+mode]=2
        print(variant,kind,results[variant][kind],flush=True)
    errorcase=work/variant/'errors';errorcase.mkdir(exist_ok=True)
    for mode in ['gate','inform']:
        env={**base_env,'GRYPE_DB_CACHE_DIR':str(errorcase/'absent-db')}
        r=run(variant,'grype',['runtime-clean','-o','json'],errorcase,env)
        assert r.returncode==1;results[variant]['tool-error-'+mode]=r.returncode
    # VEX-unavailability invokes the exact canonical action configure block.
    import yaml
    root=Path(__file__).resolve().parents[3]
    action=yaml.safe_load(action_path.read_text())
    configure=next(s['run'] for s in action['runs']['steps'] if s.get('name')=='Configure and download VEX repos')
    for mode in ['gate','inform']:
        case=errorcase/mode;case.mkdir(exist_ok=True);repo=case/'repo/vex';repo.mkdir(parents=True,exist_ok=True)
        (repo/'repository.yaml').write_text('repositories:\n  - name: unavailable\n    url: http://127.0.0.1:9\n    enabled: true\n')
        bindir=case/'bin';bindir.mkdir(exist_ok=True)
        tool=args.candidate/'trivy' if variant=='candidate' else args.original/'trivy/trivy'
        identity=verify(tool,variant,'trivy');shim=bindir/'trivy'
        shim.write_text('#!/usr/bin/env bash\nexec python3 '+shlex.quote(str(Path(__file__).with_name('invoke.py')))+' "$@"\n');shim.chmod(0o755)
        env={**base_env,'PATH':str(bindir)+':'+os.environ['PATH'],'HOME':str(case),'TRIVY_CACHE_DIR':str(case/'cache'),'REPO_ROOT':str(repo.parent),'INPUT_MODE':mode,'QUALIFIED_BINARY':identity['path'],'QUALIFIED_VARIANT':variant,'QUALIFIED_LOG':str(work/'shell-identities.jsonl')}
        resolved=subprocess.check_output(['bash','-c','command -v trivy'],env=env,text=True).strip()
        assert Path(resolved).resolve()==shim.resolve()
        r=subprocess.run(['bash','-c',configure],cwd=case,env=env,capture_output=True,text=True,timeout=60)
        (case/'vex-policy.log').write_text(r.stdout+r.stderr)
        evidence.append({'identity':identity,'control':'active unreachable VEX '+mode,'exit':r.returncode})
        assert r.returncode==1
        results[variant]['missing-vex-'+mode]=r.returncode
    (work/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    (work/'identity-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
assert results['original']==results['candidate']
comparisons={}
for kind in ['clean','vulnerable','bci']:
    comparisons[kind]={}
    for tool in ['trivy','grype']:
        a=json.loads((work/'original'/kind/(tool+'.json')).read_text());b=json.loads((work/'candidate'/kind/(tool+'.json')).read_text())
        if tool=='trivy':
            for j in (a,b):j.pop('CreatedAt',None);j.pop('ReportID',None)
        else:
            for variant, j in [('original', a), ('candidate', b)]:
                j['descriptor'].pop('timestamp',None)
                expected_output = 'json=' + str(work/variant/kind/'grype.json')
                assert j['descriptor']['configuration']['output'] == [expected_output]
                j['descriptor']['configuration']['output'] = ['json=grype.json']
        comparisons[kind][tool]={'equal_except_volatile_and_output_path':a==b}
    for mode in ['gate','inform']:
        comparisons[kind][mode+'-sarif']={'equal':json.loads((work/'original'/kind/(mode+'.sarif')).read_text())==json.loads((work/'candidate'/kind/(mode+'.sarif')).read_text())}
(work/'comparisons.json').write_text(json.dumps(comparisons,indent=2)+'\n')
(work/'identity-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
print('Policy controls passed; output equality status recorded separately',flush=True)
