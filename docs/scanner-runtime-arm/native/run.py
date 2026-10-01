"""Prepare a separately identified snapshot and run only native ARM policy pairs."""
import argparse,hashlib,json,os,platform,shutil,struct,subprocess,tarfile,urllib.request,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('family',choices=['newer','older']);args=p.parse_args()
assert platform.machine() in ('aarch64','arm64'),'native host required'
root=Path.cwd();out=Path(os.environ['ARM_OUTPUT']).resolve();out.mkdir(parents=True,exist_ok=True)
work=out/'reports';work.mkdir();setup=out/'setup';setup.mkdir();tools=out/'tools';tools.mkdir()
family=args.family;source={'newer':'5c5ac0665b8c308ac7efa05ee397ef5f9e02c255','older':'906ee014101bb9a1697e91b0ba44e86d5b9044cc'}[family]
versions={'trivy':'0.74.0' if family=='newer' else '0.70.0','grype':'0.118.0' if family=='newer' else '0.112.0'}
commands=[]
def run(cmd,**kw):
    r=subprocess.run(cmd,capture_output=True,text=True,**kw)
    commands.append({'command':cmd,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    (setup/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    if r.returncode:raise RuntimeError('command failed: '+str(cmd))
    return r.stdout
def sha(f):
    with Path(f).open('rb') as s:return hashlib.file_digest(s,'sha256').hexdigest()
def fetch(url,dest):
    run(['curl','--fail','--location','--retry','2','--max-time','180','--output',str(dest),url])
    return dest
issuer='https://token.actions.githubusercontent.com'
artifact=11174792711 if family=='newer' else 11179957417
metadata=json.loads(run(['gh','api',f'repos/StackVista/image-pipeline/actions/artifacts/{artifact}']))
assert not metadata['expired'] and metadata['workflow_run']['head_sha']==source
(setup/'artifact.json').write_text(json.dumps(metadata,indent=2))
archive=setup/'artifact.zip'
with archive.open('wb') as f:subprocess.run(['gh','api',f'repos/StackVista/image-pipeline/actions/artifacts/{artifact}/zip'],stdout=f,check=True)
assert 'sha256:'+sha(archive)==metadata['digest']
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():assert not name.startswith('/') and '..' not in Path(name).parts
    z.extractall(setup/'signed')
prefix='scanner-runtime' if family=='newer' else 'older-scanner-runtime'
d=setup/'signed'/f'{prefix}-{source}-arm64'
identity=f'https://github.com/StackVista/image-pipeline/.github/workflows/{"older-" if family=="older" else ""}scanner-runtime-ci.yml@refs/pull/{50 if family=="older" else 49}/merge'
for name in ['SHA256SUMS','provenance.json']:
    run(['cosign','verify-blob','--bundle',str(d/(name+'.sigstore.json')),'--certificate-identity',identity,'--certificate-oidc-issuer',issuer,str(d/name)])
for line in (d/'SHA256SUMS').read_text().splitlines():
    expected,name=line.split();assert sha(d/name)==expected
candidate=tools/'candidate';candidate.mkdir()
def extract(tar,dest):
    with tarfile.open(tar) as t:t.extractall(dest,filter='data')
extract(next(d.glob('*.tar.gz')),candidate)
original=tools/'original';original.mkdir()
release_proof={}
for tool,v in versions.items():
    td=original/tool;td.mkdir();base=f'https://github.com/{"aquasecurity/trivy" if tool=="trivy" else "anchore/grype"}/releases/download/v{v}/'
    checks=f'{tool}_{v}_checksums.txt';cp=fetch(base+checks,td/checks)
    if tool=='trivy':
        bundle=fetch(base+checks+'.sigstore.json',td/(checks+'.sigstore.json'))
        run(['cosign','verify-blob','--bundle',str(bundle),'--certificate-identity',f'https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v{v}','--certificate-oidc-issuer',issuer,str(cp)])
        name=f'trivy_{v}_Linux-ARM64.tar.gz'
    else:
        cert=fetch(base+checks+'.pem',td/(checks+'.pem'));sig=fetch(base+checks+'.sig',td/(checks+'.sig'))
        run(['cosign','verify-blob','--certificate',str(cert),'--signature',str(sig),'--certificate-identity','https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main','--certificate-oidc-issuer',issuer,str(cp)])
        name=f'grype_{v}_linux_arm64.tar.gz'
    archive_tool=fetch(base+name,td/name)
    expected=next(l.split()[0] for l in cp.read_text().splitlines() if l.split()[-1]==name)
    assert sha(archive_tool)==expected;extract(archive_tool,td)
    proofdir=setup/('original-'+tool+'-signature');proofdir.mkdir()
    for proof in td.glob(checks+'*'):shutil.copyfile(proof,proofdir/proof.name)
    release_proof[tool]={'url':base+name,'archive_sha256':expected,'checksums_signature_verified':True}
config={'source':source,'versions':versions,'tools':{},'cache':{'GRYPE_DB_CACHE_DIR':str(work/'cache/grype'),'TRIVY_CACHE_DIR':str(work/'cache/trivy')}}
for variant,folder in [('original',original),('candidate',candidate)]:
    config['tools'][variant]={}
    for tool in versions:
        binary=folder/tool/tool if variant=='original' else folder/tool
        header=binary.read_bytes()[:20];assert header[:4]==b'\x7fELF' and struct.unpack('<H',header[18:20])[0]==183
        if variant=='candidate':assert sha(binary)==json.loads((d/'provenance.json').read_text())['files'][tool]
        binary.chmod(0o755)
        meta=run(['go','version','-m',str(binary)])
        if variant=='candidate':assert 'vcs.revision='+source in meta and 'go.yaml.in/yaml/v3\tv3.0.5' in meta and 'gopkg.in/yaml.' not in meta
        else:assert 'gopkg.in/yaml.v3\tv3.0.1' in meta
        nm=subprocess.run(['go','tool','nm',str(binary)],capture_output=True,text=True)
        symbols=setup/f'{variant}-{tool}-symbols.txt';symbols.write_text(nm.stdout+nm.stderr)
        if variant=='candidate':
            audit=candidate/(tool+'-symbols.txt')
            expected_audit=json.loads((d/'provenance.json').read_text())['files'][tool+'-symbols.txt']
            assert sha(audit)==expected_audit and 'gopkg.in/yaml.' not in audit.read_text()
            assert nm.returncode==0 or 'no symbol' in nm.stderr
        # Upstream release binaries can be stripped; retain that actual boundary.
        row={'sha256':sha(binary),'symbols':{'exit':nm.returncode,'sha256':sha(symbols),'stripped':nm.returncode!=0,'audit_path':str(audit) if variant=='candidate' else None,'signed_audit_sha256':expected_audit if variant=='candidate' else None},'module_metadata':meta,'elf_machine':183}
        version=run([str(binary),'version']);assert versions[tool] in version;row['version']=version
        config['tools'][variant][tool]=row
(setup/'original-release-proof.json').write_text(json.dumps(release_proof,indent=2))
configfile=setup/'identities.json';configfile.write_text(json.dumps(config,indent=2))
os.environ['ARM_IDENTITIES']=str(configfile)
# Reuse only frozen VEX/config/fixture bytes, never label this as the old DB snapshot.
extract(root/'scanner-runtime/qualification/recovery/fresh/frozen-inputs.tar.gz',work)
for name in ['trivy','grype']:(work/'cache'/name).mkdir(parents=True,exist_ok=True)
layer='b9e5bfdb1d0c6e3fb7e40800a4b6a6a9a76b52221402f321f9691ec6ea2db6c5'
trivy_db=fetch('https://mirror.gcr.io/v2/aquasec/trivy-db/blobs/sha256:'+layer,setup/'trivy-db.tar.gz');assert sha(trivy_db)==layer
# Keep retained metadata/config but replace the actual DB from the immutable layer.
with tarfile.open(trivy_db) as t:
    entry=next(m for m in t if Path(m.name).name=='trivy.db')
    with t.extractfile(entry) as src,(work/'cache/trivy/db/trivy.db').open('wb') as dst:shutil.copyfileobj(src,dst)
assert sha(work/'cache/trivy/db/trivy.db')=='c39ee6b7f92119e7fadd7bc626d15ca8de69a56522529eeab027f6c9c433a27a'
url='https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-10-01T00:39:44Z_1790836428.tar.zst'
dbarchive=fetch(url,setup/'grype-db.tar.zst');assert sha(dbarchive)=='c0d0263192d91df04b242e9a91e34cb289118fb08f1ed56eb0239eb57d7a517f'
# Hydrate exactly once on this native host with the verified same-generation original.
from identity import verify
verify(original/'grype/grype','original','grype')
run([str(original/'grype/grype'),'db','import',str(dbarchive)],env={**os.environ,'GRYPE_DB_CACHE_DIR':str(work/'cache/grype'),'GRYPE_DB_AUTO_UPDATE':'false'},timeout=600)
manifest={str(f.resolve()):sha(f) for parent in [work/'cache',work/'home',work/'fixtures'] for f in parent.rglob('*') if f.is_file()}
manifestfile=setup/'frozen-manifest.json';manifestfile.write_text(json.dumps(manifest,indent=2));os.environ['FROZEN_INPUTS_MANIFEST']=str(manifestfile)
(setup/'snapshot.json').write_text(json.dumps({'label':f'NEW-native-arm-{family}-{os.environ["GITHUB_RUN_ID"]}','architecture':platform.machine(),'family':family,'grype_original_version':versions['grype'],'grype_archive_url':url,'grype_archive_sha256':sha(dbarchive),'grype_hydrated_db_sha256':sha(work/'cache/grype/6/vulnerability.db'),'trivy_oci_manifest_digest':'sha256:5fc1889dd7f065881234152a7fa7f27b2c56522306aef0e43bb002d590bdd278','trivy_layer_sha256':layer,'trivy_db_sha256':sha(work/'cache/trivy/db/trivy.db'),'accepted_amd64_snapshot_reused':False,'cross_architecture_equivalence_claimed':False},indent=2))
# Persist complete frozen bytes; future hydration need not reproduce SQLite layout.
with tarfile.open(out/'new-frozen-inputs.tar.gz','w:gz') as t:
    for parent in ['cache','home','fixtures']:t.add(work/parent,arcname=parent)
(setup/'frozen-archive-sha256.txt').write_text(sha(out/'new-frozen-inputs.tar.gz')+'\n')
for kind in ['clean','secret']:
    run(['docker','build','--platform','linux/arm64','-t','runtime-'+kind,str(work/'fixtures'/kind)])
    (setup/(kind+'-image.json')).write_text(run(['docker','image','inspect','runtime-'+kind]))
    assert json.loads((setup/(kind+'-image.json')).read_text())[0]['Architecture']=='arm64'
# Compile only unchanged evaluator, in the established signed BCI builder.
evalroot=setup/'evaluator-source';evalroot.mkdir()
evaluation_commit=json.loads(run(['gh','api','repos/StackVista/image-pipeline/commits/0a1619a8a8ac1235fdbbc3f224bf329cb80903cf']))
assert evaluation_commit['commit']['verification']['verified']
(setup/'evaluator-source-verification.json').write_text(json.dumps(evaluation_commit['commit']['verification'],indent=2))
run(['git','fetch','origin','0a1619a8a8ac1235fdbbc3f224bf329cb80903cf'])
with (setup/'evaluator.tar').open('wb') as f:subprocess.run(['git','archive','0a1619a8a8ac1235fdbbc3f224bf329cb80903cf','evaluator'],stdout=f,check=True)
extract(setup/'evaluator.tar',evalroot)
image='registry.suse.com/bci/golang@sha256:97e1dd2838dba67fff33d75d30ac52b048191d385f8fef4be1e147890302dd51'
assert sha(root/'scanner-runtime/provenance/suse-container-key.pem')=='98b312e62e3e8dce75ae06d2be7277732bee4f7ad275e9de9cd1071d6fcb2329'
run(['cosign','verify','--key',str(root/'scanner-runtime/provenance/suse-container-key.pem'),image])
run(['docker','run','--rm','--user',f'{os.getuid()}:{os.getgid()}','-e','HOME=/tmp','-e','GOTOOLCHAIN=go1.27.0','-v',str(evalroot)+':/src','-w','/src/evaluator',image,'go','build','-o','/src/evaluate','.'],timeout=600)
evaluator=evalroot/'evaluate';config['evaluator_sha256']=sha(evaluator);configfile.write_text(json.dumps(config,indent=2))
# Copy the reviewed generation-specific harness without changing existing receipts.
harness=setup/'harness';harness.mkdir()
orig=root/('scanner-runtime/qualification/recovery' if family=='newer' else 'scanner-runtime/qualification/older/controls')
for name in ['invoke.py','vex.py']:shutil.copyfile(orig/name,harness/name)
shutil.copyfile(Path(__file__).with_name('identity.py'),harness/'identity.py')
text=(orig/('controls.py' if family=='newer' else 'run.py')).read_text().replace('from identity import execute, verify, HEAD','from identity import execute, verify, HEAD, evaluator_command').replace('command=[str(args.evaluator),*arguments]','command=[evaluator_command(args.evaluator),*arguments]')
(harness/'controls.py').write_text(text)
policy=setup/'action.yml'
ref=source if family=='newer' else '5dabd41a1cecfea5f865d844ea7febec4ab4f38b'
run(['git','fetch','origin',ref]);policy.write_text(run(['git','show',ref+':.github/actions/scan-image/action.yml']))
env={**os.environ,'GRYPE_CHECK_FOR_APP_UPDATE':'false'}
control=[str(harness/'controls.py'),'--work',str(work),'--candidate',str(candidate),'--original',str(original),'--evaluator',str(evaluator),'--action',str(policy)]
run(['python3',*control],env=env,timeout=2400)
# Freeze each explicitly-created VEX error fixture before executing its policy.
vtext=(harness/'vex.py').read_text().replace("env = {**os.environ", "fixture_manifest=case/'fixture-manifest.json'\n            fixture_manifest.write_text(json.dumps({str(repo/'repository.yaml'): __import__('hashlib').sha256((repo/'repository.yaml').read_bytes()).hexdigest()}))\n            env = {**os.environ, 'FROZEN_INPUTS_MANIFEST': str(fixture_manifest)")
(harness/'vex.py').write_text(vtext)
run(['python3',str(harness/'vex.py'),'--work',str(work),'--action',str(policy),'--original',str(original),'--candidate',str(candidate),'--family',family],env=env,timeout=600)
from identity import frozen_inputs
frozen_inputs()
(setup/'final-frozen-verification.json').write_text(json.dumps({'all_hashes_match':True,'native_host':platform.machine(),'snapshot':json.loads((setup/'snapshot.json').read_text())},indent=2))
# Retain every same-architecture differing field with both actual values.
def diff(a,b,path=''):
    if a==b:return []
    if type(a)!=type(b):return [{'path':path,'original':a,'candidate':b}]
    if isinstance(a,dict):return [r for k in sorted(set(a)|set(b)) for r in diff(a.get(k),b.get(k),path+'/'+k)]
    if isinstance(a,list):
        rows=[]
        if len(a)!=len(b):rows.append({'path':path+'/length','original':len(a),'candidate':len(b)})
        for i,(x,y) in enumerate(zip(a,b)):rows+=diff(x,y,path+'/'+str(i))
        return rows
    return [{'path':path,'original':a,'candidate':b}]
for case in ['clean','vulnerable','bci']:
    for report in ['trivy.json','grype.json','gate.sarif','inform.sarif']:
        a=json.loads((work/'original'/case/report).read_text());b=json.loads((work/'candidate'/case/report).read_text())
        (work/(case+'-'+report+'-raw-differing-fields.json')).write_text(json.dumps(diff(a,b),indent=2)+'\n')
