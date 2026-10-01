"""Native ARM-only identity and immutable, isolated input guards."""
import hashlib,json,os,platform,shutil,struct,subprocess,tempfile
from pathlib import Path
CONFIG=json.loads(Path(os.environ['ARM_IDENTITIES']).read_text())
HEAD=CONFIG['source']
def digest(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def verify(path,variant,tool):
    assert platform.machine() in ('aarch64','arm64'), 'native ARM host required'
    p=Path(path).resolve(strict=True);row=CONFIG['tools'][variant][tool]
    assert digest(p)==row['sha256'] and os.access(p,os.X_OK)
    with p.open('rb') as f:header=f.read(20)
    assert header[:4]==b'\x7fELF' and struct.unpack('<H',header[18:20])[0]==183
    meta=subprocess.check_output(['go','version','-m',str(p)],text=True)
    if variant=='candidate':
        assert 'vcs.revision='+HEAD in meta and 'vcs.modified=false' in meta
        assert 'go.yaml.in/yaml/v3\tv3.0.5' in meta and 'gopkg.in/yaml.' not in meta
    else:assert 'gopkg.in/yaml.v3\tv3.0.1' in meta
    if variant=='candidate':assert digest(row['symbols']['audit_path'])==row['symbols']['signed_audit_sha256']
    version=subprocess.check_output([str(p),'version'],text=True)
    assert CONFIG['versions'][tool] in version
    return {'path':str(p),'sha256':row['sha256'],'host':platform.machine(),'elf_machine':183,'mode':oct(p.stat().st_mode & 0o777),'version':version,'build_metadata':meta,'symbols':row['symbols']}
def frozen_inputs():
    p=Path(os.environ['FROZEN_INPUTS_MANIFEST']);rows=json.loads(p.read_text())
    for f,h in rows.items():assert digest(f)==h, 'frozen input changed: '+f
    return digest(p)
def evaluator_command(path):
    p=Path(path).resolve(strict=True);assert digest(p)==CONFIG['evaluator_sha256']
    assert platform.machine() in ('aarch64','arm64') and os.access(p,os.X_OK)
    with p.open('rb') as f:h=f.read(20)
    assert h[:4]==b'\x7fELF' and struct.unpack('<H',h[18:20])[0]==183
    meta=subprocess.check_output(['go','version','-m',str(p)],text=True)
    assert 'go.yaml.in/yaml/v3\tv3.0.5' in meta and 'gopkg.in/yaml.' not in meta
    return str(p)
def execute(path,variant,tool,arguments,evidence,**kwargs):
    before=frozen_inputs();identity=verify(path,variant,tool)
    env=dict(kwargs.get('env',os.environ));clones={}
    with tempfile.TemporaryDirectory(prefix='arm-invocation-') as tmp:
        for key in ['GRYPE_DB_CACHE_DIR','TRIVY_CACHE_DIR']:
            src=Path(env.get(key,'/nonexistent'))
            # Absent DB and VEX-error caches are deliberate error controls.
            if src.exists() and src.resolve()==Path(CONFIG['cache'][key]).resolve():
                dest=Path(tmp)/key;subprocess.run(['cp','-a','--reflink=auto',str(src),str(dest)],check=True)
                for f in dest.rglob('*'):
                    if f.is_file():clones[str(f)]=digest(f)
                env[key]=str(dest)
        kwargs['env']=env
        r=subprocess.run([identity['path'],*arguments],**kwargs)
        for f,h in clones.items():assert digest(f)==h,'invocation input mutated: '+f
        after=frozen_inputs();assert before==after
        evidence.append({'identity':identity,'arguments':arguments,'exit':r.returncode,'frozen_input_manifest_sha256':before,'isolated_cache_file_sha256':clones,'frozen_inputs_unchanged_before_after':True})
        return r
