"""Always retain actual partial/complete raw controls and independently hashed inputs."""
import argparse,hashlib,json,tarfile,shutil
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();o=a.output
if not o.exists():raise SystemExit('no actual evidence directory exists')
reports=o/'reports'
if reports.exists():
    entries={}
    with tarfile.open(o/'raw-reports.tar.gz','w:gz') as t:
        for f in sorted(reports.rglob('*')):
            relative=f.relative_to(reports)
            if relative.parts[0] in ['cache','home','fixtures']:continue
            if f.is_file() and not f.is_symlink():
                t.add(f,arcname=str(relative),recursive=False)
                entries[str(relative)]=hashlib.sha256(f.read_bytes()).hexdigest()
    (o/'raw-report-file-sha256.json').write_text(json.dumps(entries,indent=2)+'\n')
    # Exact immutable inputs live in the separate frozen archive, never substitute
    # a raw-report archive's runtime caches for its recorded snapshot.
setup=o/'setup'
if setup.exists():
    # Keep signed ARM manifests; original binary archives remain checksum-addressed.
    signed=setup/'signed'
    if signed.exists():
        for d in signed.iterdir():
            if d.is_dir() and d.name.endswith('arm64'):
                dest=setup/'source-signatures';dest.mkdir(exist_ok=True)
                for name in ['SHA256SUMS','SHA256SUMS.sigstore.json','provenance.json','provenance.json.sigstore.json']:shutil.copyfile(d/name,dest/name)
        shutil.rmtree(signed)
    for pattern in ['*.zip','*.tar.gz','*.tar.zst','*.tar']:
        for f in setup.glob(pattern):f.unlink()
manifest={}
for f in sorted(o.rglob('*')):
    if f.is_file() and (f.parent==o or setup in f.parents):
        with f.open('rb') as src:manifest[str(f.relative_to(o))]=hashlib.file_digest(src,'sha256').hexdigest()
(o/'evidence-sha256.json').write_text(json.dumps(manifest,indent=2)+'\n')
