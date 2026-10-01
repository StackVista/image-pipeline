"""Guard each CLI invocation made by the unchanged action policy block."""
import json,os,sys
from pathlib import Path
from identity import execute
rows=[]
r=execute(os.environ['QUALIFIED_BINARY'],os.environ['QUALIFIED_VARIANT'],'trivy',sys.argv[1:],rows)
with Path(os.environ['QUALIFIED_LOG']).open('a') as out:out.write(json.dumps(rows[0])+'\n')
sys.exit(r.returncode)
