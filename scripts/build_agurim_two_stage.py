#!/usr/bin/env python3
"""Build a pinned Aguri3/Agurim fork with an ordered, hash-bound patch chain."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

UPSTREAM='ab5c5cc80e9e1229bb66ec83bb25f186898d5e49'
INPUTS=('agurim.c','aguri3.c','odflow.c','hhh.c','agurim_plot.c','agurim_subr.c','agurim.h','aguri_flow.h','pcap_parse.c','ip_parse.c','ip_parse.h','Makefile')
COMMON=('odflow.c','hhh.c','agurim_plot.c','agurim_subr.c')
PATCHES=('vendor/agurim-prime/flow-mode.patch','vendor/agurim-two-stage/two-stage.patch')
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def stable(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def build(output: Path,root: Path|None=None)->Path:
    root=Path(root or Path(__file__).resolve().parents[1]).resolve();output=Path(output).expanduser()
    if output.is_symlink() or output.exists():raise FileExistsError(output)
    output=output.resolve()
    if output.is_relative_to(root/'vendor'):raise ValueError('build cannot modify vendor')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.aguri-two-stage-',dir=output.parent) as tmp:
        work=Path(tmp);source=work/'src';source.mkdir()
        for n in INPUTS:(source/n).write_bytes(subprocess.check_output(['git','-C',str(root/'vendor/agurim'),'show',f'{UPSTREAM}:src/{n}']))
        (work/'LICENSE').write_bytes(subprocess.check_output(['git','-C',str(root/'vendor/agurim'),'show',f'{UPSTREAM}:LICENSE']))
        chain=[]
        for name in PATCHES:
            chain.append({'path':name,'sha256':digest(root/name)})
            subprocess.run(['patch','--batch','-p1','-i',str(root/name)],cwd=work,check=True,capture_output=True)
        cc=shlex.split(os.environ.get('CC','cc'));commands={}
        extra=('weights.c',)
        for program,names,libs in [('agurim',('agurim.c',*COMMON,*extra),['-lm']),('aguri3',('aguri3.c','pcap_parse.c','ip_parse.c',*COMMON,*extra),['-lpcap','-lpthread','-lm'])]:
            argv=[*cc,'-O2','-Wall','-DINET6','-DNDEBUG','-o',str(work/program),*(str(source/n) for n in names),*libs]
            subprocess.run(argv,check=True,capture_output=True);commands[program]=argv
        identity={'upstream_commit':UPSTREAM,'patches':chain}
        manifest={'schema_version':'aguri-two-stage-build-v1','status':'success',**identity,'fork_identity':stable(identity),'fork_commit':None,
            'source_sha256':{p.name:digest(p) for p in sorted(source.iterdir()) if p.is_file()},
            'executable_sha256':{n:digest(work/n) for n in ('aguri3','agurim')},
            'compiler':subprocess.check_output([*cc,'--version'],text=True).splitlines()[0],'compiler_argv':commands,'license':'LICENSE'}
        (work/'build_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
        output.mkdir();published=[]
        try:
            for folder in ['src']:(output/folder).mkdir()
            files=sorted(p for p in work.rglob('*') if p.is_file() and p.name!='build_manifest.json')+[work/'build_manifest.json']
            for p in files:
                target=output/p.relative_to(work);os.link(p,target);published.append(target)
        except BaseException:
            for p in reversed(published):p.unlink()
            (output/'src').rmdir();output.rmdir();raise
    return output/'build_manifest.json'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
    try:print(build(a.output_dir))
    except (ValueError,OSError,subprocess.CalledProcessError) as e:p.exit(2,f'Build failed: {e}\n')
if __name__=='__main__':main()
