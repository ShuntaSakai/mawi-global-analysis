"""BSD packing compatibility: real multi-TU links and exact aguri_flow ABI."""
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest
from mawi_global_analysis.agurim_prime.input import RECORD
from mawi_global_analysis.aguri_two_stage.wire import read_wire

ROOT=Path(__file__).resolve().parents[1]
def gnu_compiler():
    for name in ('gcc-15','gcc'):
        path=shutil.which(name)
        if path and 'Free Software Foundation' in subprocess.check_output([path,'--version'],text=True):return path
    return None
GNU=gnu_compiler()
COMPILERS=[shutil.which('cc')]+([GNU] if GNU and GNU!=shutil.which('cc') else [])

def builder_module():
    path=ROOT/'scripts/build_agurim_two_stage.py';spec=importlib.util.spec_from_file_location('packing_builder',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

@pytest.fixture(scope='module')
def packed_fork(tmp_path_factory):
    # Do not compile unpatched upstream: its missing macro is the bug under test.
    return builder_module().build(tmp_path_factory.mktemp('packing-c')/'fork',ROOT).parent


def test_missing_bsd_packing_macro_does_not_emit_a_global_symbol(packed_fork,tmp_path):
    fork=packed_fork
    header='#include <sys/types.h>\n#include <sys/param.h>\n#undef __packed\n#include "aguri_flow.h"\n'
    (tmp_path/'one.c').write_text(header+'int packed_alignment(void) { return _Alignof(struct flow_spec); }\n')
    (tmp_path/'two.c').write_text(header+'int packed_alignment(void); int main(void) { return packed_alignment()!=1 || sizeof(struct aguri_flow)!=56; }\n')
    target=tmp_path/'linked'
    result=subprocess.run(['cc','-fno-common','-I',str(fork/'src'),str(tmp_path/'one.c'),str(tmp_path/'two.c'),'-o',str(target)],capture_output=True)
    assert result.returncode==0,result.stderr.decode()
    assert subprocess.run([str(target)]).returncode==0
    symbols=subprocess.check_output(['nm',str(target)],text=True)
    assert not any(line.split()[-1] in ('__packed','___packed') for line in symbols.splitlines() if line.split())


@pytest.mark.parametrize('compiler',COMPILERS)
@pytest.mark.parametrize('undefine',[False,True],ids=['predefined-packed','missing-bsd-macro'])
def test_c_layout_and_network_bytes_match_canonical_converter(packed_fork,tmp_path,compiler,undefine):
    fork=packed_fork
    code='''#include <sys/types.h>
#include <sys/param.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
UNDEFINE
#include "aguri_flow.h"
int main(void) {
    struct aguri_flow f = {0};
    f.agflow_fs.fs_srcaddr[0]=htonl(0xc0000201U);
    f.agflow_fs.fs_dstaddr[0]=htonl(0xc6336402U);
    f.agflow_fs.fs_sport=htons(12345); f.agflow_fs.fs_dport=htons(443);
    f.agflow_fs.fs_ipver=4; f.agflow_fs.fs_prot=6;
    f.agflow_packets=htonl(0x01020304U); f.agflow_bytes=htonl(0x10203040U);
    f.agflow_first=htonl(1700000000U); f.agflow_last=htonl(1700000005U);
    fprintf(stderr,"%zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\\n",
        sizeof(struct flow_spec),_Alignof(struct flow_spec),sizeof(struct aguri_flow),
        offsetof(struct flow_spec,fs_srcaddr),offsetof(struct flow_spec,fs_dstaddr),
        offsetof(struct flow_spec,fs_sport),offsetof(struct flow_spec,fs_dport),
        offsetof(struct flow_spec,fs_ipver),offsetof(struct flow_spec,fs_prot),offsetof(struct flow_spec,fs_pad),
        offsetof(struct aguri_flow,agflow_packets),offsetof(struct aguri_flow,agflow_bytes),
        offsetof(struct aguri_flow,agflow_first),offsetof(struct aguri_flow,agflow_last));
    return fwrite(&f,1,sizeof(f),stdout)!=sizeof(f);
}
'''.replace('UNDEFINE','#undef __packed' if undefine else '#undef __packed\n#define __packed __attribute__((packed))')
    source=tmp_path/'layout.c';source.write_text(code);target=tmp_path/'layout'
    result=subprocess.run([compiler,'-fno-common','-I',str(fork/'src'),str(source),'-o',str(target)],capture_output=True)
    assert result.returncode==0,result.stderr.decode()
    result=subprocess.run([str(target)],capture_output=True)
    assert result.returncode==0
    assert list(map(int,result.stderr.split()))==[40,1,56,0,16,32,34,36,37,38,40,44,48,52]
    expected=RECORD.pack(bytes.fromhex('c0000201')+b'\0'*12,bytes.fromhex('c6336402')+b'\0'*12,12345,443,4,6,0,
                         0x01020304,0x10203040,1700000000,1700000005)
    assert len(result.stdout)==56 and result.stdout==expected


@pytest.mark.skipif(GNU is None,reason='GNU GCC not installed')
def test_gcc_build_and_two_stage_execution_without_bsd_packing_macro(tmp_path,monkeypatch):
    # Preload sys/param.h then remove its BSD macro, modelling Linux headers.
    # No production source or user build is changed to simulate this condition.
    compat=tmp_path/'missing-bsd.h';compat.write_text('#include <sys/param.h>\n#undef __packed\n')
    monkeypatch.setenv('CC',shlex.join([GNU,'-fno-common','-include',str(compat)]))
    try:manifest=builder_module().build(tmp_path/'fork',ROOT)
    except subprocess.CalledProcessError as error:pytest.fail(error.stderr.decode(errors='replace'))
    build=json.loads(manifest.read_text())
    assert 'gcc' in build['compiler'].lower()
    data=RECORD.pack(bytes.fromhex('c0000201')+b'\0'*12,bytes.fromhex('c6336402')+b'\0'*12,12345,443,4,6,0,100,6000,1700000000,1700000001)
    first=subprocess.run([str(manifest.parent/'aguri3'),'-W','-m','flow'],input=data,capture_output=True)
    assert first.returncode==0,first.stderr.decode()
    second=subprocess.run([str(manifest.parent/'agurim'),'-W','-m','flow'],input=first.stdout,capture_output=True)
    assert second.returncode==0,second.stderr.decode()
    for name,result in [('stage1',first),('stage2',second)]:
        wire=tmp_path/(name+'.agw');wire.write_bytes(result.stdout)
        assert read_wire(wire)['totals']=={'packet':100,'byte':6000,'flow':1}
