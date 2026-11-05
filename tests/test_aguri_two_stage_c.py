"""Compiled two-stage controls; synthetic inputs are not MAWI evidence."""
import importlib.util
from pathlib import Path
import re
import subprocess
import pytest
from test_agurim_prime_fork import record, ROOT, PIN, SOURCES

@pytest.fixture(scope='module')
def compiled_two(tmp_path_factory):
    path=ROOT/'scripts/build_agurim_two_stage.py'
    assert path.is_file(), 'two-stage builder not implemented'
    spec=importlib.util.spec_from_file_location('two_builder',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    work=tmp_path_factory.mktemp('two-stage-c');manifest=module.build(work/'fork',ROOT)
    original=work/'original';original.mkdir()
    inputs=(*SOURCES,'aguri3.c','pcap_parse.c','ip_parse.c','ip_parse.h','agurim.h','aguri_flow.h')
    for name in inputs:(original/name).write_bytes(subprocess.check_output(['git','-C',str(ROOT/'vendor/agurim'),'show',f'{PIN}:src/{name}']))
    for program,names,libs in [('agurim',SOURCES,['-lm']),('aguri3',('aguri3.c','pcap_parse.c','ip_parse.c',*SOURCES[1:]),['-lpcap','-lpthread','-lm'])]:
        subprocess.run(['cc','-O2','-DINET6','-DNDEBUG','-o',str(original/program),*(str(original/n) for n in names),*libs],check=True,capture_output=True)
    return manifest.parent, original

def run(binary,data,*options):return subprocess.run([str(binary),*options],input=data,capture_output=True)
def stable(data):return re.sub(rb'%aggregated in [^\n]*',b'%aggregated in <time>',data)

@pytest.mark.parametrize('mode',['packet','byte','combination'])
def test_both_legacy_stages_match_pinned_upstream(compiled_two,mode):
    fork,old=compiled_two
    data=b''.join(record(src=f'192.0.2.{i}',port=10000+i,packets=i+1,byte_count=63*(i+1)) for i in range(1,61))
    args=[] if mode=='combination' else ['-m',mode]
    first=[run(p/'aguri3',data,*args,'-t','1') for p in [fork,old]]
    assert all(r.returncode==0 for r in first),[r.stderr for r in first]
    assert stable(first[0].stdout)==stable(first[1].stdout)
    second=[run(p/'agurim',first[j].stdout,*args,'-t','1','-n','0') for j,p in enumerate([fork,old])]
    assert all(r.returncode==0 for r in second)
    assert stable(second[0].stdout)==stable(second[1].stdout)

def inspect(data,tmp_path,name='wire',**expected):
    from mawi_global_analysis.aguri_two_stage.wire import read_wire
    path=tmp_path/name;path.write_bytes(data);rows=[]
    audit=read_wire(path,expected=expected,on_address=rows.append)
    return audit,rows

@pytest.mark.parametrize('mode',['packet','byte','flow','combination'])
def test_weighted_two_stage_preserves_all_counters_and_has_real_first_stage(compiled_two,tmp_path,mode):
    fork,_=compiled_two
    data=b''.join(record(src=f'192.0.2.{1+i%3}',port=10000+i,packets=i+1,byte_count=73*(i+1)) for i in range(100))
    first=run(fork/'aguri3',data,'-W','-m',mode,'-t','20')
    assert first.returncode==0,first.stderr.decode()
    a,rows=inspect(first.stdout,tmp_path,mode,mode=mode,stage=1)
    assert a['totals']=={'packet':5050,'byte':368650,'flow':100}
    assert any(r['flows']>1 for r in rows)
    second=run(fork/'agurim',first.stdout,'-W','-m',mode,'-t','20','-n','0')
    assert second.returncode==0,second.stderr.decode()
    b,_=inspect(second.stdout,tmp_path,'second-'+mode,mode=mode,stage=2)
    assert b['totals']==a['totals']


def test_hash_driven_blocks_and_eof_are_fully_drained(compiled_two,tmp_path):
    fork,_=compiled_two
    data=b''.join(record(src=f'192.0.2.{1+i%200}',port=10000+i,packets=1) for i in range(451))
    outputs=[run(fork/'aguri3',data,'-W','-m','flow','-H','10') for _ in range(2)]
    assert all(r.returncode==0 for r in outputs),[r.stderr for r in outputs]
    assert outputs[0].stdout==outputs[1].stdout
    a,_=inspect(outputs[0].stdout,tmp_path)
    assert a['blocks']>2 and a['totals']['flow']==451

@pytest.mark.parametrize('damage',['truncate','trailing','old_format','mode'])
def test_second_stage_rejects_invalid_intermediate(compiled_two,damage):
    fork,_=compiled_two;first=run(fork/'aguri3',record(),'-W','-m','flow')
    assert first.returncode==0,first.stderr.decode()
    data=first.stdout;mode='flow'
    if damage=='truncate':data=data[:-1]
    if damage=='trailing':data+=b'garbage'
    if damage=='old_format':data=b'%!AGURI-2.0\n'
    if damage=='mode':mode='packet'
    second=run(fork/'agurim',data,'-W','-m',mode)
    assert second.returncode!=0

@pytest.mark.parametrize('program',['aguri3','agurim'])
def test_empty_versioned_stream_is_explicit_and_complete(compiled_two,tmp_path,program):
    fork,_=compiled_two
    first=run(fork/'aguri3',b'','-W','-m','flow')
    result=first if program=='aguri3' else run(fork/'agurim',first.stdout,'-W','-m','flow')
    assert result.returncode==0,result.stderr.decode()
    a,rows=inspect(result.stdout,tmp_path)
    assert a['totals']=={'packet':0,'byte':0,'flow':0} and rows==[]


def test_protocol_deficit_is_audit_only_without_synthetic_wildcard(compiled_two,tmp_path):
    fork,_=compiled_two
    data=b''.join(record(port=10000+i,packets=1,protocol=6 if i<90 else 17) for i in range(100))
    first=run(fork/'aguri3',data,'-W','-m','flow','-t','10')
    a,rows=inspect(first.stdout,tmp_path)
    assert a['protocol_unattributed']['flow']==10 and a['fallback_records']==0
    assert rows[0]['flows']==100 and rows[0]['protocol_unattributed']['flow']==10
    second=run(fork/'agurim',first.stdout,'-W','-m','flow','-t','10')
    b,_=inspect(second.stdout,tmp_path,'second')
    assert b['totals']['flow']==100 and b['protocol_unattributed']['flow']==10 and b['fallback_records']==0


def test_two_stage_is_not_direct_rls_called_twice(compiled_two,tmp_path):
    import random,csv,io
    fork,old=compiled_two;rng=random.Random(93)
    data=b''.join(record(src=f'192.0.{rng.randrange(3)}.{rng.randrange(1,100)}',dst=f'198.51.100.{rng.randrange(1,25)}',port=10000+i,packets=rng.randrange(1,200)) for i in range(301))
    one=run(fork/'aguri3',data,'-W','-m','packet','-t','10','-H','10')
    two=run(fork/'agurim',one.stdout,'-W','-m','packet','-t','10')
    assert one.returncode==two.returncode==0
    _,rows=inspect(two.stdout,tmp_path)
    direct=run(old/'agurim',data,'-F','-m','packet','-t','10','-n','0')
    from mawi_global_analysis.agurim_prime.stage import _parse_control
    direct_rows=_parse_control(direct.stdout.decode())
    normalize=lambda s:'0.0.0.0/0' if s=='*' else s if '/' in s else s+'/32'
    assert {(r['src_prefix'],r['dst_prefix'],r['packets']) for r in rows}!={(normalize(r.src_prefix),normalize(r.dst_prefix),int(r.discounted_packets)) for r in direct_rows.itertuples()}

@pytest.mark.parametrize('extra',[('-t','1.5'),('-t','0'),('-i','1'),('-H','0'),('-m','flowjunk'),('-D','-D','-D'),('-f','ip'),('-W',)])
def test_versioned_aguri3_rejects_noncontract_options(compiled_two,extra):
    fork,_=compiled_two
    assert run(fork/'aguri3',record(),'-W','-m','flow',*extra).returncode!=0


def test_new_weighted_input_rejects_partial_and_out_of_scope_records(compiled_two):
    fork,_=compiled_two
    for data in [record()+b'x',record(ipv=6,src='2001:db8::1',dst='2001:db8::2'),record(protocol=1),record(packets=0)]:
        assert run(fork/'aguri3',data,'-W','-m','packet').returncode!=0


def test_new_format_is_rejected_by_fork_legacy_reader(compiled_two):
    fork,_=compiled_two;first=run(fork/'aguri3',record(),'-W','-m','packet')
    assert first.returncode==0
    assert run(fork/'agurim',first.stdout,'-m','packet').returncode!=0


def test_legacy_quickmerge_and_multiblock_controls_match(compiled_two):
    fork,old=compiled_two
    data=b''.join(record(port=10000+i,packets=i%7+1) for i in range(1101))
    for mode in ('packet','byte','combination'):
        args=[] if mode=='combination' else ['-m',mode]
        first=[run(p/'aguri3',data,*args) for p in [fork,old]]
        assert all(r.returncode==0 for r in first)
        assert stable(first[0].stdout)==stable(first[1].stdout)
        second=[run(p/'agurim',first[i].stdout,*args) for i,p in enumerate([fork,old])]
        assert stable(second[0].stdout)==stable(second[1].stdout)
    data=b''.join(record(src=f'192.0.2.{i%200+1}',port=10000+i) for i in range(73))
    first=[run(p/'aguri3',data,'-m','packet','-H','10') for p in [fork,old]]
    # Legacy producer/consumer scheduling changes block boundaries at tiny H.
    # Preserve that old path; compare totals rather than claim bitwise equality.
    from mawi_global_analysis.agurim_prime.stage import _parse_control
    for r in first:
        assert r.returncode==0
        assert sum(int(n) for n in _parse_control(r.stdout.decode()).discounted_packets)==7300


def test_flow_parent_residual_remains_twenty_after_both_stages(compiled_two,tmp_path):
    fork,_=compiled_two
    data=b''.join(record(src='192.0.2.1' if i<80 else '192.0.2.2' if i<90 else '192.0.2.4',port=10000+i,packets=1) for i in range(100))
    first=run(fork/'aguri3',data,'-W','-m','flow','-t','20')
    second=run(fork/'agurim',first.stdout,'-W','-m','flow','-t','20')
    for name,r in [('first',first),('second',second)]:
        assert r.returncode==0,r.stderr.decode()
        audit,rows=inspect(r.stdout,tmp_path,name)
        assert audit['totals']['flow']==100
        assert next(x['flows'] for x in rows if x['src_prefix']=='192.0.2.0/29')==20


def test_basis_separates_packet_byte_and_flow_heavy_hosts(compiled_two,tmp_path):
    fork,_=compiled_two
    data=record(src='192.0.2.1',port=10000,packets=10000,byte_count=10000)
    data+=record(src='203.0.113.1',port=10001,packets=10,byte_count=1000000)
    data+=b''.join(record(src='172.16.0.1',port=11000+i,packets=1,byte_count=64) for i in range(100))
    expected={'packet':'192.0.2.1/32','byte':'203.0.113.1/32','flow':'172.16.0.1/32'}
    for mode,host in expected.items():
        first=run(fork/'aguri3',data,'-W','-m',mode,'-t','20')
        second=run(fork/'agurim',first.stdout,'-W','-m',mode,'-t','20')
        assert first.returncode==second.returncode==0
        _,rows=inspect(second.stdout,tmp_path,mode)
        selected={r['src_prefix'] for r in rows}
        assert host in selected and not (set(expected.values())-{host})&selected


def test_stage2_rejects_threshold_overflow(compiled_two):
    import struct
    from mawi_global_analysis.aguri_two_stage.wire import HEADER,BLOCK,ADDRESS,PROTOCOL
    fork,_=compiled_two;v=(1,1,2**64-1);zero=b'\0'*16
    data=HEADER.pack(b'AGWGT001',4,100,0,1,1000000,0)+b'BLK1'+BLOCK.pack(0,1,2,*v,1,1)
    data+=ADDRESS.pack(zero,zero,0,0,*v,1,0,0,0)+PROTOCOL.pack(zero,zero,0,0,*v)
    data+=b'SUM1'+struct.pack('!5Q',*v,1,1)+b'END1'+struct.pack('!4Q',1,*v)
    result=run(fork/'agurim',data,'-W','-m','flow','-t','100')
    assert result.returncode!=0 and b'overflow' in result.stderr


def join_single_blocks(streams,tmp_path):
    import struct
    from mawi_global_analysis.aguri_two_stage.wire import HEADER
    totals=[0,0,0];out=streams[0][:HEADER.size]
    for i,data in enumerate(streams):
        audit,_=inspect(data,tmp_path,'join-'+str(i));assert audit['blocks']==1
        totals=[a+audit['totals'][k] for a,k in zip(totals,('packet','byte','flow'))]
        block=data[HEADER.size:-36];assert block[:4]==b'BLK1'
        out+=block[:4]+struct.pack('!Q',i)+block[12:]
    return out+b'END1'+struct.pack('!4Q',len(streams),*totals)


def test_repeated_parent_blocks_keep_deficit_out_of_candidate_lookup(compiled_two,tmp_path):
    from mawi_global_analysis.aguri_two_stage.wire import HEADER,BLOCK,ADDRESS,PROTOCOL
    fork,_=compiled_two
    first=b''.join(record(port=10000+i,packets=1,protocol=6 if i<90 else 17) for i in range(100))
    second=b''.join(record(port=11000+i,packets=1,protocol=17) for i in range(100))
    streams=[run(fork/'aguri3',d,'-W','-m','flow','-t','10').stdout for d in (first,second)]
    combined=join_single_blocks(streams,tmp_path);r=run(fork/'agurim',combined,'-W','-m','flow','-t','10')
    assert r.returncode==0,r.stderr.decode()
    audit,rows=inspect(r.stdout,tmp_path,'joined-output')
    assert audit['totals']['flow']==200 and audit['protocol_unattributed']['flow']==10
    assert audit['protocol_records']==2 and audit['fallback_records']==0
    offset=HEADER.size+4+BLOCK.size+ADDRESS.size
    children=[PROTOCOL.unpack_from(r.stdout,offset+i*PROTOCOL.size) for i in range(2)]
    assert {x[0][0]:x[-1] for x in children}=={6:90,17:100}


def test_old_fallback_still_absorbs_later_labeled_protocol_in_repeated_parent(compiled_two,tmp_path):
    fork,old=compiled_two
    first=b''.join(record(port=10000+i,packets=1,protocol=6 if i<50 else 17) for i in range(100))
    second=b''.join(record(port=11000+i,packets=1,protocol=6) for i in range(100))
    streams=[run(fork/'aguri3',d,'-W','-m','packet','-t','20').stdout for d in (first,second)]
    a,_=inspect(streams[0],tmp_path,'fallback-input');assert a['fallback_records']==1
    r=run(fork/'agurim',join_single_blocks(streams,tmp_path),'-W','-m','packet','-t','20')
    assert r.returncode==0
    a,_=inspect(r.stdout,tmp_path,'fallback-output')
    assert a['totals']['flow']==200 and a['protocol_records']==a['fallback_records']==1
    agr=b''.join(run(old/'aguri3',d,'-m','packet','-t','20').stdout for d in (first,second))
    legacy=run(old/'agurim',agr,'-m','packet','-t','20')
    assert legacy.returncode==0 and b'[*:*:*] 100.00% 100.00%' in legacy.stdout


def test_exact_wire_preserves_protocol_counts_lost_by_old_percent_roundtrip(compiled_two,tmp_path):
    import re,math
    from mawi_global_analysis.aguri_two_stage.wire import HEADER,BLOCK,ADDRESS,PROTOCOL
    fork,old=compiled_two
    data=b''.join(record(port=port,packets=n) for port,n in [(10000,33333),(20000,33333),(30000,33334)])
    exact=run(fork/'aguri3',data,'-W','-m','packet')
    legacy=run(old/'aguri3',data,'-m','packet')
    assert exact.returncode==legacy.returncode==0
    audit,rows=inspect(exact.stdout,tmp_path);assert len(rows)==1 and audit['protocol_records']==3
    offset=HEADER.size+4+BLOCK.size+ADDRESS.size
    children=[PROTOCOL.unpack_from(exact.stdout,offset+i*PROTOCOL.size) for i in range(3)]
    assert sorted(r[-3] for r in children)==[33333,33333,33334]
    fractions=[float(x) for line in legacy.stdout.decode().splitlines() if line.startswith('\t') for x in re.findall(r'\]\s+[0-9.]+%\s+([0-9.]+)%',line)]
    reconstructed=sorted(int(x*100000/100) for x in fractions)
    assert reconstructed!=[33333,33333,33334]


def test_fork_source_makefile_can_build_both_stages(compiled_two,tmp_path):
    import shutil
    fork,_=compiled_two;source=tmp_path/'buildable-source';shutil.copytree(fork/'src',source)
    result=subprocess.run(['make','-C',str(source)],capture_output=True)
    assert result.returncode==0,result.stderr.decode()
    assert (source/'aguri3').is_file() and (source/'agurim').is_file()
