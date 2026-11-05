"""Bounded-memory verification of AGWGT001 residual frames, never histogram data."""
from __future__ import annotations
import ipaddress
from pathlib import Path
import struct

MAGIC=b'AGWGT001'
HEADER=struct.Struct('!8s6I')
BLOCK=struct.Struct('!8Q')
ADDRESS=struct.Struct('!16s16sBB3QI3Q')
PROTOCOL=struct.Struct('!16s16sBB3Q')
COUNTS=struct.Struct('!3Q')
MODES={1:'packet',2:'byte',3:'combination',4:'flow'}
UINT64=2**64-1

def _get(stream,spec):
    data=stream.read(spec.size)
    if len(data)!=spec.size:raise ValueError('wire: truncated record/frame')
    return spec.unpack(data)
def _sum(a,b):
    result=tuple(x+y for x,y in zip(a,b))
    if any(n>UINT64 for n in result):raise ValueError('wire: counter overflow')
    return result
def _spec(src,dst,sl,dl,bits):
    for value,length in [(src,sl),(dst,dl)]:
        if length>bits:raise ValueError('wire: invalid prefix length')
        number=int.from_bytes(value,'big');mask=((1<<length)-1)<<(128-length) if length else 0
        if number&mask!=number:raise ValueError('wire: noncanonical label bits')
    if bits==32:return str(ipaddress.ip_network((int.from_bytes(src[:4],'big'),sl))),str(ipaddress.ip_network((int.from_bytes(dst[:4],'big'),dl)))

def read_wire(path: Path,*,expected: dict|None=None,on_address=None) -> dict:
    """Stream and verify all counters; callback receives one address at a time.

    Protocol deficits are metadata, not synthesized wildcard candidates. Genuine
    old no-label fallback is a real zero-label protocol record with full weight.
    """
    with Path(path).open('rb') as stream:
        magic,basis,t,h,stage,limit,reserved=_get(stream,HEADER)
        if magic!=MAGIC or basis not in MODES or stage not in (1,2) or not 1<=t<=100 or h>2 or not 1<=limit<=2**31-1 or reserved:
            raise ValueError('wire: invalid magic/version/settings')
        settings=dict(mode=MODES[basis],threshold=t,heuristics=h,stage=stage,max_hashentries=limit)
        for key,value in (expected or {}).items():
            if settings.get(key)!=value:raise ValueError(f'wire.{key}: {settings.get(key)!r} != {value!r}')
        seq=0;totals=(0,0,0);unattributed=(0,0,0);address_count=protocol_count=0;fallback_count=0
        while True:
            frame=stream.read(4)
            if frame==b'END1':
                n,=_get(stream,struct.Struct('!Q'));v=_get(stream,COUNTS)
                if n!=seq or v!=totals or stream.read(1):raise ValueError('wire: footer totals/sequence/trailing data mismatch')
                break
            if frame!=b'BLK1':raise ValueError('wire: missing/invalid block frame')
            number,start,end,p,b,f,na,np=_get(stream,BLOCK)
            if number!=seq or not 0<=start<=end<=2**32-1:raise ValueError('wire: invalid block sequence/timestamps')
            seq+=1;block_sum=(0,0,0);actual_np=0
            for _ in range(na):
                src,dst,sl,dl,p1,b1,f1,n,up,ub,uf=_get(stream,ADDRESS)
                prefixes=_spec(src,dst,sl,dl,32);lower=(0,0,0)
                if n<1:raise ValueError('wire: missing protocol record/fallback')
                for _ in range(n):
                    ss,dd,ssl,ddl,pp,bb,ff=_get(stream,PROTOCOL);_spec(ss,dd,ssl,ddl,24)
                    lower=_sum(lower,(pp,bb,ff));actual_np+=1
                    if ssl==ddl==0:fallback_count+=1
                if _sum(lower,(up,ub,uf))!=(p1,b1,f1):raise ValueError('wire: protocol residual conservation mismatch')
                block_sum=_sum(block_sum,(p1,b1,f1));unattributed=_sum(unattributed,(up,ub,uf))
                if on_address:on_address(dict(src_prefix=prefixes[0],dst_prefix=prefixes[1],packets=p1,bytes=b1,flows=f1,
                    protocol_records=n,protocol_unattributed=dict(packet=up,byte=ub,flow=uf),block=number))
            if block_sum!=(p,b,f) or actual_np!=np:raise ValueError('wire: block counter/count mismatch')
            if stream.read(4)!=b'SUM1' or _get(stream,COUNTS)!=block_sum or _get(stream,struct.Struct('!2Q'))!=(na,np):raise ValueError('wire: block trailer mismatch')
            totals=_sum(totals,block_sum);address_count+=na;protocol_count+=np
    return dict(schema_version='aguri-weight-wire-v1',**settings,blocks=seq,totals=dict(zip(('packet','byte','flow'),totals)),
        address_records=address_count,protocol_records=protocol_count,protocol_unattributed=dict(zip(('packet','byte','flow'),unattributed)),
        fallback_records=fallback_count,semantics='discounted HHH residuals; address and protocol counts are not additive; protocol deficits never become candidates')
