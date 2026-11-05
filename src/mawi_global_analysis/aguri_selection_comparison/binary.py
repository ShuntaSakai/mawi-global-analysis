"""Read-only verification of saved canonical aguri_flow records, not conversion."""
import csv
import hashlib
import ipaddress
from pathlib import Path

from mawi_global_analysis.agurim_prime.input import RECORD, _REQUIRED, _integer, _timestamp


def verify_canonical_binary(flows: Path,binary: Path) -> dict:
    """Compare every saved record to canonical fields, in order, without writes.

    Reuses the converter's ABI and scalar validation. No binary is generated and
    no selector is executed. Constant record memory; packet/byte audits remain
    Python integers. Shared canonical validation separately checks cache/IDs.
    """
    audit=dict(input_rows=0,included_flows=0,excluded_ipv6=0,excluded_protocol=0,
               included_packets=0,included_frame_bytes=0)
    checksum=hashlib.sha256()
    with Path(flows).open(newline='',encoding='utf-8') as source,Path(binary).open('rb') as saved:
        reader=csv.DictReader(source,strict=True)
        if not reader.fieldnames or len(set(reader.fieldnames))!=len(reader.fieldnames) or not _REQUIRED.issubset(reader.fieldnames):
            raise ValueError('C.binary: invalid canonical header')
        for row in reader:
            audit['input_rows']+=1
            if None in row or any(v is None for v in row.values()):raise ValueError('C.binary: malformed canonical row')
            version=_integer(row['ip_version'],'ip_version',4,6)
            src,dst=ipaddress.ip_address(row['src_ip']),ipaddress.ip_address(row['dst_ip'])
            if src.version!=version or dst.version!=version:raise ValueError('C.binary: endpoint version mismatch')
            protocol=_integer(row['protocol'],'protocol',0,255)
            sport=_integer(row['src_port'],'src_port',0,65535);dport=_integer(row['dst_port'],'dst_port',0,65535)
            packets=_integer(row['packet_count'],'packet_count',1,2**32-1);size=_integer(row['byte_count'],'byte_count',1,2**32-1)
            first,fi=_timestamp(row['start_time']);last,li=_timestamp(row['end_time'])
            if first>last:raise ValueError('C.binary: reversed timestamps')
            if 'frame_byte_count' in row and _integer(row['frame_byte_count'],'frame_byte_count',1,2**32-1)!=size:
                raise ValueError('C.binary: frame byte count mismatch')
            if version!=4:audit['excluded_ipv6']+=1;continue
            if protocol not in (6,17):audit['excluded_protocol']+=1;continue
            expected=RECORD.pack(src.packed.ljust(16,b'\0'),dst.packed.ljust(16,b'\0'),sport,dport,4,protocol,0,packets,size,fi,li)
            if saved.read(RECORD.size)!=expected:
                raise ValueError(f'C.binary record differs from canonical flow: {row["flow_id"]}')
            checksum.update(expected);audit['included_flows']+=1;audit['included_packets']+=packets;audit['included_frame_bytes']+=size
        if saved.read(1):raise ValueError('C.binary: extra records/trailing bytes')
    return dict(audit=audit,record_size=RECORD.size,record_count=audit['included_flows'],
                expected_sha256=checksum.hexdigest(),verification='all saved fields/weights/order match canonical rows; no conversion executed')
