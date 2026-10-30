"""One canonical bidirectional flow becomes one network-order aguri_flow."""
from __future__ import annotations

import csv
from decimal import Decimal, InvalidOperation
import ipaddress
import os
from pathlib import Path
import sqlite3
import struct
import tempfile

CONVERTER_VERSION = 'canonical-aguri-flow-v1'
RECORD = struct.Struct('!16s16sHHBBHIIII')
_REQUIRED = {'flow_id','ip_version','protocol','src_ip','dst_ip','src_port','dst_port',
             'packet_count','byte_count','start_time','end_time'}


def _integer(value: str, label: str, minimum: int, maximum: int) -> int:
    try:
        if not value or not value.isascii() or not value.isdecimal():
            raise ValueError
        result = int(value)
        if not minimum <= result <= maximum:
            raise ValueError
        return result
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError(f'{label}: integer outside [{minimum},{maximum}]: {value!r}') from exc


def _timestamp(value: str) -> tuple[Decimal, int]:
    try:
        timestamp = Decimal(value)
        if not timestamp.is_finite() or not 0 <= timestamp < 2**32:
            raise ValueError
        return timestamp, int(timestamp)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f'timestamp cannot be represented by aguri_flow: {value!r}') from exc


def convert_flows(flows: Path, output: Path, *, unit_packets: bool = False,
                  allow_segments: bool = False) -> dict:
    """Stream validated IPv4 TCP/UDP rows; never split or expand a flow.

    packet/byte fields are uint32 in upstream's 56-byte wire ABI. Overflow is an
    error, including in the probe. SQLite bounds ID/key validation RAM. With an
    explicit inactivity timeout, repeated keys are distinct canonical segments;
    otherwise duplicate (including reversed) keys are rejected.
    """
    flows, output = Path(flows), Path(output)
    if output.exists():
        raise FileExistsError(output)
    audit = {'input_rows':0,'included_flows':0,'excluded_ipv6':0,'excluded_protocol':0,
             'included_packets':0,'included_frame_bytes':0,
             'orientation':'first observed packet; not initiator/responder',
             'scope':'IPv4 TCP/UDP','unit_packets':unit_packets}
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.canonical-',dir=output.parent) as work:
        temporary = Path(work)/'records.bin'
        db = sqlite3.connect(Path(work)/'unique.sqlite')
        try:
            db.execute('PRAGMA cache_size=-8192')
            db.execute('PRAGMA temp_store=FILE')
            db.execute('CREATE TABLE ids(id TEXT PRIMARY KEY) WITHOUT ROWID')
            db.execute('CREATE TABLE tuples(key TEXT PRIMARY KEY) WITHOUT ROWID')
            with flows.open(newline='',encoding='utf-8') as source, temporary.open('wb') as target:
                reader = csv.DictReader(source,strict=True)
                if (not reader.fieldnames or len(reader.fieldnames)!=len(set(reader.fieldnames))
                        or not _REQUIRED.issubset(reader.fieldnames)):
                    raise ValueError('canonical flows: missing or duplicate required columns')
                for row in reader:
                    audit['input_rows'] += 1
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError('canonical flows: invalid CSV row width')
                    if not row['flow_id'].strip():
                        raise ValueError('canonical flows: empty flow_id')
                    try:
                        db.execute('INSERT INTO ids VALUES (?)',(row['flow_id'],))
                    except sqlite3.IntegrityError as exc:
                        raise ValueError('canonical flows: duplicate flow_id') from exc
                    version = _integer(row['ip_version'],'ip_version',4,6)
                    src,dst = ipaddress.ip_address(row['src_ip']),ipaddress.ip_address(row['dst_ip'])
                    if src.version!=version or dst.version!=version:
                        raise ValueError('canonical flows: endpoint / ip_version mismatch')
                    protocol = _integer(row['protocol'],'protocol',0,255)
                    sport = _integer(row['src_port'],'src_port',0,65535)
                    dport = _integer(row['dst_port'],'dst_port',0,65535)
                    # Exact canonical counts must fit the old ABI; splitting would
                    # silently change the formal flow count.
                    packets = _integer(row['packet_count'],'packet_count',1,2**32-1)
                    byte_count = _integer(row['byte_count'],'byte_count',1,2**32-1)
                    first,first_int = _timestamp(row['start_time'])
                    last,last_int = _timestamp(row['end_time'])
                    if first>last:
                        raise ValueError('canonical flows: end_time before start_time')
                    if 'frame_byte_count' in row and _integer(row['frame_byte_count'],'frame_byte_count',1,2**32-1)!=byte_count:
                        raise ValueError('canonical flows: byte_count must equal frame_byte_count')
                    endpoints = sorted(((str(src),sport),(str(dst),dport)))
                    if not allow_segments:
                        key = repr((version,protocol,endpoints))
                        try:
                            db.execute('INSERT INTO tuples VALUES (?)',(key,))
                        except sqlite3.IntegrityError as exc:
                            raise ValueError('canonical flows: duplicate bidirectional 5-tuple') from exc
                    if version!=4:
                        audit['excluded_ipv6']+=1
                        continue
                    if protocol not in (6,17):
                        audit['excluded_protocol']+=1
                        continue
                    target.write(RECORD.pack(src.packed.ljust(16,b'\0'),dst.packed.ljust(16,b'\0'),
                        sport,dport,4,protocol,0,1 if unit_packets else packets,byte_count,first_int,last_int))
                    audit['included_flows']+=1
                    audit['included_packets']+=packets
                    audit['included_frame_bytes']+=byte_count
                target.flush()
                os.fsync(target.fileno())
            # link publishes atomically and fails if another writer won the name.
            os.link(temporary,output)
        finally:
            db.close()
    return audit
