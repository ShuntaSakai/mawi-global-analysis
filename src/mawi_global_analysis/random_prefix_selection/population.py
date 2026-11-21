"""Strict streamed canonical rows and disk-backed observed /24 populations."""
from __future__ import annotations

import csv
from decimal import Decimal, InvalidOperation
import ipaddress
from pathlib import Path
import sqlite3
from collections.abc import Iterator

from mawi_global_analysis.flow_stage import FLOW_COLUMNS


def parent24(prefix: str) -> ipaddress.IPv4Network:
    network = ipaddress.ip_network(prefix, strict=True)
    if network.version != 4 or network.prefixlen < 24 or str(network) != prefix:
        raise ValueError(f'expected canonical IPv4 /24-/32: {prefix!r}')
    return ipaddress.IPv4Network((int(network.network_address) & 0xffffff00, 24))


def address24(address: str) -> ipaddress.IPv4Network:
    ip = ipaddress.IPv4Address(address)
    return ipaddress.IPv4Network((int(ip) & 0xffffff00, 24))


def load_selected_prefixes(path: Path, expected_count: int) -> tuple[ipaddress.IPv4Network, ...]:
    selected, seen = [], set()
    with Path(path).open(encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream, strict=True)
        columns = reader.fieldnames or []
        if len(set(columns)) != len(columns) or not {'prefix', 'selected_for_analysis'}.issubset(columns):
            raise ValueError('prefix ledger missing or duplicate columns')
        for row in reader:
            if None in row or any(v is None for v in row.values()):
                raise ValueError('malformed prefix ledger row')
            flag = row['selected_for_analysis']
            if flag not in ('True', 'False', 'true', 'false', '1', '0'):
                raise ValueError(f'invalid selected_for_analysis: {flag!r}')
            if row['prefix'] in seen:
                raise ValueError('duplicate prefix ledger row')
            seen.add(row['prefix'])
            if flag in ('True', 'true', '1'):
                parent24(row['prefix'])
                if 'analysis_scope' in row and row['analysis_scope'] != 'native':
                    raise ValueError('selected prefix must have native scope')
                selected.append(ipaddress.IPv4Network(row['prefix']))
    if len(selected) != expected_count:
        raise ValueError(f'selected count mismatch: expected {expected_count}, found {len(selected)}')
    return tuple(selected)


def exclusion_set(flow: list[str], packet: list[str]) -> tuple[ipaddress.IPv4Network, ...]:
    return tuple(sorted({parent24(str(p)) for p in (*flow, *packet)}, key=lambda p: int(p.network_address)))


def integer(value: str, label: str, minimum: int = 0, maximum: int | None = None) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError(f'{label}: expected unsigned integer')
    number = int(value)
    if number < minimum or (maximum is not None and number > maximum):
        raise ValueError(f'{label}: integer out of range')
    return number


def iter_flow_chunks(path: Path, chunksize: int) -> Iterator[list[dict]]:
    if type(chunksize) is not int or chunksize < 1:
        raise ValueError('chunksize must be positive')
    with Path(path).open(encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream, strict=True)
        if tuple(reader.fieldnames or ()) != FLOW_COLUMNS:
            raise ValueError('invalid canonical flow header')
        chunk = []
        for row in reader:
            if None in row or any(v is None for v in row.values()):
                raise ValueError('invalid canonical CSV row width')
            if not row['flow_id'].strip():
                raise ValueError('empty canonical flow_id')
            version = integer(row['ip_version'], 'ip_version')
            src, dst = ipaddress.ip_address(row['src_ip']), ipaddress.ip_address(row['dst_ip'])
            if src.version != version or dst.version != version:
                raise ValueError('endpoint / ip_version mismatch')
            for name, lo, hi in [('protocol', 0, 255), ('src_port', 0, 65535), ('dst_port', 0, 65535),
                                 ('packet_count', 1, None), ('byte_count', 1, None), ('frame_byte_count', 1, None)]:
                row[name] = integer(row[name], name, lo, hi)
            if row['byte_count'] != row['frame_byte_count']:
                raise ValueError('byte_count must equal frame_byte_count')
            try:
                start, end = Decimal(row['start_time']), Decimal(row['end_time'])
                if not start.is_finite() or not end.is_finite() or start < 0 or end < start:
                    raise ValueError('invalid canonical timestamps')
            except InvalidOperation as exc:
                raise ValueError('invalid canonical timestamps') from exc
            row['ip_version'] = version
            chunk.append(row)
            if len(chunk) == chunksize:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


def included(row: dict) -> bool:
    return row['ip_version'] == 4 and row['protocol'] in (6, 17)


def build_population(flows: Path, db: sqlite3.Connection, *, chunksize: int) -> dict:
    db.executescript('''
        PRAGMA cache_size=-8192;
        PRAGMA temp_store=FILE;
        CREATE TABLE population (address INTEGER PRIMARY KEY);
        CREATE TABLE ids (id TEXT PRIMARY KEY) WITHOUT ROWID;
        CREATE TABLE tuples (key TEXT PRIMARY KEY) WITHOUT ROWID;
    ''')
    audit = dict(input_rows=0, included_flows=0, excluded_ipv6=0, excluded_protocol=0)
    for chunk in iter_flow_chunks(flows, chunksize):
        for row in chunk:
            audit['input_rows'] += 1
            endpoints = sorted(((row['src_ip'], row['src_port']), (row['dst_ip'], row['dst_port'])))
            # Canonical textual IPs avoid alternate IPv6 spellings bypassing uniqueness.
            endpoints = sorted((str(ipaddress.ip_address(ip)), port) for ip, port in endpoints)
            key = repr((row['ip_version'], row['protocol'], endpoints))
            try:
                db.execute('INSERT INTO ids VALUES (?)', (row['flow_id'],))
            except sqlite3.IntegrityError as exc:
                raise ValueError('duplicate canonical flow_id') from exc
            try:
                db.execute('INSERT INTO tuples VALUES (?)', (key,))
            except sqlite3.IntegrityError as exc:
                raise ValueError('duplicate bidirectional 5-tuple') from exc
            if not included(row):
                audit['excluded_ipv6' if row['ip_version'] == 6 else 'excluded_protocol'] += 1
                continue
            audit['included_flows'] += 1
            for ip in (row['src_ip'], row['dst_ip']):
                db.execute('INSERT OR IGNORE INTO population VALUES (?)', (int(address24(ip).network_address),))
        db.commit()
    audit['population_count'] = db.execute('SELECT COUNT(*) FROM population').fetchone()[0]
    return audit


def iter_population(db: sqlite3.Connection) -> Iterator[ipaddress.IPv4Network]:
    for (address,) in db.execute('SELECT address FROM population ORDER BY address'):
        yield ipaddress.IPv4Network((address, 24))
