"""Versioned distinct-IP observations from validated saved IPv4 flows.

The temporary SQLite facts/membership/labels tables belong to flow_length.
Only the resulting integer counts are persisted; Python never holds all IPs.
"""
from __future__ import annotations

import ipaddress
import math
from numbers import Real
import sqlite3

HOST_COUNT_DEFINITION = 'ipv4-prefix-endpoints-observed-senders-v1'
HOST_COUNT_COLUMNS = ('unique_endpoint_ips', 'unique_sender_ips')
GROUPS = ('Raw', 'removed', 'retained')
REFERENCES = ('selected_union', 'overall_ipv4')


def summarize_host_counts(db: sqlite3.Connection, prefixes: list[str]) -> dict:
    """Count only in-scope endpoints; sender means that direction had packets.

    Native membership flags restrict each endpoint individually. The union
    uses the same flags across prefixes, never all peers of selected flows.
    MAX(sender) and GROUP BY ip preserve distinct sets across both directions
    and removal groups, including self-addressed flows and repeated IPs.
    """
    db.execute('''CREATE TABLE host_ips (
        ip INTEGER NOT NULL, removed INTEGER NOT NULL, sender INTEGER NOT NULL,
        PRIMARY KEY(ip,removed)) WITHOUT ROWID''')
    result = {}
    for prefix in [*prefixes, *REFERENCES]:
        db.execute('DELETE FROM host_ips')
        parameters = ()
        if prefix == 'overall_ipv4':
            source = 'facts f JOIN labels l ON f.id=l.id'
            src_where = dst_where = 'f.ipv=4'
        else:
            source = 'membership m JOIN facts f ON m.id=f.id JOIN labels l ON f.id=l.id'
            selected = "m.scope='native'"
            if prefix != 'selected_union':
                selected += ' AND m.prefix=?'
                parameters = (prefix, prefix)
            src_where, dst_where = selected+' AND m.sm=1', selected+' AND m.dm=1'
        db.execute(f'''INSERT INTO host_ips
            SELECT ip,removed,MAX(sender) FROM (
                SELECT f.src AS ip,l.broad_removed AS removed,f.src_sent AS sender
                FROM {source} WHERE {src_where}
                UNION ALL
                SELECT f.dst AS ip,l.broad_removed AS removed,f.dst_sent AS sender
                FROM {source} WHERE {dst_where}
            ) GROUP BY ip,removed''', parameters)
        for group, condition in [('Raw', '1'), ('removed', 'removed=1'), ('retained', 'removed=0')]:
            endpoints, senders = db.execute(f'''SELECT COUNT(*),COALESCE(SUM(sender),0)
                FROM (SELECT ip,MAX(sender) AS sender FROM host_ips
                      WHERE {condition} GROUP BY ip)''').fetchone()
            result[prefix, group] = (endpoints, senders)
    db.execute('DROP TABLE host_ips')
    return result


def validate_host_counts(summary, definition: str | None, prefixes: list[str]) -> bool:
    """Return False only for a genuine legacy summary with no measurements.

    Incomplete, unversioned, contradictory or non-integer measurements stop
    before they can be presented as measured values or cached again.
    """
    present = set(HOST_COUNT_COLUMNS) & set(summary.columns)
    if not present and definition is None:
        return False
    if present != set(HOST_COUNT_COLUMNS) or definition != HOST_COUNT_DEFINITION:
        raise ValueError('host IP summary: missing columns or unsupported host_count_definition')
    expected = {(p, g) for p in [*prefixes, *REFERENCES] for g in GROUPS}
    if (not {'prefix', 'group', 'flow_count'}.issubset(summary.columns)
            or summary.duplicated(['prefix', 'group']).any()
            or set(zip(summary.prefix, summary.group)) != expected):
        raise ValueError('host IP summary: missing/duplicate/unknown prefix or group')
    capacities = {p: ipaddress.ip_network(p).num_addresses for p in prefixes}
    capacities.update(selected_union=sum(capacities.values()), overall_ipv4=2**32)
    metrics = {}
    for row in summary.itertuples(index=False):
        values = (row.flow_count, row.unique_endpoint_ips, row.unique_sender_ips)
        if any(isinstance(v, bool) or not isinstance(v, Real) or not math.isfinite(v)
               or v < 0 or int(v) != v for v in values):
            raise ValueError('host IP summary: nonnegative integers required')
        n, endpoints, senders = map(int, values)
        if (not 0 <= senders <= endpoints <= min(capacities[row.prefix], 2*n)
                or (n > 0 and endpoints == 0)):
            raise ValueError(f'host IP summary: invalid counts: {row.prefix}/{row.group}')
        metrics[row.prefix, row.group] = (endpoints, senders)
    for prefix in [*prefixes, *REFERENCES]:
        for index in range(2):
            raw, removed, retained = (metrics[prefix, group][index] for group in GROUPS)
            if not max(removed, retained) <= raw <= removed+retained:
                raise ValueError(f'host IP summary: inconsistent group cardinalities: {prefix}')
    return True
