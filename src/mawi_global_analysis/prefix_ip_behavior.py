"""Run-specific, disk-backed observations for the fixed Raw sender cohort.

Only saved flows-v3 and run artifacts are read. No packet parser or classifier
is called. See docs/guide/prefix-ip-behavior.md for definitions and limits.
"""
from __future__ import annotations

import csv
from contextlib import closing
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile

from mawi_global_analysis.flow_length import GROUPS, inspect_run, _targets
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.host_counts import HOST_COUNT_DEFINITION, summarize_host_counts
from mawi_global_analysis.scan_labels import FLOW_LABEL_COLUMNS

SCHEMA = 'prefix-ip-behavior-v1'
ADDITIVE = (
    'flow_count', 'sent_packets', 'received_packets', 'sent_frame_bytes',
    'received_frame_bytes', 'tcp_flow_count', 'udp_flow_count',
    'tcp_sent_packets', 'udp_sent_packets', 'tcp_received_packets', 'udp_received_packets',
    'plain_syn_sent_count_observed_post_init', 'synack_sent_count_observed_post_init',
    'rst_sent_count_observed_post_init', 'tcp_syn_attempt_flows', 'tcp_syn_receiver_flows',
    'tcp_synack_response_flows', 'tcp_rst_response_flows', 'tcp_payload_observed_flows',
)
DISTINCT = ('unique_peer_ips', 'unique_tcp_peer_ips', 'unique_udp_peer_ips')
IDENTIFIERS = ('dataset_id', 'run_name', 'prefix', 'ip', 'group')
BEHAVIOR_COLUMNS = (*IDENTIFIERS, *ADDITIVE, *DISTINCT)
PORT_COLUMNS = (*IDENTIFIERS, 'protocol', 'port_side', 'observed_role', 'port', 'flow_count', 'sent_packets')
SAFE_MAX = 2**53-1


def integer(value, name, maximum=2**63-1):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+', value) or len(value)>20 or int(value)>maximum:
        raise ValueError(f'{name}: nonnegative bounded integer required')
    return int(value)


def boolean(value, name):
    if value.lower() not in ('true', 'false', '1', '0'):
        raise ValueError(f'{name}: invalid boolean')
    return int(value.lower() in ('true', '1'))


def csv_rows(path, columns):
    with Path(path).open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames) or not set(columns)<=set(reader.fieldnames):
            raise ValueError(f'{path}: missing/duplicate CSV columns')
        for line, row in enumerate(reader, 2):
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f'{path}:{line}: malformed CSV row')
            yield row


def _rows(info, name, progress):
    from mawi_global_analysis.flow_length import SCHEMAS
    count = 0
    for row in csv_rows(info.paths[name], SCHEMAS[name]):
        count += 1
        yield row
        if count%100000 == 0:
            if progress:
                progress(name, count)
    if count != info.entries[name]['row_count']:
        raise ValueError(f'{name}: row_count mismatch')
    if progress:
        progress(name, count)


def _flow(row):
    """Validate saved directional observations, returning endpoint vectors."""
    if not row['flow_id']:
        raise ValueError('empty flow_id')
    version = integer(row['ip_version'], 'ip_version', 6)
    src, dst = ipaddress.ip_address(row['src_ip']), ipaddress.ip_address(row['dst_ip'])
    if version not in (4, 6) or src.version != version or dst.version != version:
        raise ValueError('IP version mismatch')
    proto = integer(row['protocol'], 'protocol', 17)
    if proto not in (6, 17):
        raise ValueError('protocol must be TCP/UDP')
    ports = [integer(row[k], k, 65535) for k in ('src_port', 'dst_port')]
    packets = [integer(row[k], k) for k in ('packets_from_src', 'packets_from_dst')]
    sizes = [integer(row[k], k) for k in ('bytes_from_src', 'bytes_from_dst')]
    if sum(packets) != integer(row['packet_count'], 'packet_count') or not sum(packets):
        raise ValueError('directional packet_count mismatch')
    if any((packets[i]==0)!=(sizes[i]==0) for i in (0,1)):
        raise ValueError('directional bytes/packets presence mismatch')
    if sum(sizes) != integer(row['frame_byte_count'], 'frame_byte_count') or sum(sizes) != integer(row['byte_count'], 'byte_count'):
        raise ValueError('directional frame byte_count mismatch')
    payload = boolean(row['transport_payload_observed'], 'transport_payload_observed')
    counters = [[integer(row[f'{flag}_from_{role}'], f'{flag}_from_{role}')
                 for flag in ('syn', 'synack', 'rst')] for role in ('initiator', 'responder')]
    endpoints = [(str(src), ports[0]), (str(dst), ports[1])]
    sender, receiver = row['initial_syn_sender_ip'], row['initial_syn_receiver_ip']
    if bool(sender) != bool(receiver):
        raise ValueError('initial SYN sender/receiver must both be present or absent')
    initiator = None
    if sender:
        pair = (sender, integer(row['initial_syn_sender_port'], 'initial_syn_sender_port', 65535))
        other = (receiver, integer(row['initial_syn_receiver_port'], 'initial_syn_receiver_port', 65535))
        if proto != 6 or pair not in endpoints or other != endpoints[1-endpoints.index(pair)]:
            raise ValueError('initial SYN endpoint mismatch')
        initiator = endpoints.index(pair)
    elif any(any(c) for c in counters):
        raise ValueError('post-init counters without observed initial SYN')
    if proto == 17 and payload:
        raise ValueError('TCP payload observation on UDP')
    vectors, roles = [], []
    for side in (0, 1):
        role = None if initiator is None else int(side != initiator)
        # Identical endpoint tuples are attributed by flow.py to src/initiator.
        flags = [0, 0, 0] if role is None else counters[role]
        if any(c > packets[side] for c in flags):
            raise ValueError('post-init flag count exceeds endpoint packets')
        vectors.append([1, packets[side], packets[1-side], sizes[side], sizes[1-side],
            int(proto==6), int(proto==17), packets[side] if proto==6 else 0,
            packets[side] if proto==17 else 0, packets[1-side] if proto==6 else 0,
            packets[1-side] if proto==17 else 0, *flags,
            int(proto==6 and sender==str((src,dst)[side])),
            int(proto==6 and receiver==str((src,dst)[side])),
            int(role==1 and flags[1]>0), int(role==1 and flags[2]>0), int(proto==6 and payload)])
        roles.append(('syn_sender' if role==0 else 'syn_receiver' if role==1 else 'unknown')
                     if proto==6 else ('first_packet_sender' if side==0 else 'first_packet_receiver'))
    return version, proto, src, dst, ports, packets, vectors, roles


def _ingest(db, info, progress):
    columns = ','.join(f'{c} INTEGER NOT NULL' for c in ADDITIVE)
    db.executescript(f'''
        CREATE TABLE facts(id TEXT PRIMARY KEY, ipv INTEGER, src INTEGER, dst INTEGER,
                           src_sent INTEGER, dst_sent INTEGER) WITHOUT ROWID;
        CREATE TABLE labels(id TEXT PRIMARY KEY, broad_removed INTEGER, strict_removed INTEGER) WITHOUT ROWID;
        CREATE TABLE membership(scope TEXT,prefix TEXT,id TEXT,sm INTEGER,dm INTEGER,
                                PRIMARY KEY(scope,prefix,id)) WITHOUT ROWID;
        CREATE INDEX membership_id ON membership(id);
        CREATE TABLE events(prefix TEXT,ip INTEGER,id TEXT,removed INTEGER,proto INTEGER,peer INTEGER,{columns});
        CREATE TABLE ports(prefix TEXT,ip INTEGER,removed INTEGER,proto INTEGER,side TEXT,role TEXT,port INTEGER,sent INTEGER);
    ''')
    for row in _rows(info, 'flow_labels', progress):
        flags = {k: boolean(row[k],k) for k in FLOW_LABEL_COLUMNS[1:]}
        if (not row['flow_id'] or flags['strict_removed']>flags['broad_removed']
                or flags['strict_scan_like']!=flags['strict_removed'] or flags['broad_scan_like']!=flags['broad_removed']):
            raise ValueError('invalid removal labels')
        db.execute('INSERT INTO labels VALUES (?,?,?)', (row['flow_id'], flags['broad_removed'], flags['strict_removed']))
    targets = _targets(info)
    for row in _rows(info, 'flow_prefix_membership', progress):
        key = row['analysis_scope'], row['analysis_prefix']
        if key not in targets:
            raise ValueError('unknown membership scope/prefix')
        sm, dm = (boolean(row[k],k) for k in ('src_match','dst_match'))
        if not (sm or dm) or not row['flow_id']:
            raise ValueError('invalid membership')
        db.execute('INSERT INTO membership VALUES (?,?,?,?,?)', (*key,row['flow_id'],sm,dm))
    db.commit()
    expected = dict.fromkeys(targets,0)
    for count, row in enumerate(_rows(info, 'flows', progress),1):
        version, proto, src, dst, ports, packets, vectors, roles = _flow(row)
        sid, did = (int(src),int(dst)) if version==4 else (-1,-1)
        db.execute('INSERT INTO facts VALUES (?,?,?,?,?,?)', (row['flow_id'],version,sid,did,int(packets[0]>0),int(packets[1]>0)))
        label = db.execute('SELECT broad_removed,strict_removed FROM labels WHERE id=?',(row['flow_id'],)).fetchone()
        if label is None:
            raise ValueError('missing flow label')
        removed, strict_removed = label
        pattern=row['observed_tcp_pattern']
        syn_tcp=proto==6 and bool(row['initial_syn_sender_ip'])
        if (strict_removed and (not syn_tcp or pattern not in ('syn_to_rst','syn_synack_rst'))
                or removed and (not syn_tcp or pattern not in ('syn_to_rst','syn_synack_rst','syn_only_observed'))
                or removed and not strict_removed and pattern!='syn_only_observed'):
            raise ValueError('saved labels / observed pattern mismatch')
        members = {(s,p):(sm,dm) for s,p,sm,dm in db.execute('SELECT scope,prefix,sm,dm FROM membership WHERE id=?',(row['flow_id'],))}
        for key,(low,high) in targets.items():
            sm, dm = int(low<=sid<=high),int(low<=did<=high)
            if sm or dm:
                expected[key] += 1
                if members.get(key)!=(sm,dm):
                    raise ValueError('missing membership or endpoint flags mismatch')
            elif key in members:
                raise ValueError('out-of-range membership')
            if key[0]!='native' or not (sm or dm):
                continue
            prefix=key[1]
            endpoints = {sid:[0],did:[1]} if sid!=did else {sid:[0,1]}
            for ip,sides in endpoints.items():
                if not low<=ip<=high:
                    continue
                vector = vectors[sides[0]].copy()
                if len(sides)==2:
                    # One IP-flow: sum volume/flag counters, OR flow evidence.
                    for j in range(len(ADDITIVE)):
                        if j in (1,2,3,4,7,8,9,10,11,12,13):
                            vector[j]=sum(vectors[s][j] for s in sides)
                        else:
                            vector[j]=max(vectors[s][j] for s in sides)
                values=(prefix,ip,row['flow_id'],removed,proto,did if ip==sid else sid,*vector)
                db.execute(f'INSERT INTO events VALUES ({",".join("?" for _ in values)})',values)
                exposure={}
                for side in sides:
                    for port_side,port in [('local',ports[side]),('peer',ports[1-side])]:
                        k=(port_side,roles[side],port)
                        exposure[k]=exposure.get(k,0)+packets[side]
                for (port_side,role,port),sent in exposure.items():
                    db.execute('INSERT INTO ports VALUES (?,?,?,?,?,?,?,?)',(prefix,ip,removed,proto,port_side,role,port,sent))
        if count%100000==0:
            db.commit()
    for table in ('labels','membership'):
        if db.execute(f'SELECT 1 FROM {table} a LEFT JOIN facts f ON a.id=f.id WHERE f.id IS NULL LIMIT 1').fetchone():
            raise ValueError(f'{table}: unknown flow_id')
    db.executescript('''
        CREATE INDEX events_ip ON events(prefix,ip,removed);
        CREATE INDEX ports_ip ON ports(prefix,ip,removed);
        CREATE TABLE cohort AS SELECT prefix,ip FROM events GROUP BY prefix,ip HAVING SUM(sent_packets)>0;
        CREATE UNIQUE INDEX cohort_ip ON cohort(prefix,ip);
    ''')
    db.commit()
    return expected


def _summaries(db, prefixes):
    hosts=summarize_host_counts(db,prefixes)
    report={}
    for prefix in prefixes:
        report[prefix]={}
        for group,condition in [('Raw','1'),('removed','l.broad_removed=1'),('retained','l.broad_removed=0')]:
            count=db.execute(f'''SELECT COUNT(*) FROM membership m JOIN labels l ON m.id=l.id
                WHERE m.scope='native' AND m.prefix=? AND {condition}''',(prefix,)).fetchone()[0]
            sender_condition={'Raw':'1','removed':'removed=1','retained':'removed=0'}[group]
            senders=db.execute(f'''SELECT COUNT(*) FROM (SELECT e.ip FROM events e JOIN cohort c
                ON e.prefix=c.prefix AND e.ip=c.ip WHERE e.prefix=? AND {sender_condition}
                GROUP BY e.ip HAVING SUM(sent_packets)>0)''',(prefix,)).fetchone()[0]
            if senders!=hosts[prefix,group][1]:
                raise ValueError('host_counts sender mismatch')
            report[prefix][group]={'flow_count':count,'unique_sender_ips':senders}
    return report


def _write_csvs(db, stage, dataset, run):
    counts={}
    with (stage/'prefix_ip_behavior.csv').open('w',newline='',encoding='utf-8') as b, (stage/'prefix_ip_ports.csv').open('w',newline='',encoding='utf-8') as p:
        bw,pw=csv.writer(b),csv.writer(p)
        bw.writerow(BEHAVIOR_COLUMNS); pw.writerow(PORT_COLUMNS)
        counts={'prefix_ip_behavior.csv':0,'prefix_ip_ports.csv':0}
        sums=','.join(f'COALESCE(SUM({c}),0)' for c in ADDITIVE)
        for prefix,ip in db.execute('SELECT prefix,ip FROM cohort ORDER BY prefix,ip'):
            values={}
            for group,condition in [('Raw','1'),('removed','removed=1'),('retained','removed=0')]:
                vector=db.execute(f'''SELECT {sums},COUNT(DISTINCT peer),
                    COUNT(DISTINCT CASE WHEN proto=6 THEN peer END),COUNT(DISTINCT CASE WHEN proto=17 THEN peer END)
                    FROM events WHERE prefix=? AND ip=? AND {condition}''',(prefix,ip)).fetchone()
                if any(type(v)!=int or not 0<=v<=SAFE_MAX for v in vector):
                    raise ValueError('aggregate exceeds safe integer range')
                values[group]=vector
                bw.writerow((dataset,run,prefix,str(ipaddress.IPv4Address(ip)),group,*vector))
                counts['prefix_ip_behavior.csv']+=1
                # A cursor streams all port keys; no Python-wide port dictionary.
                for proto,side,role,port,n,sent in db.execute(f'''SELECT proto,side,role,port,COUNT(*),SUM(sent)
                    FROM ports WHERE prefix=? AND ip=? AND {condition}
                    GROUP BY proto,side,role,port ORDER BY proto,side,role,port''',(prefix,ip)):
                    if max(n,sent)>SAFE_MAX:
                        raise ValueError('port aggregate exceeds safe integer range')
                    pw.writerow((dataset,run,prefix,str(ipaddress.IPv4Address(ip)),group,'TCP' if proto==6 else 'UDP',side,role,port,n,sent))
                    counts['prefix_ip_ports.csv']+=1
            if any(a!=b+c for a,b,c in zip(values['Raw'][:len(ADDITIVE)],values['removed'],values['retained'])):
                raise ValueError('Raw additive identity failed')
        # Raw ports are the SQL union of the two disjoint removal partitions.
    return counts


def aggregate_run(root: Path, dataset_id: str, run_name: str, *, output_dir: Path,
                  scratch_dir: Path | None = None, expected_prefix_count: int = 18, progress=None) -> Path:
    output=Path(output_dir).resolve()
    if output.exists():
        raise FileExistsError(f'existing output protected: {output}')
    info=inspect_run(root,dataset_id,run_name,verify_content_hashes=False)
    if len(info.selected_prefixes)!=expected_prefix_count:
        raise ValueError(f'selected prefix count: expected {expected_prefix_count}, got {len(info.selected_prefixes)}')
    scratch=Path(scratch_dir) if scratch_dir else Path(tempfile.gettempdir())
    if not scratch.is_dir():
        raise FileNotFoundError(scratch)
    # Conservative estimate, not a measured upper bound (port diversity matters).
    estimate=sum(p.stat().st_size for p in info.paths.values())*6+64*1024**2
    if shutil.disk_usage(scratch).free<estimate:
        raise ValueError(f'insufficient scratch space; estimated need {estimate} bytes')
    manifest_sha=sha256_file(info.manifest_path)
    inputs={k:{'path':str(p),'sha256':sha256_file(p),'size_bytes':p.stat().st_size,
               'row_count':info.entries[k]['row_count'],'mtime_ns':p.stat().st_mtime_ns} for k,p in info.paths.items()}
    for key,entry in inputs.items():
        if info.entries[key].get('sha256',entry['sha256'])!=entry['sha256']:
            raise ValueError(f'{key}: input checksum mismatch')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mawi-ip-behavior-',dir=scratch) as work, tempfile.TemporaryDirectory(prefix='.ip-behavior-stage-',dir=output.parent) as staging:
        stage=Path(staging)/'bundle'; stage.mkdir()
        with closing(sqlite3.connect(Path(work)/'working.sqlite')) as db:
            db.execute('PRAGMA cache_size=-32768'); db.execute('PRAGMA temp_store=FILE')
            try:
                expected=_ingest(db,info,progress)
                report=_summaries(db,info.selected_prefixes)
                counts=_write_csvs(db,stage,dataset_id,run_name)
            except sqlite3.Error as exc:
                raise ValueError(f'duplicate/invalid SQLite record or aggregate: {exc}') from exc
            for prefix in info.selected_prefixes:
                if report[prefix]['Raw']['flow_count']!=expected['native',prefix]:
                    raise ValueError('prefix flow count mismatch')
        for key,p in info.paths.items():
            if (p.stat().st_size,p.stat().st_mtime_ns)!=(inputs[key]['size_bytes'],inputs[key]['mtime_ns']):
                raise ValueError('input changed during aggregation')
        if sha256_file(info.manifest_path)!=manifest_sha:
            raise ValueError('run manifest changed during aggregation')
        validation={'status':'passed','expected_prefix_count':expected_prefix_count,
            'host_count_definition':HOST_COUNT_DEFINITION,'prefixes':report,
            'flow_rows':info.entries['flows']['row_count'],
            'invalid_records':0,'duplicate_records':0,'missing_records':0,
            'checks':['run identity','CSV schemas/counts','unique IDs','complete membership',
                      'IPv4 membership','directional volumes','fixed Raw cohort','host_counts senders',
                      'prefix flow counts','Raw additive partition','peer set union by SQL DISTINCT',
                      'port additive partition by SQL GROUP BY']}
        (stage/'ip_behavior_validation.json').write_text(json.dumps(validation,indent=2),encoding='utf-8')
        record={'schema_version':SCHEMA,'dataset_id':dataset_id,'run_name':run_name,
            'run_manifest_sha256':manifest_sha,'selected_prefixes':info.selected_prefixes,
            'host_count_definition':HOST_COUNT_DEFINITION,'inputs':inputs,
            'tool':{'python':sys.version,'module':'mawi_global_analysis.prefix_ip_behavior',
                    'source_sha256':{name:sha256_file(Path(__file__).with_name(name)) for name in
                        ('prefix_ip_behavior.py','flow_length.py','host_counts.py','flow_stage.py','config.py','hashing.py')},
                    'config_sha256':sha256_file(Path(__file__).resolve().parents[2]/'configs/scan_source_driven_removal.yaml')},
            'scratch_estimate_bytes':estimate,
            'outputs':{name:{'sha256':sha256_file(stage/name),'row_count':count} for name,count in counts.items()},
            'validation_sha256':sha256_file(stage/'ip_behavior_validation.json')}
        (stage/'ip_behavior_manifest.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
        for path in stage.iterdir():
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
        if output.exists():
            raise FileExistsError(output)
        stage.rename(output)
    return output


def load_bundle(data, behavior_csv, ports_csv, manifest_path, top_k=10):
    """Validate the full bundle before attaching any bounded display payload."""
    if type(top_k)!=int or not 1<=top_k<=100:
        raise ValueError('top_k must be between 1 and 100')
    manifest_path=Path(manifest_path)
    record=json.loads(manifest_path.read_text(encoding='utf-8'))
    if (record.get('schema_version')!=SCHEMA or record.get('dataset_id')!=data['dataset_id']
            or record.get('run_name')!=data['run_name']
            or record.get('run_manifest_sha256')!=data.get('run_manifest_sha256')
            or not re.fullmatch('[0-9a-f]{64}',str(record.get('run_manifest_sha256','')))
            or record.get('host_count_definition')!=HOST_COUNT_DEFINITION):
        raise ValueError('IP behavior manifest identity mismatch')
    targets={t['prefix']:t for t in data['prefixes']}
    if len(targets)!=len(data['prefixes']) or sorted(targets)!=record['selected_prefixes']:
        raise ValueError('IP behavior selected prefixes mismatch')
    capacities={p:ipaddress.IPv4Network(p).num_addresses for p in targets}
    if len(targets)>256 or any(n>256 for n in capacities.values()):
        raise ValueError('IP behavior display capacity exceeded')
    validation_path=manifest_path.parent/'ip_behavior_validation.json'
    if sha256_file(validation_path)!=record['validation_sha256']:
        raise ValueError('validation checksum mismatch')
    validation=json.loads(validation_path.read_text(encoding='utf-8'))
    if validation.get('status')!='passed' or set(validation['prefixes'])!=set(targets):
        raise ValueError('IP behavior validation report incomplete')
    for filename,path in [('prefix_ip_behavior.csv',behavior_csv),('prefix_ip_ports.csv',ports_csv)]:
        if sha256_file(Path(path))!=record['outputs'][filename]['sha256']:
            raise ValueError('IP behavior CSV checksum mismatch')
    incoming={p:{} for p in targets}
    row_count=0
    for row in csv_rows(behavior_csv,BEHAVIOR_COLUMNS):
        row_count+=1
        if row_count>sum(capacities.values())*3:
            raise ValueError('IP behavior row limit exceeded')
        prefix,ip,group=(row[k] for k in ('prefix','ip','group'))
        if prefix not in targets or group not in GROUPS or ipaddress.IPv4Address(ip) not in ipaddress.IPv4Network(prefix):
            raise ValueError('IP behavior unknown/out-of-range key')
        if row['dataset_id']!=data['dataset_id'] or row['run_name']!=data['run_name']:
            raise ValueError('IP behavior row identity mismatch')
        groups=incoming[prefix].setdefault(ip,{})
        if group in groups:
            raise ValueError('duplicate IP behavior key')
        numbers={k:integer(row[k],k,SAFE_MAX) for k in (*ADDITIVE,*DISTINCT)}
        n=numbers['flow_count']
        if (numbers['tcp_flow_count']+numbers['udp_flow_count']!=n
                or numbers['tcp_sent_packets']+numbers['udp_sent_packets']!=numbers['sent_packets']
                or numbers['tcp_received_packets']+numbers['udp_received_packets']!=numbers['received_packets']
                or n>validation['prefixes'][prefix][group]['flow_count']
                or (numbers['unique_peer_ips']>0)!=(n>0)
                or (numbers['unique_tcp_peer_ips']>0)!=(numbers['tcp_flow_count']>0)
                or (numbers['unique_udp_peer_ips']>0)!=(numbers['udp_flow_count']>0)
                or numbers['unique_peer_ips']>n
                or numbers['unique_tcp_peer_ips']>numbers['tcp_flow_count']
                or numbers['unique_udp_peer_ips']>numbers['udp_flow_count']
                or not max(numbers['unique_tcp_peer_ips'],numbers['unique_udp_peer_ips'])<=numbers['unique_peer_ips']<=numbers['unique_tcp_peer_ips']+numbers['unique_udp_peer_ips']
                or any(numbers[k]>numbers['tcp_sent_packets'] for k in ADDITIVE[11:14])
                or any(numbers[k]>numbers['tcp_flow_count'] for k in ADDITIVE[14:])
                or (n==0 and any(numbers.values()))):
            raise ValueError('IP behavior inconsistent metric bounds')
        groups[group]={**numbers,'ports':[],'port_summary':{}}
    if row_count!=record['outputs']['prefix_ip_behavior.csv']['row_count']:
        raise ValueError('IP behavior row_count mismatch')
    for prefix,ips in incoming.items():
        target=targets[prefix]
        for ip,groups in ips.items():
            if set(groups)!=set(GROUPS) or groups['Raw']['sent_packets']==0:
                raise ValueError('fixed Raw cohort requires three groups and observed Raw sending')
            for metric in ADDITIVE:
                if groups['Raw'][metric]!=groups['removed'][metric]+groups['retained'][metric]:
                    raise ValueError('IP behavior Raw additive mismatch')
            for metric in DISTINCT:
                raw,removed,retained=(groups[g][metric] for g in GROUPS)
                if not max(removed,retained)<=raw<=removed+retained:
                    raise ValueError('IP behavior distinct set bounds mismatch')
        for group in GROUPS:
            measured=validation['prefixes'][prefix][group]
            senders=sum(groups[group]['sent_packets']>0 for groups in ips.values())
            if (senders!=measured['unique_sender_ips'] or measured['flow_count']!=target['stats'][group]['flow_count']
                    or not target.get('host_summary') or senders!=target['host_summary'][group]['unique_sender_ips']):
                raise ValueError('IP behavior host counts / prefix flow count mismatch; host summary required')
    # Disk-backed full port validation precedes TopK selection.
    with tempfile.TemporaryDirectory(prefix='mawi-ip-ports-') as work, closing(sqlite3.connect(Path(work)/'ports.sqlite')) as db:
        db.execute('PRAGMA temp_store=FILE'); db.execute('PRAGMA cache_size=-32768')
        db.execute('''CREATE TABLE p(prefix TEXT,ip TEXT,g TEXT,proto TEXT,side TEXT,role TEXT,port INTEGER,n INTEGER,sent INTEGER,
            PRIMARY KEY(prefix,ip,g,proto,side,role,port)) WITHOUT ROWID''')
        count=0
        try:
            for row in csv_rows(ports_csv,PORT_COLUMNS):
                count+=1
                prefix,ip,group=(row[k] for k in ('prefix','ip','group'))
                proto,side,role=(row[k] for k in ('protocol','port_side','observed_role'))
                if (row['dataset_id']!=data['dataset_id'] or row['run_name']!=data['run_name']
                        or prefix not in incoming or ip not in incoming[prefix] or group not in GROUPS
                        or proto not in ('TCP','UDP') or side not in ('local','peer')
                        or role not in (('syn_sender','syn_receiver','unknown') if proto=='TCP' else ('first_packet_sender','first_packet_receiver'))):
                    raise ValueError('invalid port key/role/identity')
                port=integer(row['port'],'port',65535)
                n,sent=(integer(row[k],k,SAFE_MAX) for k in ('flow_count','sent_packets'))
                metrics=incoming[prefix][ip][group]
                if not 0<n<=metrics[f'{proto.lower()}_flow_count'] or sent>metrics[f'{proto.lower()}_sent_packets']:
                    raise ValueError('port metric bound mismatch')
                db.execute('INSERT INTO p VALUES (?,?,?,?,?,?,?,?,?)',(prefix,ip,group,proto,side,role,port,n,sent))
            if count!=record['outputs']['prefix_ip_ports.csv']['row_count']:
                raise ValueError('port row count mismatch')
            if db.execute('''SELECT 1 FROM p GROUP BY prefix,ip,proto,side,role,port
                HAVING SUM(CASE WHEN g='Raw' THEN n ELSE -n END)!=0
                OR SUM(CASE WHEN g='Raw' THEN sent ELSE -sent END)!=0 LIMIT 1''').fetchone():
                raise ValueError('port Raw additive mismatch')
            for prefix,ips in incoming.items():
                for ip,groups in ips.items():
                    for group,metrics in groups.items():
                        for proto in ('TCP','UDP'):
                            for side in ('local','peer'):
                                keys,n,sent=db.execute('''SELECT COUNT(*),COALESCE(SUM(n),0),COALESCE(SUM(sent),0)
                                    FROM p WHERE prefix=? AND ip=? AND g=? AND proto=? AND side=?''',(prefix,ip,group,proto,side)).fetchone()
                                flows=metrics[f'{proto.lower()}_flow_count']
                                if sent!=metrics[f'{proto.lower()}_sent_packets'] or not flows<=n<=2*flows:
                                    raise ValueError('port local/peer totals mismatch')
                                summary={'total_keys':keys,'shown_keys':min(keys,top_k),'omitted_keys':max(0,keys-top_k),
                                         'endpoint_flow_count':n,'sent_packets':sent}
                                metrics['port_summary'][f'{proto}/{side}']=summary
                                for role,port,fn,sp in db.execute('''SELECT role,port,n,sent FROM p
                                    WHERE prefix=? AND ip=? AND g=? AND proto=? AND side=?
                                    ORDER BY sent DESC,n DESC,port,role LIMIT ?''',(prefix,ip,group,proto,side,top_k)):
                                    metrics['ports'].append({'protocol':proto,'port_side':side,'observed_role':role,
                                        'port':port,'flow_count':fn,'sent_packets':sp})
        except sqlite3.Error as exc:
            raise ValueError(f'duplicate or invalid port aggregate: {exc}') from exc
    return {prefix:{'schema_version':SCHEMA,'top_k':top_k,
                   'ips':[{'ip':ip,'groups':groups} for ip,groups in sorted(ips.items(),key=lambda item:int(ipaddress.IPv4Address(item[0])))]}
            for prefix,ips in incoming.items()}
