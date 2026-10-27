"""Synthetic saved runs: literal endpoint expectations, no PCAP or real data."""
import csv
import json
from pathlib import Path
import pandas as pd
import pytest
from mawi_global_analysis.flow_length import make_demo_run, analyze_run
from mawi_global_analysis.hashing import sha256_file

@pytest.fixture
def run(tmp_path):
    dataset, name = make_demo_run(tmp_path)
    manifest_path = tmp_path/'results'/dataset/name/'run_manifest.json'
    manifest = json.loads(manifest_path.read_text())
    path = tmp_path/manifest['artifacts']['flows']['path']
    frame = pd.read_csv(path, keep_default_na=False)
    frame['byte_count'] = frame.packet_count*60
    frame['frame_byte_count'] = frame.byte_count
    frame['bytes_from_src'] = frame.packets_from_src*60
    frame['bytes_from_dst'] = frame.packets_from_dst*60
    frame['src_port'] = 40000
    frame['dst_port'] = 80
    frame['transport_payload_observed'] = False
    frame['initial_syn_receiver_ip'] = ''
    frame.loc[frame.initial_syn_sender_ip.eq('0'),'initial_syn_sender_ip']=''
    for i in frame.index:
        if frame.loc[i,'initial_syn_sender_ip']:
            frame.loc[i,'initial_syn_sender_port'] = 40000
            frame.loc[i,'initial_syn_receiver_ip'] = frame.loc[i,'dst_ip']
            frame.loc[i,'initial_syn_receiver_port'] = 80
            frame.loc[i,'syn_from_initiator'] = 1
    # Canonical src can be the observed SYN receiver.
    frame.loc[1, ['initial_syn_sender_ip','initial_syn_sender_port','initial_syn_receiver_ip','initial_syn_receiver_port','syn_from_initiator','synack_from_responder','packets_from_src','packets_from_dst','bytes_from_src','bytes_from_dst']] = ['192.0.2.2',80,'203.0.113.200',40000,1,1,1,1,60,60]
    frame.loc[2,'protocol'] = 17
    frame.to_csv(path,index=False)
    return tmp_path,dataset,name,path,manifest_path

def aggregate(run, **kwargs):
    from mawi_global_analysis.prefix_ip_behavior import aggregate_run
    return aggregate_run(*run[:3], output_dir=run[0]/'behavior', expected_prefix_count=3, **kwargs)

def rows(path):
    with path.open() as f:
        return list(csv.DictReader(f))

def test_fixed_cohort_direction_ports_and_host_counts(run):
    out=aggregate(run)
    table={(r['prefix'],r['ip'],r['group']):r for r in rows(out/'prefix_ip_behavior.csv')}
    a=table['192.0.2.0/24','192.0.2.2','Raw']
    assert (int(a['sent_packets']),int(a['received_packets'])) == (1,1)
    assert int(a['plain_syn_sent_count_observed_post_init']) == 1
    assert int(a['synack_sent_count_observed_post_init']) == 0
    assert int(a['tcp_syn_attempt_flows']) == 1
    assert int(table['192.0.2.0/24','192.0.2.2','retained']['flow_count']) == 0
    assert int(table['192.0.2.0/24','192.0.2.3','Raw']['udp_sent_packets']) == 3
    ports=rows(out/'prefix_ip_ports.csv')
    assert any(r['ip']=='192.0.2.2' and r['port_side']=='local' and r['port']=='80' and r['observed_role']=='syn_sender' for r in ports)
    summary=analyze_run(*run[:3]).summary
    for row in summary.itertuples():
        if '/' in row.prefix:
            assert sum(int(v['sent_packets'])>0 for (p,ip,g),v in table.items() if p==row.prefix and g==row.group)==row.unique_sender_ips
    report=json.loads((out/'ip_behavior_validation.json').read_text())
    assert report['status']=='passed'
    assert report['prefixes']['203.0.113.7/32']['Raw']['flow_count']==0
    for p,ip,g in table:
        for col in ('flow_count','sent_packets','received_frame_bytes','plain_syn_sent_count_observed_post_init'):
            assert int(table[p,ip,'Raw'][col]) == int(table[p,ip,'removed'][col])+int(table[p,ip,'retained'][col])

def test_self_ip_counts_flow_once_and_ports_keep_endpoint_meaning(run):
    frame=pd.read_csv(run[3],keep_default_na=False)
    frame.loc[2,['dst_ip','packets_from_src','packets_from_dst','bytes_from_src','bytes_from_dst']]=['192.0.2.3',2,1,120,60]
    frame.to_csv(run[3],index=False)
    # Update membership flags to reflect both endpoints.
    m=json.loads(run[4].read_text()); path=run[0]/m['artifacts']['flow_prefix_membership']['path']
    from mawi_global_analysis.membership import build_membership
    member=build_membership(frame,pd.read_csv(run[0]/m['artifacts']['prefixes']['path'])); member.to_csv(path,index=False)
    m['artifacts']['flow_prefix_membership']['row_count']=len(member); run[4].write_text(json.dumps(m))
    out=aggregate(run)
    a=next(r for r in rows(out/'prefix_ip_behavior.csv') if r['ip']=='192.0.2.3' and r['group']=='Raw')
    assert (int(a['flow_count']),int(a['sent_packets']),int(a['received_packets']),int(a['unique_peer_ips']))==(1,3,3,1)
    local=[r for r in rows(out/'prefix_ip_ports.csv') if r['ip']=='192.0.2.3' and r['group']=='Raw' and r['port_side']=='local']
    assert {r['port'] for r in local}=={'40000','80'}
    assert sum(int(r['sent_packets']) for r in local)==3

@pytest.mark.parametrize('column,value',[('packets_from_src','-1'),('bytes_from_dst','bad'),('protocol','1'),('src_port','65536'),('initial_syn_receiver_ip','198.51.100.99'),('transport_payload_observed','maybe')])
def test_bad_flow_stops_without_publication(run,column,value):
    frame=pd.read_csv(run[3],dtype=str,keep_default_na=False); frame.loc[0,column]=value; frame.to_csv(run[3],index=False)
    with pytest.raises(ValueError): aggregate(run)
    assert not (run[0]/'behavior').exists()

@pytest.mark.parametrize('artifact,kind',[('flow_labels','duplicate'),('flow_labels','missing'),('flow_prefix_membership','duplicate'),('flow_prefix_membership','missing'),('flow_prefix_membership','unknown')])
def test_bad_relations_stop(run,artifact,kind):
    m=json.loads(run[4].read_text()); path=run[0]/m['artifacts'][artifact]['path']; frame=pd.read_csv(path)
    if kind=='duplicate': frame=pd.concat([frame,frame.iloc[:1]])
    elif kind=='missing': frame=frame.iloc[1:]
    else: frame.loc[0,'flow_id']='unknown'
    frame.to_csv(path,index=False); m['artifacts'][artifact]['row_count']=len(frame); run[4].write_text(json.dumps(m))
    with pytest.raises(ValueError): aggregate(run)
    assert not (run[0]/'behavior').exists()

def test_protect_output_and_manifest_identity(run):
    out=aggregate(run); before=sha256_file(out/'prefix_ip_behavior.csv')
    with pytest.raises(FileExistsError): aggregate(run)
    assert sha256_file(out/'prefix_ip_behavior.csv')==before

def test_prefix_count_must_match_before_publication(run):
    from mawi_global_analysis.prefix_ip_behavior import aggregate_run
    with pytest.raises(ValueError,match='prefix'): aggregate_run(*run[:3],output_dir=run[0]/'behavior')
    assert not (run[0]/'behavior').exists()

def dashboard(run):
    from mawi_global_analysis.prefix_dashboard import build_dashboard_data
    data=build_dashboard_data(analyze_run(*run[:3]))
    data['run_manifest_sha256']=sha256_file(run[4])
    return data


def test_attach_verified_bundle_and_topk_preserves_all_port_csv(run):
    from mawi_global_analysis.prefix_dashboard import attach_ip_behavior, render_dashboard
    out=aggregate(run); data=dashboard(run)
    attach_ip_behavior(data,out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',out/'ip_behavior_manifest.json',top_k=1)
    target=next(t for t in data['prefixes'] if t['prefix']=='192.0.2.0/24')
    assert len(target['ip_behavior']['ips'])==4
    assert all('ip_behavior' not in t for t in data['references'])
    a=next(ip for ip in target['ip_behavior']['ips'] if ip['ip']=='192.0.2.2')
    assert a['groups']['Raw']['sent_packets']==1
    assert a['groups']['retained']['ports']==[]
    assert a['groups']['Raw']['port_summary']['TCP/local']['total_keys']==1
    html=render_dashboard(data)
    assert 'ip-behavior' in html
    assert 'script-src \'sha256-' in html
    assert '<script src=' not in html


@pytest.mark.parametrize('bad',['manifest','hash','cohort','additive','ports','host','prefix-flow'])
def test_attach_rejects_corruption_without_partial_mutation(run,bad):
    from mawi_global_analysis.prefix_dashboard import attach_ip_behavior
    out=aggregate(run); data=dashboard(run)
    manifest_path=out/'ip_behavior_manifest.json'; manifest=json.loads(manifest_path.read_text())
    if bad=='manifest': data['run_manifest_sha256']='0'*64
    elif bad=='host': data['prefixes'][0]['host_summary']['Raw']['unique_sender_ips']+=1
    elif bad=='prefix-flow': data['prefixes'][0]['stats']['Raw']['flow_count']+=1
    else:
        filename='prefix_ip_ports.csv' if bad=='ports' else 'prefix_ip_behavior.csv'
        path=out/filename; records=rows(path)
        if bad=='cohort': records.pop()
        elif bad=='additive': records[0]['sent_packets']=str(int(records[0]['sent_packets'])+1)
        elif bad=='ports': records[0]['port_side']='source'
        else: records[0]['sent_packets']='-1'
        with path.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(records[0]));w.writeheader();w.writerows(records)
        if bad!='hash':
            manifest['outputs'][filename]={'sha256':sha256_file(path),'row_count':len(records)}
            manifest_path.write_text(json.dumps(manifest))
    before=json.dumps(data,sort_keys=True)
    with pytest.raises(ValueError): attach_ip_behavior(data,out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',manifest_path)
    assert json.dumps(data,sort_keys=True)==before


def rewrite_flows(run, frame):
    from mawi_global_analysis.membership import build_membership
    frame.to_csv(run[3],index=False)
    manifest=json.loads(run[4].read_text())
    member=build_membership(frame,pd.read_csv(run[0]/manifest['artifacts']['prefixes']['path']))
    path=run[0]/manifest['artifacts']['flow_prefix_membership']['path']
    member.to_csv(path,index=False)
    manifest['artifacts']['flow_prefix_membership']['row_count']=len(member)
    run[4].write_text(json.dumps(manifest))


def test_distinct_peer_union_is_not_additive_and_huge_ids_are_text(run):
    frame=pd.read_csv(run[3],dtype=str,keep_default_na=False)
    frame.loc[5,'src_ip']='192.0.2.1'
    frame.loc[5,'flow_id']='9999999999999999999999999999999999999'
    manifest=json.loads(run[4].read_text()); labels=run[0]/manifest['artifacts']['flow_labels']['path']
    label_frame=pd.read_csv(labels); label_frame.loc[label_frame.flow_id.eq('demo-5'),'flow_id']=frame.loc[5,'flow_id']; label_frame.to_csv(labels,index=False)
    rewrite_flows(run,frame)
    out=aggregate(run)
    ip={r['group']:r for r in rows(out/'prefix_ip_behavior.csv') if r['ip']=='192.0.2.1'}
    assert [int(ip[g]['unique_peer_ips']) for g in ('Raw','removed','retained')]==[1,1,1]
    assert int(ip['Raw']['flow_count'])==2
    from mawi_global_analysis.prefix_dashboard import attach_ip_behavior
    attach_ip_behavior(dashboard(run),out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',out/'ip_behavior_manifest.json')


def test_same_prefix_two_senders_rst_payload_and_unknown_tcp_roles(run):
    frame=pd.read_csv(run[3],keep_default_na=False)
    frame.loc[4,'packets_from_src']=5; frame.loc[4,'packets_from_dst']=2
    frame.loc[4,'bytes_from_src']=300; frame.loc[4,'bytes_from_dst']=120
    frame.loc[4,'rst_from_responder']=1; frame.loc[4,'synack_from_responder']=1
    frame.loc[4,'transport_payload_observed']=True
    rewrite_flows(run,frame)
    out=aggregate(run); table={(r['ip'],r['group']):r for r in rows(out/'prefix_ip_behavior.csv')}
    responder=table['198.51.100.6','Raw']
    assert int(responder['flow_count'])==1
    assert int(responder['rst_sent_count_observed_post_init'])==1
    assert int(responder['tcp_rst_response_flows'])==1
    assert int(responder['tcp_synack_response_flows'])==1
    assert int(responder['tcp_payload_observed_flows'])==1
    assert int(table['198.51.100.5','Raw']['tcp_payload_observed_flows'])==1
    assert any(r['observed_role']=='unknown' for r in rows(out/'prefix_ip_ports.csv') if r['ip']=='192.0.2.4')


def test_native_28_and_32_do_not_expand_into_normalized_24(run):
    frame=pd.read_csv(run[3],keep_default_na=False)
    frame.loc[5,'src_ip']='203.0.113.7'
    manifest=json.loads(run[4].read_text()); path=run[0]/manifest['artifacts']['prefixes']['path']
    prefixes=pd.read_csv(path); prefixes['prefix']=prefixes.prefix.replace({'192.0.2.0/24':'192.0.2.0/28'}); prefixes.to_csv(path,index=False)
    rewrite_flows(run,frame)
    out=aggregate(run); table=rows(out/'prefix_ip_behavior.csv')
    assert any(r['prefix']=='192.0.2.0/28' for r in table)
    narrow=[r for r in table if r['prefix']=='203.0.113.7/32']
    assert len(narrow)==3 and {r['ip'] for r in narrow}=={'203.0.113.7'}


def test_deterministic_csv_after_input_reordering(run):
    out=aggregate(run); before={name:sha256_file(out/name) for name in ('prefix_ip_behavior.csv','prefix_ip_ports.csv')}
    manifest=json.loads(run[4].read_text())
    for entry in manifest['artifacts'].values():
        path=run[0]/entry['path']; frame=pd.read_csv(path,dtype=str,keep_default_na=False); frame.iloc[::-1].to_csv(path,index=False)
    from mawi_global_analysis.prefix_ip_behavior import aggregate_run
    second=aggregate_run(*run[:3],output_dir=run[0]/'second',expected_prefix_count=3)
    assert before=={name:sha256_file(second/name) for name in before}


def test_recorded_input_hash_and_scratch_capacity_fail_before_publication(run,monkeypatch):
    manifest=json.loads(run[4].read_text()); manifest['artifacts']['flows']['sha256']='0'*64; run[4].write_text(json.dumps(manifest))
    with pytest.raises(ValueError,match='checksum'): aggregate(run)
    assert not (run[0]/'behavior').exists()
    manifest['artifacts']['flows'].pop('sha256'); run[4].write_text(json.dumps(manifest))
    import shutil
    monkeypatch.setattr(shutil,'disk_usage',lambda path:type('Usage',(),{'free':0})())
    with pytest.raises(ValueError,match='scratch'): aggregate(run)
    assert not (run[0]/'behavior').exists()


def test_exact_cache_export_can_attach_bundle_without_reaggregation(run):
    from mawi_global_analysis.prefix_dashboard import export_dashboard, enrich_ip_behavior
    out=aggregate(run); cache=run[0]/'exact-cache'
    analyze_run(*run[:3],exact_cache_dir=cache)
    result=export_dashboard(*run[:3],cache,run[0]/'export.html',ip_behavior_bundle=out)
    html=result.read_text()
    assert '"ip_behavior"' in html
    assert '"ips"' in html
    again=enrich_ip_behavior(result,out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',out/'ip_behavior_manifest.json',run[0]/'again.html')
    assert again.read_text()==html
    with pytest.raises(FileExistsError): enrich_ip_behavior(result,out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',out/'ip_behavior_manifest.json',result)


def test_review_directional_bytes_require_packets(run):
    frame=pd.read_csv(run[3],keep_default_na=False)
    frame.loc[0,'bytes_from_src']=0; frame.loc[0,'bytes_from_dst']=60
    frame.to_csv(run[3],index=False)
    with pytest.raises(ValueError,match='directional'): aggregate(run)
    assert not (run[0]/'behavior').exists()


def test_review_impossible_empty_peer_sets_rejected(run):
    from mawi_global_analysis.prefix_dashboard import attach_ip_behavior
    out=aggregate(run); path=out/'prefix_ip_behavior.csv'; records=rows(path)
    for row in records:
        for col in ('unique_peer_ips','unique_tcp_peer_ips','unique_udp_peer_ips'): row[col]='0'
    with path.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(records[0])); writer.writeheader(); writer.writerows(records)
    mpath=out/'ip_behavior_manifest.json'; m=json.loads(mpath.read_text()); m['outputs'][path.name]['sha256']=sha256_file(path); mpath.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='bound'): attach_ip_behavior(dashboard(run),path,out/'prefix_ip_ports.csv',mpath)


def test_review_manifest_identifies_uncommitted_source_code(run):
    out=aggregate(run); m=json.loads((out/'ip_behavior_manifest.json').read_text())
    assert m['tool']['source_sha256']['prefix_ip_behavior.py']==sha256_file(Path(__file__).parents[2]/'src/mawi_global_analysis/prefix_ip_behavior.py')
    assert 'host_counts.py' in m['tool']['source_sha256']


def test_review_html_flush_failure_does_not_publish_partial_file(run,monkeypatch):
    import os
    from mawi_global_analysis.prefix_dashboard import enrich_ip_behavior, render_dashboard
    out=aggregate(run); source=run[0]/'source.html'; source.write_text(render_dashboard(dashboard(run)))
    output=run[0]/'failed.html'
    def fail(fd): raise OSError('simulated disk flush failure')
    monkeypatch.setattr(os,'fsync',fail)
    with pytest.raises(OSError,match='flush'): enrich_ip_behavior(source,out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',out/'ip_behavior_manifest.json',output)
    assert not output.exists()
    assert not list(run[0].glob('.ip-dashboard-*'))


def test_saved_removal_pattern_contradiction_is_rejected(run):
    manifest=json.loads(run[4].read_text()); path=run[0]/manifest['artifacts']['flow_labels']['path']
    frame=pd.read_csv(path); frame.loc[frame.flow_id.eq('demo-2'),['broad_removed','broad_scan_like']]=True; frame.to_csv(path,index=False)
    with pytest.raises(ValueError,match='pattern'): aggregate(run)
    assert not (run[0]/'behavior').exists()


def test_fixed_sender_can_have_receive_only_retained_group(run):
    frame=pd.read_csv(run[3],keep_default_na=False); frame.loc[6,'dst_ip']='192.0.2.1'; rewrite_flows(run,frame)
    out=aggregate(run); row=next(r for r in rows(out/'prefix_ip_behavior.csv') if r['ip']=='192.0.2.1' and r['group']=='retained')
    assert int(row['sent_packets'])==0
    assert int(row['received_packets'])==131072
    assert int(row['flow_count'])==1


def test_self_ip_same_port_does_not_double_flow_port_key(run):
    frame=pd.read_csv(run[3],keep_default_na=False)
    frame.loc[2,'dst_ip']='192.0.2.3'; frame.loc[2,'dst_port']=40000
    rewrite_flows(run,frame)
    out=aggregate(run)
    ports=[r for r in rows(out/'prefix_ip_ports.csv') if r['ip']=='192.0.2.3' and r['group']=='Raw' and r['port_side']=='local']
    # UDP observation roles intentionally remain two different keys.
    assert sum(int(r['sent_packets']) for r in ports)==3
    assert {r['port'] for r in ports}=={'40000'}


def test_topk_explicitly_reports_omitted_keys(run):
    frame=pd.read_csv(run[3],keep_default_na=False); frame.loc[5,'src_ip']='192.0.2.1'; frame.loc[5,'src_port']=50000; rewrite_flows(run,frame)
    out=aggregate(run)
    from mawi_global_analysis.prefix_dashboard import attach_ip_behavior
    data=dashboard(run); attach_ip_behavior(data,out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',out/'ip_behavior_manifest.json',top_k=1)
    p=next(t for t in data['prefixes'] if t['prefix']=='192.0.2.0/24')
    item=next(t for t in p['ip_behavior']['ips'] if t['ip']=='192.0.2.1')['groups']['Raw']
    assert item['port_summary']['TCP/local']['omitted_keys']==1
    assert item['port_summary']['TCP/local']['sent_packets']==9
    assert len([r for r in item['ports'] if r['protocol']=='TCP' and r['port_side']=='local'])==1


def test_all_eighteen_native_prefixes_and_two_references_are_preserved(run):
    from mawi_global_analysis.config import load_config
    from mawi_global_analysis.flow_length import CONFIG_PATH
    from mawi_global_analysis.prefix import build_corrected_prefix_ledger
    from mawi_global_analysis.prefix_ip_behavior import aggregate_run
    from mawi_global_analysis.prefix_dashboard import attach_ip_behavior
    prefixes=['192.0.2.0/24','198.51.100.0/24','203.0.113.7/32']+[f'198.19.{i}.0/24' for i in range(15)]
    ledger=build_corrected_prefix_ledger(pd.DataFrame({'src_prefix':prefixes,'dst_prefix':['*']*18}),load_config(CONFIG_PATH))
    manifest=json.loads(run[4].read_text()); path=run[0]/manifest['artifacts']['prefixes']['path']; ledger.to_csv(path,index=False)
    manifest['artifacts']['prefixes']['row_count']=len(ledger); run[4].write_text(json.dumps(manifest))
    rewrite_flows(run,pd.read_csv(run[3],keep_default_na=False))
    out=aggregate_run(*run[:3],output_dir=run[0]/'eighteen')
    data=dashboard(run); attach_ip_behavior(data,out/'prefix_ip_behavior.csv',out/'prefix_ip_ports.csv',out/'ip_behavior_manifest.json')
    assert len(data['prefixes'])==18
    assert len(data['references'])==2
    assert sum(not p['ip_behavior']['ips'] for p in data['prefixes'])==16
    assert all('ip_behavior' not in p for p in data['references'])
