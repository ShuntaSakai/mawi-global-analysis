"""Actual sibling loader/CLI, without changing or installing into that repo."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from test_random_prefix_validation import source_runs, compiled_two
from mawi_global_analysis.random_prefix_selection.run import run_random_selection

SIBLING=Path(__file__).resolve().parents[2]/'mawi-protocol-analysis'


def test_actual_downstream_reads_random18_flow18_packet15(source_runs,tmp_path):
    if not (SIBLING/'src/mawi_protocol_analysis/prefixes.py').is_file():
        pytest.skip('actual sibling repository unavailable; compatibility not verified here')
    root,flows=source_runs
    assert (root/'synthetic.pcap').is_file(), 'synthetic source PCAP must bind actual bytes'
    random=run_random_selection(root,'fixture','downstream',flows,'flow','packet')
    env={**os.environ,'PYTHONPATH':str(SIBLING/'src'),'PYTHONDONTWRITEBYTECODE':'1'}
    for mode,count,manifest in [('random',18,random),('flow',18,root/'results/fixture/flow/run_manifest.json'),('packet',15,root/'results/fixture/packet/run_manifest.json')]:
        source=json.loads(manifest.read_text()); ledger=source['artifacts']['prefixes']['path']
        code='from pathlib import Path; from mawi_protocol_analysis.prefixes import load_prefixes; import sys; s=load_prefixes(Path(sys.argv[1]),int(sys.argv[2])); print(len(s.networks))'
        load=subprocess.run([sys.executable,'-c',code,ledger,str(count)],env=env,capture_output=True,text=True)
        assert load.returncode==0,load.stderr
        assert int(load.stdout)==count
        result=subprocess.run([sys.executable,'-m','mawi_protocol_analysis',str(root/'synthetic.pcap'),
            '--prefixes',ledger,'--selection-manifest',str(manifest),'--expected-prefix-count',str(count),
            '--output-root',str(tmp_path/mode)],env=env,capture_output=True,text=True)
        assert result.returncode==0,result.stderr
    # Downstream must refuse a different PCAP, even with the same valid ledger.
    changed=tmp_path/'changed.pcap'; raw=(root/'synthetic.pcap').read_bytes(); changed.write_bytes(raw[:24])
    result=subprocess.run([sys.executable,'-m','mawi_protocol_analysis',str(changed),'--prefixes',
        str(random.parent/'prefixes.csv'),'--selection-manifest',str(random),'--output-root',str(tmp_path/'wrong')],env=env,capture_output=True,text=True)
    assert result.returncode!=0 and 'SHA-256' in result.stderr
