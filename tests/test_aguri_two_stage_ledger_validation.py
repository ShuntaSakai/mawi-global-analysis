"""Read-only saved-ledger checks; no binary build or Aguri execution required."""
import csv
from pathlib import Path
import subprocess

import pandas as pd
import pytest

from mawi_global_analysis.aguri_two_stage import validation
from mawi_global_analysis.config import load_config
from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.prefix import build_corrected_prefix_ledger,CORRECTED_LEDGER_COLUMNS

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def ledger(tmp_path):
    cfg=load_config(ROOT/'configs/baseline.yaml')
    candidates=pd.DataFrame({'src_prefix':['192.0.0.0/16','192.0.2.0/24','192.0.2.1/32','198.51.100.2/32','2001:db8::/32','0.0.0.0/0'],
                             'dst_prefix':['203.0.113.9/32','*','192.0.2.128/25','198.51.100.0/24','*','*']})
    source=tmp_path/'candidates.csv';saved=tmp_path/'prefixes.csv';candidates.to_csv(source,index=False)
    expected=build_corrected_prefix_ledger(candidates,cfg);expected.to_csv(saved,index=False)
    return source,cfg,saved,expected


def snapshot(paths):return {str(p):(p.stat().st_mtime_ns,sha256_file(p)) for p in paths}


def test_saved_null_normalization_roundtrip_is_read_only_without_selectors(ledger,monkeypatch):
    source,cfg,saved,expected=ledger
    missing=expected.loc[expected.normalized_prefix_24.isna(),'prefix'].tolist()
    assert missing==['0.0.0.0/0','192.0.0.0/16','2001:db8::/32']
    # Other fields have no nulls. Empty strings already represent absent reason/parent.
    assert expected.drop(columns='normalized_prefix_24').notna().all().all()
    before=snapshot((source,saved))
    def forbidden(*args,**kwargs):raise AssertionError('saved-ledger validation must not execute any process')
    monkeypatch.setattr(subprocess,'run',forbidden)
    validation._validate_prefix_ledger(source,cfg,saved)
    assert snapshot((source,saved))==before


@pytest.mark.parametrize('column,value',[
    ('prefix','192.0.3.0/24'),('prefix_length','25'),('normalized_prefix_24','192.0.3.0/24'),
    ('seen_as_src_prefix','False'),('seen_as_dst_prefix','True'),('aguri_occurrence_count','2'),
    ('aguri_src_occurrence_count','2'),('aguri_dst_occurrence_count','1'),('selected_for_analysis','False'),
    ('exclusion_reason','covered_by_parent'),('covered_by_prefix','192.0.0.0/16'),
    ('aguri_occurrence_count','1.00000001'),('prefix_length','24.00000001'),
    ('selected_for_analysis','1'),('aguri_occurrence_count',''),
])
def test_every_column_and_exact_numeric_flag_representation_remains_checked(ledger,column,value):
    source,cfg,saved,_=ledger
    with saved.open(newline='') as stream:rows=list(csv.DictReader(stream))
    row=next(r for r in rows if r['prefix']=='192.0.2.0/24');row[column]=value
    with saved.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=CORRECTED_LEDGER_COLUMNS);writer.writeheader();writer.writerows(rows)
    before=snapshot((source,saved))
    with pytest.raises(ValueError,match='corrected prefix ledger differs'):
        validation._validate_prefix_ledger(source,cfg,saved)
    assert snapshot((source,saved))==before


@pytest.mark.parametrize('text',['None','nan','NA',' '])
def test_literal_null_like_text_is_not_normalized_as_a_missing_cell(ledger,text):
    source,cfg,saved,_=ledger
    actual=pd.read_csv(saved,dtype=str,keep_default_na=False)
    actual.loc[actual.prefix.eq('192.0.0.0/16'),'normalized_prefix_24']=text;actual.to_csv(saved,index=False)
    with pytest.raises(ValueError,match='corrected prefix ledger differs'):
        validation._validate_prefix_ledger(source,cfg,saved)


@pytest.mark.parametrize('kind',['empty','no-null'])
def test_empty_and_nonnullable_ledgers_remain_valid(tmp_path,kind):
    cfg=load_config(ROOT/'configs/baseline.yaml')
    candidates=pd.DataFrame({'src_prefix':[],'dst_prefix':[]}) if kind=='empty' else pd.DataFrame({'src_prefix':['192.0.2.1/32'],'dst_prefix':['198.51.100.1/32']})
    source=tmp_path/'candidates.csv';saved=tmp_path/'prefixes.csv';candidates.to_csv(source,index=False)
    build_corrected_prefix_ledger(candidates,cfg).to_csv(saved,index=False)
    validation._validate_prefix_ledger(source,cfg,saved)


@pytest.mark.parametrize('kind',['missing-column','extra-column','missing-row','extra-row','row-order'])
def test_structural_differences_are_not_hidden_by_null_normalization(ledger,kind):
    source,cfg,saved,_=ledger;actual=pd.read_csv(saved,dtype=str,keep_default_na=False)
    if kind=='missing-column':actual=actual.drop(columns='exclusion_reason')
    elif kind=='extra-column':actual['unexpected']=''
    elif kind=='missing-row':actual=actual.iloc[1:]
    elif kind=='extra-row':actual=pd.concat([actual,actual.iloc[:1]],ignore_index=True)
    else:actual=actual.iloc[::-1]
    actual.to_csv(saved,index=False)
    with pytest.raises(ValueError,match='corrected prefix ledger differs'):
        validation._validate_prefix_ledger(source,cfg,saved)
