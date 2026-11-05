"""Bounded static source audit; never execute a Notebook or infer past results."""
import json
from pathlib import Path

from mawi_global_analysis.hashing import sha256_file


def audit_archives() -> dict:
    root=Path(__file__).resolve().parents[3]/'notebooks/archive/society-2026'
    records=[];tracked={}
    for path in sorted(root.glob('02_main_prefix_comparison_*.ipynb')):
        digest=sha256_file(path);notebook=json.loads(path.read_text(encoding='utf-8'))
        code='\n'.join(''.join(c.get('source',[])) for c in notebook.get('cells',[]) if c.get('cell_type')=='code')
        record=dict(path=str(path),sha256=digest,
            unique_native_union_expression_observed="raw_flows['flow_id'].isin(native_membership['flow_id'].unique())" in code,
            ecdf_float_conversion_observed='np.sort(np.asarray(values, dtype=float))' in code,
            median_call_observed="survivors['packet_count'].median()" in code,
            prefix_median_distribution_is_separate='per_prefix_condition_summary' in code)
        if sha256_file(path)!=digest:raise ValueError('Notebook archive changed during source audit')
        records.append(record);tracked[str(path)]=digest
    return dict(status='source_inspected' if records else 'archives_unavailable',sources=records,tracked_files=tracked,
                evidence='Static current archive only; no historical dataset, publication median or Notebook execution authenticated.',
                quantile_note='Current quantiles: linear (n-1)*q; archived median calls and ECDF float casts recorded separately. Prefix-median distributions are not the union distribution.')
