"""Refresh a standalone dashboard from a verified saved comparison, read-only."""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import tempfile

from mawi_global_analysis.hashing import sha256_file
from mawi_global_analysis.normalized24.statistics import _new_output
from .dashboard import render_dashboard
from .generation import (_entries, _json, _prefixes, _publish, _verify_artifacts,
                         _write_text, verify_comparison_manifest)
from .metrics import MODES
from .prefix_ecdf import SCHEMA, build_prefix_ecdfs


class _Payload(HTMLParser):
    def __init__(self):
        super().__init__();self.active=False;self.parts=[];self.count=0

    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        self.active=tag=='script' and attrs.get('id')=='dashboard-data' and attrs.get('type')=='application/json'
        if self.active:self.count+=1

    def handle_data(self,text):
        if self.active:self.parts.append(text)

    def handle_endtag(self,tag):
        if tag=='script':self.active=False


def _guard_locations(base: Path, manifest: dict, output: Path, scratch: Path | None) -> None:
    """Protect the bundle and recorded/current analysis roots, even when moved.

    Recorded paths are inspected lexically; refresh never opens canonical/run
    files and remains usable without the original analysis dataset present.
    """
    roots={Path(__file__).resolve().parents[3]}
    for run in manifest.get('source_runs',{}).values():
        name=run.get('inputs',{}).get('run_manifest',{}).get('path')
        if name:
            path=Path(name).expanduser()
            if path.is_absolute() and len(path.parents)>3 and path.parents[2].name=='results':
                roots.add(path.parents[3].resolve())
    for kind,path in (('output',output),('scratch',scratch)):
        if path is None:continue
        if path.is_relative_to(base):
            raise ValueError(f'{kind} must be outside the read-only source comparison bundle')
        if any(path.is_relative_to(root/name) for root in roots
               for name in ('data','results','notebooks','sources')):
            raise ValueError(f'{kind} must be outside protected analysis data/results/notebooks/sources')


def refresh_dashboard(manifest_path: Path, output_dir: Path, *, scratch_dir: Path | None = None) -> Path:
    """Copy exact research artifacts unchanged; publish a newly hashed HTML bundle.

    No canonical input, run/cache, binary, PCAP or aggregation code is accessed.
    All source files are staged and hash-verified BEFORE display reads. A single
    manifest byte snapshot binds those copies. Source hashes are also rechecked
    before publication. Existing outputs are never overwritten.
    """
    source=Path(manifest_path).expanduser().resolve();base=source.parent
    manifest_bytes=source.read_bytes()
    source_hash=hashlib.sha256(manifest_bytes).hexdigest()
    manifest=json.loads(manifest_bytes)
    if verify_comparison_manifest(source)!=manifest:
        raise ValueError('source comparison manifest changed during snapshot')
    if manifest.get('native_extension') is not None:
        raise ValueError('native-extended bundles must be regenerated with --include-native from their normalized source')
    output=Path(output_dir).expanduser()
    if output.is_symlink():raise FileExistsError(f'existing output symlink: {output}')
    output=output.resolve()
    scratch=Path(scratch_dir).expanduser().resolve() if scratch_dir is not None else None
    _guard_locations(base,manifest,output,scratch);_new_output(base,output)
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.rls-dashboard-',dir=output.parent) as temporary:
        work=Path(temporary)
        # _verify_artifacts has rejected traversal/alias names before any copy.
        # Independent copies prevent subsequent source edits affecting this view.
        for name in manifest['artifacts']:
            target=work/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(base/name,target)
        _verify_artifacts(work,manifest['artifacts'])
        parser=_Payload();parser.feed((work/'dashboard.html').read_text(encoding='utf-8'))
        if parser.count!=1:raise ValueError('saved dashboard: expected one JSON data block')
        payload=json.loads(''.join(parser.parts))
        if not isinstance(payload,dict) or payload.get('schema_version')!='rls-weight-comparison-dashboard-v1':
            raise ValueError('saved dashboard: unsupported payload schema')
        data={mode:_json(work/'modes'/mode/'summary.json') for mode in MODES}
        _,prefixes=_prefixes(data)
        from .dashboard import _browser_numbers
        if _browser_numbers(prefixes)!=payload.get('prefixes'):
            raise ValueError('saved dashboard: prefix statistics differ from exact summaries')
        curves=build_prefix_ecdfs(work,prefixes,scratch_dir=scratch)
        payload['per_prefix_ecdf']=curves
        provenance=payload['provenance']
        provenance.setdefault('schemas',{})['per_prefix_ecdf']=SCHEMA
        settings={k:v for k,v in curves.items() if k!='curves'}
        provenance.setdefault('display',{})['per_prefix_ecdf']=settings
        implementation={name:sha256_file(Path(__file__).with_name(name)) for name in
                        ('refresh.py','prefix_ecdf.py','metrics.py','generation.py','cli.py','dashboard.py','dashboard.html')}
        refresh=dict(source_manifest_sha256=source_hash,source_manifest=str(source),
                     implementation_sha256=implementation,
                     operation='hash-verified staged snapshot; exact research artifacts copied unchanged')
        provenance['dashboard_refresh']=refresh
        (work/'dashboard.html').unlink()
        provenance['artifacts']=_entries(work)
        _write_text(work/'dashboard.html',render_dashboard(payload))
        verify_comparison_manifest(source)
        if sha256_file(source)!=source_hash:raise ValueError('source comparison manifest changed during refresh')
        entries=_entries(work);_verify_artifacts(work,entries)
        for name,entry in manifest['artifacts'].items():
            if name!='dashboard.html' and entries[name]!=entry:
                raise ValueError(f'{name}: copied artifact differs from source manifest')
        manifest.update(artifacts=entries,dashboard_refresh=refresh)
        manifest.setdefault('schemas',{})['per_prefix_ecdf']=SCHEMA
        manifest.setdefault('dashboard_generation',{})['per_prefix_ecdf']=settings
        _write_text(work/'comparison_manifest.json',json.dumps(manifest,ensure_ascii=False,allow_nan=False,sort_keys=True,indent=2)+'\n')
        verify_comparison_manifest(work/'comparison_manifest.json')
        _new_output(base,output);_publish(work,output)
    return output/'comparison_manifest.json'
