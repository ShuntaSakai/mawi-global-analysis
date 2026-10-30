"""Method-independent offline presentation for a normalized-/24 Raw payload."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re

from mawi_global_analysis.hashing import sha256_file
from .analysis import HistogramSpec, analyze_agurim_run
from mawi_global_analysis.prefix_dashboard import _write_new_dashboard


def render_dashboard(data: dict) -> str:
    """Embed only escaped JSON and repository-owned JavaScript; no remote assets."""
    template_path = Path(__file__).with_suffix('.html')
    template = template_path.read_text(encoding='utf-8')
    data = {**data, 'presentation':{'template_sha256':sha256_file(template_path),
                                  'renderer_sha256':sha256_file(Path(__file__))}}
    encoded = json.dumps(data,ensure_ascii=False,allow_nan=False,separators=(',',':'))
    for char in ('&','<','>','\u2028','\u2029'):
        encoded = encoded.replace(char, f'\\u{ord(char):04x}')
    scripts = re.findall(r'<script>(.*?)</script>',template,re.S)
    if len(scripts) != 1:
        raise ValueError('one application script required')
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode('ascii')
    return template.replace('__SCRIPT_HASH__',digest).replace('__DASHBOARD_DATA__',encoded)


def export_dashboard(root: Path, dataset_id: str, run_name: str, output: Path, *,
                     chunksize: int = 100_000, scratch_dir: Path | None = None,
                     spec: HistogramSpec | None = None, progress=None) -> Path:
    """Aggregate existing CSVs and publish a new standalone HTML exactly once."""
    root,output = Path(root).expanduser().resolve(),Path(output).expanduser().resolve()
    if output.suffix.lower() != '.html':
        raise ValueError('出力先は新しい .html ファイルを指定してください')
    if output.exists():
        raise FileExistsError(f'既存ファイルは上書きしません: {output}')
    if any(output.is_relative_to(root/name) for name in ('data','results','notebooks','sources')):
        raise ValueError('入力・run・Notebook・cacheのディレクトリ内には出力できません')
    for parent in output.parents:
        if (parent/'exact_counts.sqlite').exists() or any(parent.glob('*manifest.json')):
            raise ValueError('既存run / cache内には出力できません')
    data = analyze_agurim_run(root,dataset_id,run_name,chunksize=chunksize,
                              scratch_dir=scratch_dir,spec=spec,progress=progress)
    return _write_new_dashboard(output,render_dashboard(data))
