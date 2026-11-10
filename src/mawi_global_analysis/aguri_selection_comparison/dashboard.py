"""Render a separate offline ABC experiment; existing dashboards stay unchanged."""
from pathlib import Path
import re

from mawi_global_analysis.rls_weight_comparison.dashboard import render_dashboard
from .validation import CONDITIONS, CONDITIONS_V2


def render(payload: dict) -> str:
    folder=Path(__file__).parent
    common=folder.parent/'rls_weight_comparison/dashboard.html'
    style=re.search(r'<style>(.*?)</style>',common.read_text(encoding='utf-8'),re.S)[1]
    template=(folder/'dashboard.html').read_text(encoding='utf-8')
    v2=payload.get('schema_version')=='aguri-selection-analysis-v2'
    keys=CONDITIONS_V2 if v2 else CONDITIONS
    template=re.sub(r'<!-- V1 START -->(.*?)<!-- V1 END -->',
                    '' if v2 else r'\1',template,flags=re.S)
    template=template.replace('__ABC_CONDITION_LABEL__','/'.join(keys))
    template=template.replace('__ABC_CONDITION_OPTIONS__',''.join(f'<option>{key}</option>' for key in keys))
    template=template.replace('__ABC_STYLE__',style).replace('__ABC_SCRIPT__',(folder/'dashboard.js').read_text(encoding='utf-8'))
    return render_dashboard(payload,template=template)
