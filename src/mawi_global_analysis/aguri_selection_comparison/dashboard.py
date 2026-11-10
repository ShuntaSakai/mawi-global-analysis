"""Render a separate offline ABC experiment; existing dashboards stay unchanged."""
from pathlib import Path
import re

from mawi_global_analysis.rls_weight_comparison.dashboard import render_dashboard
from .validation import CONDITIONS, CONDITIONS_V2


FOLDER=Path(__file__).parent
PREFIX_DASHBOARD='prefix_dashboard.html'


def _render(template: str, script: str, payload: dict) -> str:
    common=FOLDER.parent/'rls_weight_comparison/dashboard.html'
    style=re.search(r'<style>(.*?)</style>',common.read_text(encoding='utf-8'),re.S)[1]
    chart=(FOLDER/'ecdf_chart.js').read_text(encoding='utf-8')
    app=(FOLDER/script).read_text(encoding='utf-8')
    template=template.replace('__ABC_STYLE__',style).replace('__ABC_SCRIPT__',chart+'\n'+app)
    return render_dashboard(payload,template=template)


def render(payload: dict) -> str:
    template=(FOLDER/'dashboard.html').read_text(encoding='utf-8')
    v2=payload.get('schema_version')=='aguri-selection-analysis-v2'
    keys=CONDITIONS_V2 if v2 else CONDITIONS
    template=re.sub(r'<!-- V1 START -->(.*?)<!-- V1 END -->',
                    '' if v2 else r'\1',template,flags=re.S)
    template=template.replace('__ABC_CONDITION_LABEL__','/'.join(keys))
    template=template.replace('__ABC_CONDITION_OPTIONS__',''.join(f'<option>{key}</option>' for key in keys))
    return _render(template,'dashboard.js',payload)


def render_prefix(payload: dict, *, axis_max_packet_count: str) -> str:
    template=(FOLDER/PREFIX_DASHBOARD).read_text(encoding='utf-8')
    tabs=[]
    for key in CONDITIONS_V2:
        selected='true' if key=='A' else 'false'
        index=0 if key=='A' else -1
        tabs.append(f'<button type="button" role="tab" id="prefix-tab-{key}" data-condition="{key}" '
                    f'aria-controls="prefix-panel" aria-selected="{selected}" tabindex="{index}">{key}</button>')
    template=template.replace('__PREFIX_TABS__',''.join(tabs))
    return _render(template,'prefix_dashboard.js',{**payload,'axis_max_packet_count':axis_max_packet_count})
