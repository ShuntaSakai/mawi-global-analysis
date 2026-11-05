"""Render a separate offline ABC experiment; existing dashboards stay unchanged."""
from pathlib import Path
import re

from mawi_global_analysis.rls_weight_comparison.dashboard import render_dashboard


def render(payload: dict) -> str:
    folder=Path(__file__).parent
    common=folder.parent/'rls_weight_comparison/dashboard.html'
    style=re.search(r'<style>(.*?)</style>',common.read_text(encoding='utf-8'),re.S)[1]
    template=(folder/'dashboard.html').read_text(encoding='utf-8')
    template=template.replace('__ABC_STYLE__',style).replace('__ABC_SCRIPT__',(folder/'dashboard.js').read_text(encoding='utf-8'))
    return render_dashboard(payload,template=template)
