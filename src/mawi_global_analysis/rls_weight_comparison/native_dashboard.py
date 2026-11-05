"""Native vocabulary and scope view over the existing safe offline renderer."""
from pathlib import Path
import re

from .dashboard import render_dashboard


def render_native_dashboard(payload: dict, *, template_transform=None) -> str:
    """Adapt trusted template text BEFORE injecting untrusted analytical values.

    The shared normalized template is unchanged. Native payloads use `prefix`,
    never `prefix_24`, and reuse its plotting/selection controllers.
    """
    folder=Path(__file__).parent
    template=(folder/'dashboard.html').read_text(encoding='utf-8')
    # Explicitly replace the scope explanation before vocabulary substitutions;
    # otherwise a parent-/24 description would falsely describe native scope.
    template=re.sub(r'<dt>Native / normalized /24</dt><dd>.*?</dd>',
        '<dt>Native prefix evaluation</dt><dd>選定されたCIDRをそのまま評価し、親/24へ拡張しません。同じ選定集合を親/24へ拡張した場合との違いはScope Comparisonで確認します。</dd>',template)
    template=template.replace("['選定normalized /24数',k=>object(modes[k]).normalized_prefix_count,int],",'')
    template=template.replace('prefix_24','prefix').replace("'normalized24'","'native_prefix'")
    template=template.replace('normalized /24','native prefix').replace('/24','prefix')
    # Restore the explicit parent /24 term in the one cross-scope explanation.
    template=template.replace('親prefix','親/24')
    template=template.replace('RLS Weight Comparison','RLS Weight Comparison · Native')
    template=template.replace('ecdf_counts.csv','native_ecdf_counts.csv').replace('modes/*/frequencies.csv','native/modes/*/frequencies.csv')
    template=template.replace('modes/&lt;mode&gt;/frequencies.csv','native/modes/&lt;mode&gt;/frequencies.csv').replace('modes/<mode>/frequencies.csv','native/modes/<mode>/frequencies.csv')
    template=template.replace('dashboard.html自身','dashboard_native.html自身')
    template=template.replace('同じcanonical入力、同じRLS条件で、選定時の重みだけを比較します。',
        '同じcanonical入力・RLS条件の保存済み選定を、native範囲で評価します。')
    template=template.replace('RLS comparison · Exact CSV','RLS native comparison · Exact CSV')
    button='<button role="tab" id="tab-scope" aria-controls="scope" aria-selected="false" tabindex="-1">Scope Comparison</button>\n'
    template=template.replace('<button role="tab" id="tab-details"',button+'<button role="tab" id="tab-details"')
    template=template.replace('<section id="details"',(folder/'native_scope.html').read_text(encoding='utf-8')+'\n<section id="details"')
    template=template.replace("['表示条件・ECDF削減設定',provenance.display]","['表示条件・ECDF削減設定',provenance.display],['Native評価の来歴と検証済み不変条件',provenance.native_extension]")
    script=(folder/'native_scope.js').read_text(encoding='utf-8')
    template=template.replace('})();\n</script>',script+'\n})();\n</script>')
    if template_transform is not None:
        template=template_transform(template)  # trusted experiment adapter, before untrusted payload insertion
    return render_dashboard(payload,template=template)
