import importlib
import json
import pytest
from test_random_prefix_validation import source_runs, compiled_two


def api():
    try: return importlib.import_module('mawi_global_analysis.random_prefix_selection.cli')
    except ModuleNotFoundError: pytest.fail('random CLI missing')


def test_audit_resolves_manifest_paths_without_write(source_runs,capsys):
    root,flows=source_runs
    assert api().main(['audit-inputs','--root',str(root),'--dataset','fixture','--flow-run','flow','--packet-run','packet','--json'])==0
    v=json.loads(capsys.readouterr().out)
    assert v['source']['path']==str(flows) and v['runs']['flow']['selected_count']==18


@pytest.mark.parametrize('args', [['--seed','-1'],['--seed',str(2**64)],['--count','0'],['--chunksize','0'],['--run','../bad']])
def test_cli_errors_return_two(source_runs,args):
    root,flows=source_runs
    with pytest.raises(SystemExit) as exc:
        api().main(['run','--root',str(root),'--dataset','fixture','--flows',str(flows),'--flow-run','flow','--packet-run','packet','--run','invalid',*args])
    assert exc.value.code==2
