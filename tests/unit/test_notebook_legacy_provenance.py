import json
from pathlib import Path


def test_legacy_notebook_reads_nested_manifest_provenance() -> None:
    """Legacy notebook provenance must match the run manifest schema."""
    notebook = json.loads(
        (Path(__file__).parents[2] / "notebooks" / "00_paper_legacy_reproduction.ipynb").read_text()
    )
    source = "".join(notebook["cells"][1]["source"])

    assert "manifest.get('config', {}).get('hash')" in source
    assert "manifest.get('input', {}).get('sha256')" in source
