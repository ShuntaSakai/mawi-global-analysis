import json
from pathlib import Path


NOTEBOOK_PATH = Path(__file__).parents[2] / "notebooks" / "05_one_packet_context.ipynb"


def _notebook() -> dict[str, object]:
    return json.loads(NOTEBOOK_PATH.read_text(encoding="utf-8"))


def _notebook_source() -> str:
    notebook = _notebook()
    return "\n".join("".join(cell["source"]) for cell in notebook["cells"])


def test_one_packet_context_notebook_is_valid_and_uses_manifest_loader() -> None:
    notebook = _notebook()
    source = _notebook_source()

    assert notebook["nbformat"] == 4
    assert "from mawi_global_analysis.io import load_one_packet_context" in source
    assert "load_one_packet_context(dataset_id, context_run_name, root=root)" in source
    assert "pd.read_csv" not in source
    assert "dpkt" not in source
    assert ".pcap" not in source.lower()


def test_one_packet_context_notebook_has_explicit_inputs_and_required_sections() -> None:
    source = _notebook_source()

    assert "MAWI_ANALYSIS_ROOT" in source
    assert "MAWI_DATASET_ID" in source
    assert "MAWI_CONTEXT_RUN_NAME" in source
    assert "## 1. Provenance and cohort sanity checks" in source
    assert "## 2. Protocol composition" in source
    assert "## 3. Exact TCP flag composition" in source
    assert "## 4. Destination-port composition" in source
    assert "## 5. One-packet size characteristics" in source
    assert "## 6. Same-5-tuple 24h context" in source
    assert "## 7. Temporal context" in source
    assert "## 8. 15-minute window-boundary context" in source
    assert "## 9. Plain-SYN source context" in source
    assert "## 10. Compact observational summary" in source


def test_one_packet_context_notebook_keeps_observations_descriptive() -> None:
    source = _notebook_source()

    assert "captured_frame_length" in source
    assert "original_frame_length" in source
    assert "same_5tuple_packet_count_24h" in source
    assert "source_context_applicable" in source
    assert "Interpret after real-data execution." in source
    assert "malicious" not in source.lower()
    assert "benign" not in source.lower()
