import pytest

from mawi_global_analysis.pipeline import STAGE_NAMES, build_parser


@pytest.mark.parametrize(
    "arguments",
    [[], ["--dataset", "202604081400", "--input", "trace.pcap.gz"]],
)
def test_cli_requires_exactly_one_input_mode(arguments: list[str]) -> None:
    """The parser must reject ambiguous or absent input selection."""
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(arguments)

    assert error.value.code == 2


def test_cli_exposes_all_pipeline_stages() -> None:
    parser = build_parser()
    parsed = parser.parse_args(
        ["--dataset", "202604081400", "--from", "input", "--to", "manifest"]
    )

    assert STAGE_NAMES == (
        "input",
        "flows",
        "aguri",
        "scan-stats",
        "scan-labels",
        "prefixes",
        "membership",
        "manifest",
    )
    assert parsed.from_stage == "input"
    assert parsed.to_stage == "manifest"
