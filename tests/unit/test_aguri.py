from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

from mawi_global_analysis.aguri import parse_aguri_output, resolve_aguri_binaries


def test_parse_aguri_output_preserves_aggregate_and_protocol_fields() -> None:
    rows = parse_aguri_output(
        """
% agurim output header
[ 12] 192.0.2.0/24 198.51.100.0/24: 1,234 (12.50%) 56 (7.25%)
  [6:443:50123] 10.00% 5.00% [17:53:53000] 2.50% 2.25%
"""
    )

    assert rows == [
        {
            "aggregate_id": "12",
            "src_prefix": "192.0.2.0/24",
            "dst_prefix": "198.51.100.0/24",
            "bytes": "1234",
            "byte_ratio": "12.50",
            "packets": "56",
            "packet_ratio": "7.25",
            "tcp_byte_ratio": "10.00",
            "tcp_packet_ratio": "5.00",
            "udp_byte_ratio": "2.50",
            "udp_packet_ratio": "2.25",
            "protocol_breakdown": "[6:443:50123] 10.00% 5.00% [17:53:53000] 2.50% 2.25%",
        }
    ]


def test_resolve_aguri_binaries_prefers_vendor_binaries(tmp_path) -> None:
    vendor_src = tmp_path / "vendor" / "agurim" / "src"
    vendor_src.mkdir(parents=True)
    for name in ("aguri3", "agurim"):
        executable = vendor_src / name
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)

    binaries = resolve_aguri_binaries(
        SimpleNamespace(aguri3_executable=None, agurim_executable=None), root=tmp_path
    )

    assert binaries.aguri3 == vendor_src / "aguri3"
    assert binaries.agurim == vendor_src / "agurim"
    assert binaries.aguri3_source == "vendor"
    assert binaries.agurim_source == "vendor"
    assert not binaries.used_path_fallback


def test_parse_real_pinned_agurim_fixture() -> None:
    output = Path("tests/fixtures/aguri/tcp_patterns.agurim.txt").read_text(
        encoding="utf-8"
    )

    rows = parse_aguri_output(output)

    assert len(rows) == 12
    assert rows[0] == {
        "aggregate_id": "1",
        "src_prefix": "198.51.100.30",
        "dst_prefix": "192.0.2.30",
        "bytes": "167",
        "byte_ratio": "19.74",
        "packets": "3",
        "packet_ratio": "20.00",
        "tcp_byte_ratio": "100.00",
        "tcp_packet_ratio": "100.00",
        "udp_byte_ratio": "0.00",
        "udp_packet_ratio": "0.00",
        "protocol_breakdown": "[6:40002:8080] 100.00% 100.00%",
    }
    assert rows[2]["udp_packet_ratio"] == "100.00"


def test_parse_aguri_output_rejects_unparsed_non_metadata_line() -> None:
    with pytest.raises(ValueError, match="unparsed Agurim output at line 3"):
        parse_aguri_output(
            """
[ 1] 192.0.2.0/24 198.51.100.0/24: 100 (100.00%) 2 (100.00%)
semantic-loss-is-not-valid-output
"""
        )


def test_parse_aguri_output_rejects_malformed_protocol_continuation() -> None:
    with pytest.raises(ValueError, match="unparsed Agurim output at line 3"):
        parse_aguri_output(
            """
[ 1] 192.0.2.0/24 198.51.100.0/24: 100 (100.00%) 2 (100.00%)
  [6:443:50123] malformed-ratios
"""
        )
