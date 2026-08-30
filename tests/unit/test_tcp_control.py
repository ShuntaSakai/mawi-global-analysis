from __future__ import annotations

from pathlib import Path

from mawi_global_analysis.flow import parse_pcap


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "pcaps"
PCAP_PATH = FIXTURE_DIR / "tcp_patterns.pcap"


def _flow_for_destination_port(destination_port: int) -> dict[str, object]:
    rows = parse_pcap(PCAP_PATH, timeout=None)
    return next(row for row in rows if row["dst_port"] == destination_port)


def test_observed_plain_syn_sets_initial_endpoints_without_relabeling_direction() -> None:
    """A missing plain SYN must not be inferred from first-observed direction."""
    syn_only = _flow_for_destination_port(22)
    mid_connection = _flow_for_destination_port(25)

    assert syn_only["src_ip"] == "198.51.100.40"
    assert syn_only["initial_syn_sender_ip"] == "198.51.100.40"
    assert syn_only["initial_syn_sender_port"] == 40003
    assert syn_only["initial_syn_receiver_ip"] == "192.0.2.40"
    assert syn_only["initial_syn_receiver_port"] == 22
    assert syn_only["first_syn_time"] == 4.0
    assert syn_only["syn_from_initiator"] == 1

    assert mid_connection["src_ip"] == "198.51.100.50"
    assert mid_connection["initial_syn_sender_ip"] is None
    assert mid_connection["initial_syn_sender_port"] is None
    assert mid_connection["initial_syn_receiver_ip"] is None
    assert mid_connection["initial_syn_receiver_port"] is None
    assert mid_connection["first_syn_time"] is None
    assert mid_connection["syn_from_initiator"] == 0


def test_tcp_control_facts_classify_only_ordered_observed_patterns() -> None:
    """Payload and missing response evidence prevent over-claiming probe patterns."""
    from mawi_global_analysis.scan_patterns import classify_observed_tcp_pattern

    syn_to_rst = _flow_for_destination_port(80)
    syn_synack_rst = _flow_for_destination_port(443)
    established_payload = _flow_for_destination_port(8080)
    syn_only = _flow_for_destination_port(22)

    assert syn_to_rst["rst_from_responder"] == 1
    assert syn_to_rst["first_responder_rst_time"] == 1.1
    assert syn_to_rst["non_syn_response_observed"] is True
    assert classify_observed_tcp_pattern(syn_to_rst) == "syn_to_rst"

    assert syn_synack_rst["synack_from_responder"] == 1
    assert syn_synack_rst["first_responder_synack_time"] == 2.1
    assert syn_synack_rst["rst_from_initiator"] == 1
    assert syn_synack_rst["first_initiator_rst_time"] == 2.2
    assert syn_synack_rst["ack_after_synack_observed"] is False
    assert classify_observed_tcp_pattern(syn_synack_rst) == "syn_synack_rst"

    assert established_payload["ack_after_synack_observed"] is True
    assert established_payload["transport_payload_observed"] is True
    assert classify_observed_tcp_pattern(established_payload) == "none"

    assert syn_only["non_syn_response_observed"] is False
    assert syn_only["transport_payload_observed"] is False
    assert classify_observed_tcp_pattern(syn_only) == "syn_only_observed"


def test_tcp_flag_totals_preserve_the_legacy_selection_inputs() -> None:
    """Legacy selection needs packet-level flag totals, not inferred roles."""
    syn_to_rst = _flow_for_destination_port(80)
    syn_synack_rst = _flow_for_destination_port(443)
    established_payload = _flow_for_destination_port(8080)
    syn_only = _flow_for_destination_port(22)

    assert syn_to_rst["syn_count"] == 1
    assert syn_to_rst["syn_ack_count"] == 0
    assert syn_to_rst["ack_count"] == 1
    assert syn_to_rst["rst_count"] == 1
    assert syn_synack_rst["syn_count"] == 2
    assert syn_synack_rst["syn_ack_count"] == 1
    assert syn_synack_rst["ack_count"] == 2
    assert syn_synack_rst["rst_count"] == 1
    assert established_payload["ack_count"] >= 2
    assert syn_only["syn_count"] == 1
    assert syn_only["ack_count"] == 0


def test_udp_keeps_byte_metrics_without_tcp_control_facts() -> None:
    """A UDP payload is not an observed TCP establishment fact."""
    udp_flow = next(
        row for row in parse_pcap(PCAP_PATH, timeout=None) if row["protocol"] == 17
    )

    assert udp_flow["transport_payload_byte_count"] == 11
    assert udp_flow["initial_syn_sender_ip"] is None
    assert udp_flow["syn_from_initiator"] == 0
    assert udp_flow["transport_payload_observed"] is False
