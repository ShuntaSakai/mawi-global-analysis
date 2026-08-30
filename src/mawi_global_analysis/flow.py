"""Canonical bidirectional TCP/UDP flow extraction from Ethernet PCAPs."""

from __future__ import annotations

import gzip
import ipaddress
import socket
import struct
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

import dpkt


TCP_PROTOCOL = dpkt.ip.IP_PROTO_TCP
UDP_PROTOCOL = dpkt.ip.IP_PROTO_UDP
SUPPORTED_PROTOCOLS = (TCP_PROTOCOL, UDP_PROTOCOL)
_GZIP_MAGIC = b"\x1f\x8b"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapParseError(ValueError):
    """Raised when a capture cannot be trusted as a complete readable PCAP."""


@dataclass(frozen=True)
class Endpoint:
    """One IP-and-port endpoint in a normalized flow key."""

    ip: str
    port: int


@dataclass(frozen=True)
class FlowKey:
    """Direction-independent TCP/UDP 5-tuple key."""

    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: int

    @classmethod
    def from_packet(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: int,
    ) -> "FlowKey":
        """Create one stable key shared by packets in either direction."""
        src_address = ipaddress.ip_address(src_ip)
        dst_address = ipaddress.ip_address(dst_ip)
        if src_address.version != dst_address.version:
            raise ValueError("flow endpoints must use the same IP version")
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"unsupported transport protocol: {protocol}")

        endpoints = (
            (src_address.packed, src_port, Endpoint(str(src_address), src_port)),
            (dst_address.packed, dst_port, Endpoint(str(dst_address), dst_port)),
        )
        first, second = sorted(endpoints, key=lambda item: (item[0], item[1]))
        return cls(endpoint_a=first[2], endpoint_b=second[2], protocol=protocol)


@dataclass
class _FlowAccumulator:
    flow_id: int
    ip_version: int
    protocol: int
    start_time: float
    end_time: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packet_count: int = 0
    frame_byte_count: int = 0
    ip_byte_count: int = 0
    transport_payload_byte_count: int = 0
    packets_from_src: int = 0
    packets_from_dst: int = 0
    bytes_from_src: int = 0
    bytes_from_dst: int = 0
    last_seen: float = 0.0
    initial_syn_sender_ip: str | None = None
    initial_syn_sender_port: int | None = None
    initial_syn_receiver_ip: str | None = None
    initial_syn_receiver_port: int | None = None
    first_syn_time: float | None = None
    syn_from_initiator: int = 0
    syn_from_responder: int = 0
    synack_from_initiator: int = 0
    synack_from_responder: int = 0
    rst_from_initiator: int = 0
    rst_from_responder: int = 0
    first_responder_synack_time: float | None = None
    first_responder_rst_time: float | None = None
    first_initiator_rst_time: float | None = None
    ack_after_synack_observed: bool = False
    non_syn_response_observed: bool = False
    transport_payload_observed: bool = False
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    rst_count: int = 0

    def add_packet(
        self,
        *,
        timestamp: float,
        packet_src_ip: str,
        packet_src_port: int,
        frame_bytes: int,
        ip_bytes: int,
        payload_bytes: int,
        tcp_flags: int | None,
    ) -> None:
        self.end_time = timestamp
        self.last_seen = timestamp
        self.packet_count += 1
        self.frame_byte_count += frame_bytes
        self.ip_byte_count += ip_bytes
        self.transport_payload_byte_count += payload_bytes

        if (packet_src_ip, packet_src_port) == (self.src_ip, self.src_port):
            self.packets_from_src += 1
            self.bytes_from_src += frame_bytes
        else:
            self.packets_from_dst += 1
            self.bytes_from_dst += frame_bytes

        if self.protocol != TCP_PROTOCOL or tcp_flags is None:
            return
        if payload_bytes:
            self.transport_payload_observed = True

        is_plain_syn = bool(tcp_flags & dpkt.tcp.TH_SYN) and not bool(
            tcp_flags & dpkt.tcp.TH_ACK
        )
        if tcp_flags & dpkt.tcp.TH_SYN:
            self.syn_count += 1
        if tcp_flags & dpkt.tcp.TH_SYN and tcp_flags & dpkt.tcp.TH_ACK:
            self.syn_ack_count += 1
        if tcp_flags & dpkt.tcp.TH_ACK:
            self.ack_count += 1
        if tcp_flags & dpkt.tcp.TH_RST:
            self.rst_count += 1
        if self.initial_syn_sender_ip is None:
            if not is_plain_syn:
                return
            self.initial_syn_sender_ip = packet_src_ip
            self.initial_syn_sender_port = packet_src_port
            self.initial_syn_receiver_ip = self.dst_ip if (
                packet_src_ip,
                packet_src_port,
            ) == (self.src_ip, self.src_port) else self.src_ip
            self.initial_syn_receiver_port = self.dst_port if (
                packet_src_ip,
                packet_src_port,
            ) == (self.src_ip, self.src_port) else self.src_port
            self.first_syn_time = timestamp

        from_initiator = (packet_src_ip, packet_src_port) == (
            self.initial_syn_sender_ip,
            self.initial_syn_sender_port,
        )
        if is_plain_syn:
            if from_initiator:
                self.syn_from_initiator += 1
            else:
                self.syn_from_responder += 1
        elif tcp_flags & dpkt.tcp.TH_SYN and tcp_flags & dpkt.tcp.TH_ACK:
            if from_initiator:
                self.synack_from_initiator += 1
            else:
                self.synack_from_responder += 1
                if self.first_responder_synack_time is None:
                    self.first_responder_synack_time = timestamp

        if tcp_flags & dpkt.tcp.TH_RST:
            if from_initiator:
                self.rst_from_initiator += 1
                if self.first_initiator_rst_time is None:
                    self.first_initiator_rst_time = timestamp
            else:
                self.rst_from_responder += 1
                if self.first_responder_rst_time is None:
                    self.first_responder_rst_time = timestamp

        if not from_initiator and not is_plain_syn:
            self.non_syn_response_observed = True
        if (
            from_initiator
            and self.first_responder_synack_time is not None
            and timestamp >= self.first_responder_synack_time
            and tcp_flags & dpkt.tcp.TH_ACK
            and not tcp_flags & dpkt.tcp.TH_SYN
            and not tcp_flags & dpkt.tcp.TH_RST
        ):
            self.ack_after_synack_observed = True

    def as_row(self) -> dict[str, object]:
        return {
            "flow_id": self.flow_id,
            "ip_version": self.ip_version,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.end_time - self.start_time,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "packet_count": self.packet_count,
            "byte_count": self.frame_byte_count,
            "frame_byte_count": self.frame_byte_count,
            "ip_byte_count": self.ip_byte_count,
            "transport_payload_byte_count": self.transport_payload_byte_count,
            "packets_from_src": self.packets_from_src,
            "packets_from_dst": self.packets_from_dst,
            "bytes_from_src": self.bytes_from_src,
            "bytes_from_dst": self.bytes_from_dst,
            "initial_syn_sender_ip": self.initial_syn_sender_ip,
            "initial_syn_sender_port": self.initial_syn_sender_port,
            "initial_syn_receiver_ip": self.initial_syn_receiver_ip,
            "initial_syn_receiver_port": self.initial_syn_receiver_port,
            "first_syn_time": self.first_syn_time,
            "syn_from_initiator": self.syn_from_initiator,
            "syn_from_responder": self.syn_from_responder,
            "synack_from_initiator": self.synack_from_initiator,
            "synack_from_responder": self.synack_from_responder,
            "rst_from_initiator": self.rst_from_initiator,
            "rst_from_responder": self.rst_from_responder,
            "first_responder_synack_time": self.first_responder_synack_time,
            "first_responder_rst_time": self.first_responder_rst_time,
            "first_initiator_rst_time": self.first_initiator_rst_time,
            "ack_after_synack_observed": self.ack_after_synack_observed,
            "non_syn_response_observed": self.non_syn_response_observed,
            "transport_payload_observed": self.transport_payload_observed,
            "syn_count": self.syn_count,
            "syn_ack_count": self.syn_ack_count,
            "ack_count": self.ack_count,
            "rst_count": self.rst_count,
        }


def _open_capture(path: Path) -> AbstractContextManager[BinaryIO]:
    with path.open("rb") as raw_capture:
        has_gzip_magic = raw_capture.read(len(_GZIP_MAGIC)) == _GZIP_MAGIC
    if path.suffix.lower() == ".gz" or has_gzip_magic:
        return gzip.open(path, "rb")
    return path.open("rb")


def _strict_pcap_packets(
    capture: BinaryIO, reader: dpkt.pcap.Reader
) -> Iterator[tuple[float, bytes]]:
    """Iterate PCAP records while detecting short record headers and bodies."""
    packet_header_type = reader._Reader__ph  # type: ignore[attr-defined]
    packet_header_size = packet_header_type.__hdr_len__
    divisor = reader._divisor  # type: ignore[attr-defined]
    packet_index = 0

    while True:
        header_bytes = capture.read(packet_header_size)
        if not header_bytes:
            return
        packet_index += 1
        if len(header_bytes) != packet_header_size:
            raise PcapParseError(
                f"truncated PCAP packet header at packet {packet_index}"
            )

        try:
            header = packet_header_type(header_bytes)
        except dpkt.dpkt.Error as exc:
            raise PcapParseError(
                f"malformed PCAP packet header at packet {packet_index}"
            ) from exc

        frame = capture.read(header.caplen)
        if len(frame) != header.caplen:
            raise PcapParseError(
                f"truncated PCAP packet data at packet {packet_index}: "
                f"expected {header.caplen} bytes, got {len(frame)}"
            )
        timestamp = float(header.tv_sec + (header.tv_usec / divisor))
        yield timestamp, frame


def _validate_pcapng_packet_lengths(
    block_bytes: bytes,
    block_length: int,
    byte_order: str,
    packet_index: int,
) -> None:
    """Reject packet blocks whose declared frame bytes cannot fit the block."""
    packet_data_offset = 28
    trailing_length_size = 4
    minimum_packet_block_length = packet_data_offset + trailing_length_size
    if block_length < minimum_packet_block_length:
        raise PcapParseError(
            f"malformed PCAPNG packet block at packet {packet_index}: "
            "packet header is truncated"
        )

    caplen, original_length = struct.unpack_from(f"{byte_order}II", block_bytes, 20)
    if caplen > original_length:
        raise PcapParseError(
            f"malformed PCAPNG packet block at packet {packet_index}: "
            f"caplen {caplen} exceeds original length {original_length}"
        )

    padded_caplen = (caplen + 3) & ~3
    available_packet_region = (
        block_length - packet_data_offset - trailing_length_size
    )
    if padded_caplen > available_packet_region:
        raise PcapParseError(
            f"malformed PCAPNG packet block at packet {packet_index}: "
            f"padded caplen {padded_caplen} exceeds available packet region "
            f"{available_packet_region}"
        )


def _strict_pcapng_packets(
    capture: BinaryIO, reader: dpkt.pcapng.Reader
) -> Iterator[tuple[float, bytes]]:
    """Iterate PCAPNG records while detecting truncated or malformed blocks."""
    little_endian = reader._Reader__le  # type: ignore[attr-defined]
    byte_order = "<" if little_endian else ">"
    divisor = reader._divisor  # type: ignore[attr-defined]
    timestamp_offset = reader._tsoffset  # type: ignore[attr-defined]
    packet_index = 0

    while True:
        block_header = capture.read(8)
        if not block_header:
            return
        if len(block_header) != 8:
            raise PcapParseError("truncated PCAPNG block header")

        block_type, block_length = struct.unpack(f"{byte_order}II", block_header)
        if block_length < 12 or block_length % 4:
            raise PcapParseError("malformed PCAPNG block length")
        block_data = capture.read(block_length - len(block_header))
        if len(block_data) != block_length - len(block_header):
            raise PcapParseError("truncated PCAPNG block data")
        if struct.unpack(f"{byte_order}I", block_data[-4:])[0] != block_length:
            raise PcapParseError("malformed PCAPNG block length")

        if block_type not in (dpkt.pcapng.PCAPNG_BT_EPB, dpkt.pcapng.PCAPNG_BT_PB):
            continue
        packet_index += 1
        block_bytes = block_header + block_data
        _validate_pcapng_packet_lengths(
            block_bytes, block_length, byte_order, packet_index
        )
        try:
            block_class = (
                dpkt.pcapng.EnhancedPacketBlockLE
                if little_endian
                else dpkt.pcapng.EnhancedPacketBlock
            )
            if block_type == dpkt.pcapng.PCAPNG_BT_PB:
                block_class = (
                    dpkt.pcapng.PacketBlockLE
                    if little_endian
                    else dpkt.pcapng.PacketBlock
                )
            packet_block = block_class(block_bytes)
        except (dpkt.dpkt.Error, ValueError) as exc:
            raise PcapParseError(
                f"malformed PCAPNG packet block at packet {packet_index}"
            ) from exc

        timestamp = timestamp_offset + (
            ((packet_block.ts_high << 32) | packet_block.ts_low) / divisor
        )
        yield timestamp, packet_block.pkt_data


def _decode_packet(
    frame: bytes, packet_index: int
) -> tuple[int, int, str, int, str, int, int, int, int | None] | None:
    try:
        ethernet = dpkt.ethernet.Ethernet(frame)
    except (dpkt.dpkt.Error, ValueError, IndexError) as exc:
        raise PcapParseError(
            f"malformed Ethernet frame at packet {packet_index}"
        ) from exc

    network = ethernet.data
    if not isinstance(network, (dpkt.ip.IP, dpkt.ip6.IP6)):
        if ethernet.type in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6):
            raise PcapParseError(
                f"malformed IP packet at packet {packet_index}"
            )
        return None

    ip_version = 4 if isinstance(network, dpkt.ip.IP) else 6
    transport = network.data
    if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        protocol = network.p if isinstance(network, dpkt.ip.IP) else network.nxt
        if protocol in SUPPORTED_PROTOCOLS:
            if isinstance(network, dpkt.ip.IP) and network.offset:
                return None
            raise PcapParseError(
                f"malformed TCP/UDP packet at packet {packet_index}"
            )
        return None

    protocol = TCP_PROTOCOL if isinstance(transport, dpkt.tcp.TCP) else UDP_PROTOCOL
    address_family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    try:
        src_ip = socket.inet_ntop(address_family, network.src)
        dst_ip = socket.inet_ntop(address_family, network.dst)
    except (OSError, ValueError) as exc:
        raise PcapParseError(
            f"malformed IP address at packet {packet_index}"
        ) from exc

    return (
        ip_version,
        protocol,
        src_ip,
        int(transport.sport),
        dst_ip,
        int(transport.dport),
        len(network),
        len(transport.data),
        int(transport.flags) if isinstance(transport, dpkt.tcp.TCP) else None,
    )


def parse_pcap(
    path: Path,
    timeout: float | None,
    protocols: tuple[int, ...] = SUPPORTED_PROTOCOLS,
) -> list[dict[str, object]]:
    """Aggregate an Ethernet PCAP into first-direction canonical flow rows.

    When enabled, an inactivity gap strictly greater than ``timeout`` starts a
    new instance of the same normalized 5-tuple.
    """
    if timeout is not None and timeout <= 0:
        raise ValueError("inactive flow timeout must be greater than zero")
    selected_protocols = frozenset(protocols)
    if not selected_protocols or not selected_protocols <= frozenset(SUPPORTED_PROTOCOLS):
        raise ValueError("protocols must select one or more supported transports")

    capture_path = Path(path)
    active_flows: dict[FlowKey, _FlowAccumulator] = {}
    completed_flows: list[_FlowAccumulator] = []
    next_flow_id = 1

    try:
        with _open_capture(capture_path) as capture:
            try:
                capture_magic = capture.read(len(_PCAPNG_MAGIC))
                capture.seek(0)
                if capture_magic == _PCAPNG_MAGIC:
                    reader = dpkt.pcapng.Reader(capture)
                    packets = _strict_pcapng_packets(capture, reader)
                else:
                    reader = dpkt.pcap.Reader(capture)
                    packets = _strict_pcap_packets(capture, reader)
            except (dpkt.dpkt.Error, ValueError) as exc:
                raise PcapParseError(
                    f"malformed or unreadable PCAP/PCAPNG header: {capture_path}"
                ) from exc
            if reader.datalink() != dpkt.pcap.DLT_EN10MB:
                raise PcapParseError(
                    "unsupported PCAP/PCAPNG link type "
                    f"{reader.datalink()}; Ethernet is required"
                )

            for packet_index, (timestamp, frame) in enumerate(
                packets, start=1
            ):
                decoded = _decode_packet(frame, packet_index)
                if decoded is None:
                    continue
                (
                    ip_version,
                    protocol,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    ip_bytes,
                    payload_bytes,
                    tcp_flags,
                ) = decoded
                if protocol not in selected_protocols:
                    continue
                key = FlowKey.from_packet(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                )
                flow = active_flows.get(key)
                if flow is not None and timeout is not None and (
                    timestamp - flow.last_seen > timeout
                ):
                    completed_flows.append(flow)
                    flow = None
                if flow is None:
                    flow = _FlowAccumulator(
                        flow_id=next_flow_id,
                        ip_version=ip_version,
                        protocol=protocol,
                        start_time=timestamp,
                        end_time=timestamp,
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        last_seen=timestamp,
                    )
                    active_flows[key] = flow
                    next_flow_id += 1
                flow.add_packet(
                    timestamp=timestamp,
                    packet_src_ip=src_ip,
                    packet_src_port=src_port,
                    frame_bytes=len(frame),
                    ip_bytes=ip_bytes,
                    payload_bytes=payload_bytes,
                    tcp_flags=tcp_flags,
                )
    except PcapParseError:
        raise
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise PcapParseError(f"unreadable PCAP: {capture_path}: {exc}") from exc

    return [flow.as_row() for flow in [*completed_flows, *active_flows.values()]]


def capture_start_timestamp(path: Path) -> float | None:
    """Return the first raw packet timestamp without changing flow generation.

    This deliberately examines every packet record, including frames that do
    not become TCP/UDP flows, so run-level window anchoring retains capture
    semantics without affecting the flow cache or its fingerprint.
    """
    capture_path = Path(path)
    try:
        with _open_capture(capture_path) as capture:
            try:
                capture_magic = capture.read(len(_PCAPNG_MAGIC))
                capture.seek(0)
                if capture_magic == _PCAPNG_MAGIC:
                    reader = dpkt.pcapng.Reader(capture)
                    packets = _strict_pcapng_packets(capture, reader)
                else:
                    reader = dpkt.pcap.Reader(capture)
                    packets = _strict_pcap_packets(capture, reader)
            except (dpkt.dpkt.Error, ValueError) as exc:
                raise PcapParseError(
                    f"malformed or unreadable PCAP/PCAPNG header: {capture_path}"
                ) from exc
            if reader.datalink() != dpkt.pcap.DLT_EN10MB:
                raise PcapParseError(
                    "unsupported PCAP/PCAPNG link type "
                    f"{reader.datalink()}; Ethernet is required"
                )
            first_packet = next(packets, None)
            return None if first_packet is None else first_packet[0]
    except PcapParseError:
        raise
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise PcapParseError(f"unreadable PCAP: {capture_path}: {exc}") from exc
