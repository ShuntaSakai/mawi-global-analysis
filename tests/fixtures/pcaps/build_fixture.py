"""Build deterministic PCAP fixtures for flow and TCP-pattern tests."""

from __future__ import annotations

import gzip
import socket
import struct
from pathlib import Path

import dpkt


FIXTURE_DIR = Path(__file__).resolve().parent
PCAP_PATH = FIXTURE_DIR / "tcp_patterns.pcap"
GZIP_PATH = FIXTURE_DIR / "tcp_patterns.pcap.gz"
TRUNCATED_IPV6_FRAGMENT_PATH = FIXTURE_DIR / "capture_truncated_ipv6_fragment.pcap"

CLIENT_MAC = b"\x00\x11\x22\x33\x44\x55"
SERVER_MAC = b"\x66\x77\x88\x99\xaa\xbb"


def _tcp_frame(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=src_port,
        dport=dst_port,
        seq=1,
        ack=1 if flags & dpkt.tcp.TH_ACK else 0,
        flags=flags,
        data=payload,
    )
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_pton(socket.AF_INET, src_ip),
        dst=socket.inet_pton(socket.AF_INET, dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    ip.len = len(ip)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=CLIENT_MAC,
            dst=SERVER_MAC,
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
    )


def _udp6_frame(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    payload: bytes,
) -> bytes:
    udp = dpkt.udp.UDP(sport=src_port, dport=dst_port, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip6.IP6(
        src=socket.inet_pton(socket.AF_INET6, src_ip),
        dst=socket.inet_pton(socket.AF_INET6, dst_ip),
        nxt=dpkt.ip.IP_PROTO_UDP,
        hlim=64,
        data=udp,
    )
    ip.plen = len(udp)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=CLIENT_MAC,
            dst=SERVER_MAC,
            type=dpkt.ethernet.ETH_TYPE_IP6,
            data=ip,
        )
    )


def fixture_packets() -> list[tuple[float, bytes]]:
    """Return named-scenario packets in deterministic timestamp order."""
    syn = dpkt.tcp.TH_SYN
    ack = dpkt.tcp.TH_ACK
    rst = dpkt.tcp.TH_RST
    psh = dpkt.tcp.TH_PUSH

    return [
        # A: initiator SYN -> responder RST.
        (1.0, _tcp_frame("198.51.100.10", 40000, "192.0.2.10", 80, syn)),
        (1.1, _tcp_frame("192.0.2.10", 80, "198.51.100.10", 40000, rst | ack)),
        # B: initiator SYN -> SYNACK -> initiator RST.
        (2.0, _tcp_frame("198.51.100.20", 40001, "192.0.2.20", 443, syn)),
        (2.1, _tcp_frame("192.0.2.20", 443, "198.51.100.20", 40001, syn | ack)),
        (2.2, _tcp_frame("198.51.100.20", 40001, "192.0.2.20", 443, rst | ack)),
        # C: handshake followed by application payload.
        (3.0, _tcp_frame("198.51.100.30", 40002, "192.0.2.30", 8080, syn)),
        (3.1, _tcp_frame("192.0.2.30", 8080, "198.51.100.30", 40002, syn | ack)),
        (3.2, _tcp_frame("198.51.100.30", 40002, "192.0.2.30", 8080, ack)),
        (
            3.3,
            _tcp_frame(
                "198.51.100.30",
                40002,
                "192.0.2.30",
                8080,
                psh | ack,
                b"hello",
            ),
        ),
        # D: SYN with no observed response.
        (4.0, _tcp_frame("198.51.100.40", 40003, "192.0.2.40", 22, syn)),
        # E: mid-connection ACK and payload, with no observed SYN.
        (
            5.0,
            _tcp_frame(
                "198.51.100.50",
                40004,
                "192.0.2.50",
                25,
                psh | ack,
                b"mail",
            ),
        ),
        # F: one 5-tuple with an inactivity gap strictly greater than 60 s.
        (6.0, _tcp_frame("198.51.100.60", 40005, "192.0.2.60", 110, ack)),
        (66.001, _tcp_frame("192.0.2.60", 110, "198.51.100.60", 40005, ack)),
        # G: IPv6 UDP request and response exercise the other required path.
        (67.0, _udp6_frame("2001:db8::1", 53000, "2001:db8::2", 53, b"query")),
        (67.1, _udp6_frame("2001:db8::2", 53, "2001:db8::1", 53000, b"answer")),
    ]


def capture_truncated_ipv6_fragment_packets() -> list[tuple[float, bytes]]:
    """Return a normal TCP packet plus an IPv6 fragment truncated at snaplen."""
    valid_frame = fixture_packets()[0][1]
    ipv6_header = struct.pack(
        "!IHBB16s16s",
        0x60000000,
        1312,
        44,
        64,
        b"\x20\x01\x0d\xb8" + b"\x00" * 12,
        b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01",
    )
    truncated_fragment = (
        CLIENT_MAC
        + SERVER_MAC
        + struct.pack("!H", dpkt.ethernet.ETH_TYPE_IP6)
        + ipv6_header
    )
    return [(1.0, valid_frame), (2.0, truncated_fragment)]


def build_fixture() -> None:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    with PCAP_PATH.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        for timestamp, frame in fixture_packets():
            writer.writepkt(frame, ts=timestamp)
        writer.close()

    with PCAP_PATH.open("rb") as source, GZIP_PATH.open("wb") as raw_output:
        with gzip.GzipFile(fileobj=raw_output, mode="wb", mtime=0) as compressed:
            compressed.write(source.read())

    with TRUNCATED_IPV6_FRAGMENT_PATH.open("wb") as output:
        writer = dpkt.pcap.Writer(output)
        for timestamp, frame in capture_truncated_ipv6_fragment_packets():
            writer.writepkt(frame, ts=timestamp)
        writer.close()
    capture = bytearray(TRUNCATED_IPV6_FRAGMENT_PATH.read_bytes())
    first_frame_length = len(capture_truncated_ipv6_fragment_packets()[0][1])
    second_record_offset = 24 + 16 + first_frame_length
    struct.pack_into("<I", capture, second_record_offset + 12, 1366)
    TRUNCATED_IPV6_FRAGMENT_PATH.write_bytes(capture)


if __name__ == "__main__":
    build_fixture()
