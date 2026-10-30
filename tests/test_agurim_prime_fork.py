"""Real compiled fork tests; synthetic records are not real-data validation."""
from __future__ import annotations

import csv
import importlib.util
import io
import hashlib
import ipaddress
import json
import random
import re
import socket
import struct
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PIN = "ab5c5cc80e9e1229bb66ec83bb25f186898d5e49"
SOURCES = ("agurim.c", "odflow.c", "hhh.c", "agurim_plot.c", "agurim_subr.c")


def record(src="192.0.2.1", dst="198.51.100.1", port=12345, packets=100, byte_count=6000, protocol=6, ipv=4):
    pack = lambda ip: socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip).ljust(16, b"\0")
    return struct.pack("!16s16sHHBBHIIII", pack(src), pack(dst), port, 80, ipv, protocol, 0,
                       packets, byte_count, 1700000000, 1700000001)


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    builder_path = ROOT / "scripts/build_agurim_prime.py"
    assert builder_path.is_file(), "independent flow-mode fork builder is not implemented"
    spec = importlib.util.spec_from_file_location("prime_builder", builder_path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    directory = tmp_path_factory.mktemp("prime-c")
    binary = builder.build(directory / "fork", ROOT)
    original = directory / "original"
    original.mkdir()
    for name in (*SOURCES, "agurim.h", "aguri_flow.h"):
        data = subprocess.check_output(["git", "-C", str(ROOT / "vendor/agurim"), "show", f"{PIN}:src/{name}"])
        (original / name).write_bytes(data)
    old_binary = original / "agurim"
    subprocess.run(["cc", "-O2", "-DINET6", "-DNDEBUG", "-o", str(old_binary),
                    *(str(original / name) for name in SOURCES), "-lm"], check=True, capture_output=True)
    return binary, old_binary


def invoke(binary, data, *options):
    return subprocess.run([str(binary), "-F", *options], input=data, capture_output=True)


def flow_rows(compiled, data, threshold=1, *options):
    result = invoke(compiled[0], data, "-m", "flow", "-t", str(threshold), "-n", "0", *options)
    assert result.returncode == 0, result.stderr.decode()
    return list(csv.DictReader(io.StringIO(result.stdout.decode())))


@pytest.mark.parametrize("packets,n", [(100,1),(1,100),(1000,1)])
def test_one_record_is_one_flow_independent_of_packet_weight(compiled, packets, n):
    rows = flow_rows(compiled, b"".join(record(port=10000+i, packets=packets) for i in range(n)))
    assert sum(int(r["discounted_flow_count"]) for r in rows) == n
    assert sum(int(r["discounted_packets"]) for r in rows) == n * packets
    assert sum(int(r["discounted_bytes"]) for r in rows) == n * 6000


def test_empty_input_has_explicit_flow_csv_header(compiled):
    result = invoke(compiled[0], b"", "-m", "flow")
    assert result.returncode == 0
    assert result.stdout.decode().strip() == "aggregate_id,src_prefix,dst_prefix,discounted_flow_count,flow_ratio,discounted_bytes,discounted_packets"


def test_prefix_aggregation_conserves_flow_counts_and_is_repeatable(compiled):
    data = b"".join(record(src=f"192.0.2.{i}", port=10000+i, packets=1+i) for i in range(1,101))
    first = flow_rows(compiled, data, 20)
    assert first == flow_rows(compiled, data, 20)
    assert sum(int(r["discounted_flow_count"]) for r in first) == 100
    assert any(int(r["discounted_flow_count"]) > 1 for r in first)
    assert all("/" in r["src_prefix"] and "/" in r["dst_prefix"] for r in first)


def test_flow_mode_matches_unit_packet_probe_over_random_records(compiled):
    rng = random.Random(817)
    facts = [(f"192.0.{rng.randrange(3)}.{rng.randrange(1,240)}", f"198.51.100.{rng.randrange(1,20)}", i, rng.randrange(1,1000)) for i in range(200)]
    actual = b"".join(record(src=s, dst=d, port=10000+i, packets=p) for s,d,i,p in facts)
    unit = b"".join(record(src=s, dst=d, port=10000+i, packets=1) for s,d,i,p in facts)
    for threshold in (1,5,20,100):
        rows = flow_rows(compiled, actual, threshold)
        result = invoke(compiled[1], unit, "-m", "packet", "-t", str(threshold), "-n", "0")
        assert result.returncode == 0
        from mawi_global_analysis.aguri import parse_aguri_output
        probe = parse_aguri_output("\n".join(line for line in result.stdout.decode().splitlines() if not line.startswith("\t")))
        normalize = lambda x: "0.0.0.0/0" if x == "*" else (x if "/" in x else x+"/32")
        got = {(r["src_prefix"], r["dst_prefix"]): int(r["discounted_flow_count"]) for r in rows}
        expected = {(normalize(r["src_prefix"]),normalize(r["dst_prefix"])): int(r["packets"]) for r in probe}
        assert got == expected
        assert sum(got.values()) == len(facts)


@pytest.mark.parametrize("mode", ["byte", "packet"])
def test_legacy_modes_match_pinned_upstream(compiled, mode):
    data = b"".join(record(src=f"192.0.2.{i}", port=10000+i, packets=i+1, byte_count=60*(i+1)) for i in range(1,60))
    old = invoke(compiled[1], data, "-m", mode, "-t", "5")
    new = invoke(compiled[0], data, "-m", mode, "-t", "5")
    assert old.returncode == new.returncode == 0
    # Upstream records wall-clock processing time only in a %-prefixed preamble.
    content = lambda output: "\n".join(x for x in output.decode().splitlines() if not x.startswith("%"))
    assert content(old.stdout) == content(new.stdout)


@pytest.mark.parametrize("extra", [b"x", b"x"*55, b"x"*57])
def test_truncated_input_fails(compiled, extra):
    result = invoke(compiled[0], record()+extra, "-m", "flow")
    assert result.returncode != 0


@pytest.mark.parametrize("data", [record(protocol=1), record(ipv=6,src="2001:db8::1",dst="2001:db8::2"), record(packets=0)])
def test_out_of_scope_or_noncanonical_records_fail(compiled, data):
    result = invoke(compiled[0], data, "-m", "flow")
    assert result.returncode != 0


@pytest.mark.parametrize("options", [("-n","1"),("-t","0"),("-t","1.5"),("-t","101"),("-t","garbage"),("-i","10"),("-S","1"),("-E","9999999999"),("-s","1"),("-P",),("-p",),("-d",),("-f","192.0.2.0/24 *"),("filename",)])
def test_flow_mode_rejects_unsupported_options(compiled, options):
    result = invoke(compiled[0], record(), "-m", "flow", *options)
    assert result.returncode != 0


def test_flow_requires_binary_stdin(compiled):
    result = subprocess.run([str(compiled[0]), "-m", "flow"], input=b"", capture_output=True)
    assert result.returncode != 0


def test_builder_refuses_to_replace_an_existing_build(compiled):
    builder_path = ROOT / "scripts/build_agurim_prime.py"
    result = subprocess.run([str(ROOT/".venv/bin/python"), str(builder_path), "--output-dir", str(compiled[0].parent)], capture_output=True)
    assert result.returncode != 0


def test_discounted_parent_count_is_not_original_prefix_population(compiled):
    data = b"".join(record(src="192.0.2.1", port=10000+i) for i in range(80))
    data += b"".join(record(src="192.0.2.2" if i<10 else "192.0.2.4", port=20000+i) for i in range(20))
    rows = flow_rows(compiled, data, 20)
    parent = next(row for row in rows if row["src_prefix"] == "192.0.2.0/29")
    assert int(parent["discounted_flow_count"]) == 20
    # All original source addresses belong to this parent; its raw population is 100.
    assert all(ipaddress.ip_address(ip) in ipaddress.ip_network(parent["src_prefix"])
               for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.4"))
    assert sum(int(row["discounted_flow_count"]) for row in rows) == 100


def test_build_manifest_binds_source_patch_and_binary(compiled):
    binary = compiled[0]
    manifest = json.loads((binary.parent/"build_manifest.json").read_text())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert manifest["upstream_commit"] == PIN
    assert manifest["patch_sha256"] == digest(ROOT/"vendor/agurim-prime/flow-mode.patch")
    assert manifest["executable_sha256"] == digest(binary)
    assert manifest["fork_commit"] is None
    identity = {"upstream_commit":PIN, "patch_sha256":manifest["patch_sha256"]}
    assert manifest["fork_identity"] == hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert all(digest(binary.parent/"src"/name) == checksum for name,checksum in manifest["source_sha256"].items())
    assert (binary.parent/"LICENSE").is_file()


def test_patched_aguri3_builds_and_keeps_legacy_input_output(compiled, tmp_path):
    source = compiled[0].parent/"src"
    result = subprocess.run(["make", "-C", str(source), "aguri3"], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()
    generated = tmp_path/"fixture.agr"
    result = subprocess.run([str(source/"aguri3"), "-r", str(ROOT/"tests/fixtures/pcaps/tcp_patterns.pcap"), "-w", str(generated)], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()
    assert generated.is_file() and generated.stat().st_size > 0
    data = generated.read_bytes()
    results = [subprocess.run([str(binary), "-m", "packet"], input=data, capture_output=True)
               for binary in compiled]
    assert all(result.returncode == 0 for result in results)
    content = lambda output: "\n".join(x for x in output.decode().splitlines() if not x.startswith("%"))
    assert content(results[0].stdout) == content(results[1].stdout)
