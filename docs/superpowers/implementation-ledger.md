# Implementation Ledger

## 2026-08-31 — Capture-truncated packet compatibility

- Scope: M0–M4 flow extraction only; no M5 thresholding or removal behavior.
- Root cause: a structurally valid PCAP record can have `caplen < original length` because capture snaplen truncates an IPv6 fragment/extension-header chain. The parser previously treated the resulting undecodable Ethernet/IPv6 payload as malformed IP and aborted.
- Decision: retain hard failures for PCAP/PCAPNG header, record, block, and length-structure errors. Skip only capture-truncated IPv4/IPv6 packets that cannot provide a trustworthy TCP/UDP 5-tuple, recording `capture_truncated_undecodable` in `flow_manifest.json`.
- Cache/provenance: flow schema is `flows-v3`; old caches are not reused. Reused v3 manifests must contain valid packet-skip provenance.
- Verification: `uv run pytest tests/unit/test_flow.py tests/integration/test_flow_stage.py tests/unit/test_hashing.py -v` (20 passed); `uv run pytest` (174 passed).
