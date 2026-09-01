# Implementation Ledger

## 2026-09-01 — Flow-stage memory reduction

- Scope: M0–M4 flow extraction only; no timeout-policy, scan, prefix, or M5 behavior changes.
- Root cause: the flow stage first materialized every accumulator as a canonical row dictionary and then materialized a second full list after adding `observed_tcp_pattern`. On `202604081400`, this peak duplication contributed to the Linux OOM-killer termination.
- Decision: retain all accumulators until EOF when timeout is disabled, preserving one bidirectional 5-tuple through the capture. The flow stage now consumes the aggregated accumulator sequence once: `as_row()` → observed TCP-pattern derivation → atomic `csv.DictWriter.writerow()`. The public row-materializing parser remains for callers that need it; the cache stage bypasses it. `Endpoint`, `FlowKey`, and `_FlowAccumulator` use slots to reduce per-flow Python object overhead without changing their values or identity rules.
- Compatibility: `flows-v3`, cache fingerprint inputs, CSV schema/column order, deterministic flow IDs/row order, byte and TCP-control facts, packet-skip provenance, and atomic CSV/manifest behavior are unchanged. No schema-version bump is needed because the on-disk artifact is byte-identical on the canonical fixture.
- Verification: focused flow-stage/flow/timeout/TCP-control suite (24 passed); full `uv run pytest` (175 passed). The new flow-stage regression asserts that the stage no longer imports the row-materializing parser and that its fixture CSV has the pre-change SHA-256 `d0c14db6a3bf8db3e7c710ddbb602d7f3609161d583613fdc478f96feb4fecbc`.

## 2026-08-31 — Capture-truncated packet compatibility

- Scope: M0–M4 flow extraction only; no M5 thresholding or removal behavior.
- Root cause: a structurally valid PCAP record can have `caplen < original length` because capture snaplen truncates an IPv6 fragment/extension-header chain. The parser previously treated the resulting undecodable Ethernet/IPv6 payload as malformed IP and aborted.
- Decision: retain hard failures for PCAP/PCAPNG header, record, block, and length-structure errors. Skip only capture-truncated IPv4/IPv6 packets that cannot provide a trustworthy TCP/UDP 5-tuple, recording `capture_truncated_undecodable` in `flow_manifest.json`.
- Cache/provenance: flow schema is `flows-v3`; old caches are not reused. Reused v3 manifests must contain valid packet-skip provenance.
- Verification: `uv run pytest tests/unit/test_flow.py tests/integration/test_flow_stage.py tests/unit/test_hashing.py -v` (20 passed); `uv run pytest` (174 passed).
