# Agurim prime local source fork

This directory is the durable, parent-repository-managed local fork of
`necoma/agurim` at upstream commit
`ab5c5cc80e9e1229bb66ec83bb25f186898d5e49`. `flow-mode.patch` contains all
fork source changes. No change is stored solely in the submodule working tree.
The upstream BSD-style copyright notices remain in the extracted source;
the builder copies the upstream `LICENSE` into every output bundle.

Build from the repository root:

```sh
.venv/bin/python scripts/build_agurim_prime.py --output-dir build/agurim-prime
```

The destination must be new. The builder extracts the pinned Git objects from
`vendor/agurim`, applies the tracked patch, and compiles a separate `agurim`.
It does not alter submodule files, Git configuration, index, branches or history,
and never downloads anything. `cc` and `patch` must be installed. Build manifests
record upstream commit, patch checksum, all materialized source checksums,
compiler, fork identity and executable checksum. `fork_commit` is explicitly
null because this local patch fork has not been committed or published.

## Supported independent flow mode

```sh
build/agurim-prime/agurim -F -m flow -t 1 -n 0 < canonical.aguri-flow
```

`-D` and `-D -D` retain the upstream label/subattribute heuristic switches.
Other options, file arguments, noninteger/out-of-range thresholds and top-k are
rejected in flow mode. The flow input is the upstream 56-byte `aguri_flow`
network-order structure. Each canonical bidirectional IPv4 TCP/UDP flow must
appear exactly once, in first-observed endpoint direction, with positive packet
count. The C reader validates scope, framing and positive packet counts, but
deduplication/canonical identity belongs to the CSV converter. It does not infer
reverse flow identity or packet direction. It rejects IPv6 and other protocols.

A separate uint64 `flow` counter is incremented by one per record and propagated
through OD/protocol hashes, RLS roots, aggregation, extraction discounts and
ancestor residual updates. It has its own total and threshold. Packet and byte
counters retain their real meanings. Flow mode uses the unchanged RLS search,
label heuristics, threshold rounding `ceil(total * percent / 100)`, wildcard
retention and protocol threshold multiplier. Protocol output is not exposed by
the flow CSV. Upstream byte/packet modes retain their existing text interface.

Flow output is CSV with columns:

```text
aggregate_id,src_prefix,dst_prefix,discounted_flow_count,flow_ratio,discounted_bytes,discounted_packets
```

All prefix lengths, including /0 and /32, are explicit. `flow_ratio` is a percent
of the input canonical flow total. Counts are discounted HHH counts: descendants
already extracted have been removed. They are not original prefix populations.
Compute actual native-/24 distributions and OR endpoint membership separately
from the original canonical CSV; never substitute the discounted count.

## Future committed fork/submodule migration

No remote fork or commit was created, as requested. The local source-fork
identity is the pinned upstream commit plus SHA-256 of this patch; it remains
reviewable and reproducible before commits are authorized. When the human is
ready to publish: create a separate fork of the upstream repository, apply the
patch at the pinned upstream commit, run the full regression suite, commit in
that fork and push the commit. Then update `.gitmodules` to that fork URL and
update the parent gitlink to the exact fork commit in a reviewed change. Update
the builder and provenance schema together to record the actual fork commit.
Do not merely edit the submodule without a committed fork pointer: parent Git
would only retain a dirty gitlink and lose the patch on a fresh clone.

The patch-based build is intentionally kept distinct from the existing pinned
Agurim installation, caches and run conditions. No original executable or
artifact is replaced. Tests in `tests/test_agurim_prime_fork.py` compile pinned
upstream and fork binaries and exercise synthetic record comparisons.
