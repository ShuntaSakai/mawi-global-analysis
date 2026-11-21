"""Portable versioned SHA-256 pseudorandom ranks (no PRNG state)."""
from __future__ import annotations

import hashlib
import heapq
from collections.abc import Iterable
from ipaddress import IPv4Network

ALGORITHM = 'mawi-random24-sha256-v1'


def validate_settings(count: int, seed: int) -> None:
    if type(count) is not int or count < 1:
        raise ValueError('count must be a positive integer')
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError('seed must be an unsigned 64-bit integer')


def score_prefix(prefix: IPv4Network, seed: int) -> bytes:
    validate_settings(1, seed)
    _require24(prefix)
    return hashlib.sha256(ALGORITHM.encode('ascii') + b'\0' + seed.to_bytes(8, 'big')
                          + prefix.network_address.packed).digest()


def _require24(prefix: IPv4Network) -> None:
    if not isinstance(prefix, IPv4Network) or prefix.prefixlen != 24:
        raise ValueError('candidate must be an IPv4 /24 network')


def select_prefixes(candidates: Iterable[IPv4Network], *, count: int, seed: int) -> tuple[IPv4Network, ...]:
    validate_settings(count, seed)
    # A 2 MiB bitset bounds duplicate detection over the entire IPv4 /24 space.
    seen = bytearray(2**21)
    n = 0

    def ranked():
        nonlocal n
        for prefix in candidates:
            _require24(prefix)
            address = int(prefix.network_address)
            index = address >> 8
            bucket, bit = divmod(index, 8)
            if seen[bucket] & (1 << bit):
                raise ValueError('duplicate candidate /24')
            seen[bucket] |= 1 << bit
            n += 1
            yield score_prefix(prefix, seed), address, prefix

    chosen = heapq.nsmallest(count, ranked())
    if n < count:
        raise ValueError(f'insufficient eligible candidates: need {count}, found {n}')
    return tuple(row[2] for row in chosen)


def prefix_hash(prefixes: Iterable[IPv4Network], *, ranked: bool = False) -> str:
    # Unranked callers stream numeric ascending sets from SQLite. General callers
    # also accept arbitrary order; a fixed bitset avoids an unbounded Python set.
    digest = hashlib.sha256(b'mawi-random24-selection-v1\0' if ranked else b'mawi-random24-set-v1\0')
    if ranked:
        for prefix in prefixes:
            _require24(prefix)
            digest.update(prefix.network_address.packed)
    else:
        bits = bytearray(2**21)
        for prefix in prefixes:
            _require24(prefix)
            i = int(prefix.network_address) >> 8
            bits[i >> 3] |= 1 << (i & 7)
        for bucket, flags in enumerate(bits):
            if flags:
                for bit in range(8):
                    if flags & (1 << bit):
                        digest.update(((bucket * 8 + bit) << 8).to_bytes(4, 'big'))
    return digest.hexdigest()
