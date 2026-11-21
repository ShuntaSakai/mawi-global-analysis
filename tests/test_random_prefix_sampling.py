import importlib
from ipaddress import IPv4Network
import pytest


def api():
    try: return importlib.import_module('mawi_global_analysis.random_prefix_selection.sampling')
    except ModuleNotFoundError: pytest.fail('random sampling module missing')


def candidates(): return [IPv4Network(f'10.0.{i}.0/24') for i in range(40)]


def test_rank_is_reproducible_and_input_order_independent():
    s = api(); values = candidates()
    a = s.select_prefixes(values, count=18, seed=20260408)
    assert a == s.select_prefixes(reversed(values), count=18, seed=20260408)
    assert len(a) == len(set(a)) == 18
    b = s.select_prefixes(values, count=18, seed=9)
    assert b != a and b == s.select_prefixes(values, count=18, seed=9)


def test_hash_bytes_golden():
    # Golden value filled from an independent shell SHA-256 calculation.
    assert api().score_prefix(IPv4Network('192.0.2.0/24'), 20260408).hex() == 'd3f81cfdce806ad4c5c30a2cd4fa304469c169c7eef3693cda8d8351c35718b1'


@pytest.mark.parametrize('seed', [-1, True, 1.5, '1', 2**64])
def test_invalid_seed(seed):
    with pytest.raises(ValueError): api().select_prefixes(candidates(), count=18, seed=seed)


@pytest.mark.parametrize('count', [0, -1, True, 1.5, 41])
def test_invalid_count_or_shortage(count):
    with pytest.raises(ValueError): api().select_prefixes(candidates(), count=count, seed=1)


def test_duplicates_and_non24_rejected():
    for values in [[*candidates(), candidates()[0]], [IPv4Network('192.0.2.0/25')]]:
        with pytest.raises(ValueError): api().select_prefixes(values, count=1, seed=1)


def test_tie_break_and_set_hash_order(monkeypatch):
    s = api(); monkeypatch.setattr(s, 'score_prefix', lambda p, seed: b'0'*32)
    assert s.select_prefixes(reversed(candidates()), count=2, seed=0) == tuple(candidates()[:2])
    assert s.prefix_hash(candidates()) == s.prefix_hash(reversed(candidates()))
    assert s.prefix_hash(candidates(), ranked=True) != s.prefix_hash(reversed(candidates()), ranked=True)
