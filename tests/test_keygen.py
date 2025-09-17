# pylint: disable=protected-access,missing-module-docstring
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import math
import os
import pickle
import secrets

import pytest
import sympy

from rsautils import keygen

location = os.path.dirname(__file__)
expected_primes = {}
# Load precomputed primes for referencing.
with open(os.path.join(location, "data", "primes.txt"), encoding="utf-8") as f:
    primes = f.read().splitlines()[4:-1]
    SMALL_PRIMES = []
    for line in primes:
        SMALL_PRIMES = SMALL_PRIMES + [int(entry) for entry in line.split()]

with open(os.path.join(location, "data", "rsa_primes.pickle"), "rb") as f:
    rsa_dict = pickle.load(f)

base_primetest_cases = [
    # Edge Cases (neither)
    (0, False),
    (1, False),
    # Known Primes
    (2, True),
    (3, True),
    (101, True),
    (3571, True),
    (9973, True),
    # Composite
    (4, False),
    (6, False),
    (9, False),
    # Fermat Pseudoprimes (numbers that fool naive tests)
    (341, False),  # 11 * 31
    (561, False),  # 3 * 11 * 17 (Carmichael number)
    (1105, False),  # 5 * 13 * 17 (Carmichael number)
    # Pseudo-prime (PsP)
    (121, False),
    (703, False),
    (781, False),
    (1541, False),
    (2047, False),
    (52633, False),
]

large_primetest_cases = [
    # Current Largest Known Prime
    pytest.param(2**136279841 - 1, True, marks=pytest.mark.extreme, id="LargeInt-MaxPrime"),
    # RSA PRIMES
    (rsa_dict[1024][0], True),
    (rsa_dict[1024][1], True),
    (rsa_dict[2048][0], True),
    (rsa_dict[2048][1], True),
    (rsa_dict[3072][0], True),
    (rsa_dict[3072][1], True),
    (rsa_dict[4096][0], True),
    (rsa_dict[4096][1], True),
    # RSA non-PRIMES (low multiplier)
    (rsa_dict[1024][0] * 3, False),
    (rsa_dict[1024][1] * 3, False),
    (rsa_dict[2048][0] * 3, False),
    (rsa_dict[2048][1] * 3, False),
    (rsa_dict[3072][0] * 3, False),
    (rsa_dict[3072][1] * 3, False),
    (rsa_dict[4096][0] * 3, False),
    (rsa_dict[4096][1] * 3, False)
]

rsa_composites = [
    # RSA Prime Composites
    (rsa_dict[1024][0] * rsa_dict[1024][1], False),
    (rsa_dict[1024][0] * rsa_dict[2048][1], False),
    (rsa_dict[2048][0] * rsa_dict[2048][1], False),
    (rsa_dict[2048][0] * rsa_dict[3072][1], False),
    (rsa_dict[3072][0] * rsa_dict[3072][1], False),
    (rsa_dict[3072][0] * rsa_dict[4096][1], False),
    (rsa_dict[4096][0] * rsa_dict[4096][1], False),
    # RSA non-PRIMES (probably)
    (rsa_dict[1024][0] + 4, False),
    (rsa_dict[1024][1] + 4, False),
    (rsa_dict[2048][0] + 4, False),
    (rsa_dict[2048][1] + 4, False),
    (rsa_dict[3072][0] + 4, False),
    (rsa_dict[3072][1] + 4, False),
    (rsa_dict[4096][0] + 4, False),
    (rsa_dict[4096][1] + 4, False)
]

test_sizes = [
    1024,
    2048,
    3072,
    pytest.param(4096, marks=pytest.mark.slow),
    pytest.param(7680, marks=pytest.mark.extreme),
    pytest.param(8192, marks=pytest.mark.extreme),
    pytest.param(15360, marks=pytest.mark.extreme),
]


def id_generator(param):
    if isinstance(param, int) and param > 1000000:
        return f"LargeInt-{param.bit_length()}bits"
    return str(param)


def get_expected_primes(n):
    """Helper function cutting down from SMALL_PRIMES."""
    if n not in expected_primes:
        expected = []
        for i in SMALL_PRIMES:
            if i > n:
                break
            expected.append(i)
        expected_primes[n] = expected
    return expected_primes[n]


@pytest.mark.parametrize("n", [0, 1, 2, 20, 50, 1000, 5000, 10000])
def test_sieve_sane(n):
    expected = get_expected_primes(n)
    assert keygen._sieve(n) == expected


def test_sieve_large_concrete():
    assert keygen._sieve(SMALL_PRIMES[-1]) == SMALL_PRIMES


@pytest.mark.parametrize(
    "n,expected", [(10**5, 9592),
                   (10**6, 78498), pytest.param(10**7, 664579, marks=pytest.mark.slow)])
def test_sieve_large_approx(n, expected):
    # Not the intended use of the function, but included as a sanity check.
    assert len(keygen._sieve(n)) == expected


@pytest.mark.parametrize("n", [-27358709381728, -10, -1])
def test_get_pre_primes_errors(n):
    with pytest.raises(ValueError):
        keygen.get_pre_primes(n)


def test_get_pre_primes_caches(mocker):
    mocked_primes = [2, 3, 5, 7, 11]
    mocker.patch("rsautils.keygen._sieve", return_value=mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES", [])
    mocker.patch("rsautils.keygen._SMALL_PRIMES_CAP", 0)
    n = 50

    rs = keygen.get_pre_primes(n)
    keygen._sieve.assert_called_once_with(n)
    assert rs == mocked_primes


def test_get_pre_primes_cache_hit_under(mocker):
    mocked_primes = [2, 3, 5, 7, 11]
    mocker.patch("rsautils.keygen._sieve")
    mocker.patch("rsautils.keygen._SMALL_PRIMES", mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES_CAP", 50)

    rs = keygen.get_pre_primes(25)
    keygen._sieve.assert_not_called()
    assert rs == mocked_primes


def test_get_pre_primes_cache_hit_exact(mocker):
    mocked_primes = [2, 3, 5, 7, 11]
    mocker.patch("rsautils.keygen._sieve")
    mocker.patch("rsautils.keygen._SMALL_PRIMES", mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES_CAP", 50)

    rs = keygen.get_pre_primes(50)
    keygen._sieve.assert_not_called()
    assert rs == mocked_primes


def test_get_pre_primes_cache_miss(mocker):
    mocked_primes = [2, 3, 5, 7, 11]
    greater_mocked_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    mocker.patch("rsautils.keygen._sieve", return_value=greater_mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES", mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES_CAP", 50)
    n = 75

    rs = keygen.get_pre_primes(n)
    keygen._sieve.assert_called_once_with(n)
    assert rs == greater_mocked_primes


def test_get_pre_primes_cache_forced(mocker):
    mocked_primes = [2, 3, 5, 7, 11]
    greater_mocked_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    mocker.patch("rsautils.keygen._sieve", return_value=mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES", greater_mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES_CAP", 75)
    n = 50

    rs = keygen.get_pre_primes(n, change=True)
    keygen._sieve.assert_called_with(n)
    assert rs == mocked_primes


def test_export_import_round(mocker, tmp_path):
    n = 10000
    mocked_primes = get_expected_primes(n)
    mocker.patch("rsautils.keygen._SMALL_PRIMES", mocked_primes)
    mocker.patch("rsautils.keygen._SMALL_PRIMES_CAP", n)

    sha_l, sha_g = keygen.export_primes(tmp_path / "primes.txt")
    assert os.path.isfile(tmp_path / "primes.txt")
    keygen._SMALL_PRIMES = []
    keygen._SMALL_PRIMES_CAP = 0
    keygen.import_primes(tmp_path / "primes.txt", sha_l)
    assert keygen._SMALL_PRIMES == mocked_primes
    assert keygen._SMALL_PRIMES_CAP == n
    keygen._SMALL_PRIMES = []
    keygen._SMALL_PRIMES_CAP = 0
    keygen.import_primes(tmp_path / "primes.txt", sha_g, local=False)
    assert keygen._SMALL_PRIMES == mocked_primes
    assert keygen._SMALL_PRIMES_CAP == n


@pytest.mark.parametrize("local", [False, True])
def test_import_integrity(local):
    with pytest.raises(RuntimeError):
        keygen.import_primes(__file__, "NoU", local=local)


@pytest.mark.parametrize("num,expected", base_primetest_cases + large_primetest_cases, ids=id_generator)
def test_trial_division(num, expected):
    assert keygen._trial_division(num) == expected


@pytest.mark.parametrize("n,expected", base_primetest_cases + large_primetest_cases + rsa_composites, ids=id_generator)
def test_miller_rabin(n, expected):
    assert keygen._miller_rabin(n, 5) == expected


@pytest.mark.parametrize("n,expected", base_primetest_cases + large_primetest_cases + rsa_composites, ids=id_generator)
def test_check_prime(n, expected):
    assert keygen.check_prime(n) == expected


@pytest.mark.parametrize("size", test_sizes)
def test_generate_probable_prime_size(size):
    size = size // 2
    p = keygen._generate_probable_prime(size)
    assert p.bit_length() == size
    q = keygen._generate_probable_prime(size, p)
    assert q.bit_length() == size


@pytest.mark.parametrize("size", test_sizes)
def test_generate_probable_prime_isprime(size):
    size = size // 2
    p = keygen._generate_probable_prime(size)
    assert sympy.isprime(p)
    q = keygen._generate_probable_prime(size, p)
    assert sympy.isprime(q)


@pytest.mark.parametrize("size", test_sizes)
def test_generate_probable_prime_conditions(size):
    size = size // 2
    p = keygen._generate_probable_prime(size)
    q = keygen._generate_probable_prime(size, p)
    assert math.gcd(p - 1, 65537) == 1
    assert math.gcd(q - 1, 65537) == 1
    assert p**2 > (1 << (2 * size - 1))
    assert q**2 > (1 << (2 * size - 1))


def test_generate_probably_prime_improbable_conditions(mocker):
    prime_size = 2048
    msk = (1 << (prime_size // 2) - 1) | (1 << (prime_size // 2) - 2)
    p = rsa_dict[prime_size][0] | msk
    good_q = rsa_dict[prime_size][1] | msk
    bad_q_candidate = p + 2

    mocker.patch("secrets.randbits", side_effect=[bad_q_candidate, good_q])
    mocker.patch("rsautils.keygen.check_prime", return_value=True)

    found_q = keygen._generate_probable_prime(prime_size // 2, prm_p=p)

    assert found_q == good_q
    assert secrets.randbits.call_count == 2


def test_generate_probable_prime_faulty(mocker):
    mocker.patch("rsautils.keygen.check_prime", return_value=False)
    with pytest.raises(RuntimeError):
        keygen._generate_probable_prime(1024)


def test_generate_primes_conditions(mocker):
    size = 2048
    p = rsa_dict[size][0]
    q = rsa_dict[size][1]
    mocker.patch("rsautils.keygen._generate_probable_prime", side_effect=[p, p, q])
    rp, rq = keygen.generate_primes(size)
    assert rp == p
    assert rq == q
    assert keygen._generate_probable_prime.call_count == 3


@pytest.mark.parametrize("size,pub", [(1024, None), (2049, None), (2048, 65538), (2048, 2**16 - 1), (2048, 2**256 + 1)])
def test_generate_primes_validates(size, pub):
    with pytest.raises(ValueError):
        keygen.generate_primes(size, pub)


def test_generate_key_pair_roundcryption():
    pub_key, priv_key = keygen.generate_key_pair(2048)
    message = 17092025232642
    ciphertext = pow(message, pub_key[1], pub_key[0])
    decrypted = pow(ciphertext, priv_key[1], priv_key[0])
    assert decrypted == message


def test_generate_key_pair_functional(mocker):
    size = 2048
    src_pub = 65537
    src_p, src_q = rsa_dict[size]
    mocker.patch("rsautils.keygen.generate_primes", return_value=(src_p, src_q))
    (n, pub), (n, d, p, q) = keygen.generate_key_pair(size, src_pub, expose_primes=True)
    assert src_p == p
    assert src_q == q
    assert n == src_p * src_q
    assert src_pub == pub
    assert d == pow(src_pub, -1, (src_p - 1) * (src_q - 1))
