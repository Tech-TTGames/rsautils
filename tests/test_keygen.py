# pylint: disable=protected-access,missing-module-docstring
import os
import pickle

import pytest

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


@pytest.mark.parametrize("n,expected", [(10**5, 9592), (10**6, 78498), (10**7, 664579)])
def test_sieve_large_approx(n, expected):
    # Not the intended use of the function, but included as a sanity check.
    assert len(keygen._sieve(n)) == expected


@pytest.mark.parametrize("n", [-27358709381728, -10, -1])
def test_sieve_errors(n):
    with pytest.raises(ValueError):
        keygen._sieve(n)


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


def test_import_primes():
    # TODO: Placeholder! Will be implemented after we make the "output" for prime generation
    pass


@pytest.mark.parametrize(
    "num,expected",
    [
        # Edge Cases (neither)
        (0, False),
        (1, False),
        # Known Primes
        (2, True),
        (3, True),
        (101, True),
        (3571, True),
        (9973, True),
        (2**136279841 - 1, True),  # Large prime. Because yes.
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
        # RSA PRIMES
        (rsa_dict[2048][0], True),
        (rsa_dict[2048][1], True),
        (rsa_dict[4096][0], True),
        (rsa_dict[4096][1], True),
        # RSA-non PRIMES
        (rsa_dict[2048][0] * 3, False),
        (rsa_dict[2048][1] * 3, False),
        (rsa_dict[4096][0] * 3, False),
        (rsa_dict[4096][1] * 3, False)
    ],
    ids=id_generator)
def test_trial_division(num, expected):
    assert keygen._trial_division(num) == expected


@pytest.mark.parametrize("n", [-27358709381728, -10, -1])
def test_trial_division_error(n):
    with pytest.raises(ValueError):
        keygen._trial_division(n)
