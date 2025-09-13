"""Core Key Generation Utility, mainly focusing on the generation of random large primes.`

This module is responsible for generating IFC key pairs roughly based on FIPS 186-5. We will be focusing on probable
primes, but a later implementation of provable primes is not out of the question.
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import getpass
import hashlib
import platform
import secrets

_SMALL_PRIMES: list[int] = []
_SMALL_PRIMES_CAP: int = 0


def _sieve(n: int = 10000) -> list[int]:
    """Implements the Sieve of Eratosthenes.

    Uses the textbook Sieve of Eratosthenes to generate a set of primes up to `n`.
    Includes memory space optimization and sieving until root.

    Args:
        n: The number up to which to generate primes. Defaults to 10000. Must be >= 0.

    Returns:
        A list of primes up to `n`.
    """
    # TODO: To be considered for a reimplementation allowing expanding based on the current list.
    if n < 2:
        return []
    i_size = (n - 1) // 2
    candidate: list[bool] = [True] * i_size
    for i in range(int(n**0.5) // 2):
        if candidate[i]:
            r = 2 * i + 3
            for j in range((r * r - 3) // 2, i_size, r):
                candidate[j] = False
    result = [2] + [(no * 2 + 3) for no, ele in enumerate(candidate) if ele]
    return result


def get_pre_primes(n: int = 10000, change: bool = False) -> list[int]:
    """Get the small primes, automatically generating if necessary.

    Accesses the `_SMALL_PRIMES` global variable in accordance to style guides, using it as a cache if already generated.
    Passes data to Sieve of Eratosthenes if necessary. Regeneration occurs if requested range is greater, forced by
    `change` or cache is empty.

    Args:
        n: The number up to which to generate primes. Defaults to 10000. Must be >= 0.
            Ignored if smaller or equal than `_SMALL_PRIMES_CAP`, `change` is False and `_SMALL_PRIMES` is non-empty.
        change: Whether to force a recomputation of primes. Defaults to False.

    Returns:
        List of small primes in ascending order. Guaranteed to be all primes up to `n`, but may be more unless change is `True`.
    """
    if n < 0:
        raise ValueError("n must be >= 0")
    global _SMALL_PRIMES
    global _SMALL_PRIMES_CAP
    if n > _SMALL_PRIMES_CAP or change or not _SMALL_PRIMES:
        _SMALL_PRIMES = _sieve(n)
        _SMALL_PRIMES_CAP = n
    return _SMALL_PRIMES


def import_primes(file: str, sha: str, unsalted: bool = False) -> None:
    """Imports primes from file, including SHA verification.

    Imports primes from specified file after verification of file integrity.

    Args:
        file: Path to the file to import.
        sha: SHA-384 hash of the file to verify.
        unsalted: Don't verify using locally generated salt.

    Raises:
        RuntimeError: SHA-384 hash does not match the SHA-384 hash of the file.
    """
    global _SMALL_PRIMES
    base = hashlib.sha384()
    if not unsalted:
        # Note! Salting is intended to prevent less advanced users from accidentally importing compromised files.
        base.update(f"RSALIB_RECIPE:{getpass.getuser()}@{platform.node()}+{platform.system()}".encode())
    with open(file, "rb") as f:
        base.update(f.read())
    if base.hexdigest() != sha:
        raise RuntimeError("SHA-384 file verification failed.")
    with open(file, "r", encoding="utf-8") as f:
        _SMALL_PRIMES = [int(line.strip()) for line in f]


def _trial_division(no: int, n: int = 10000) -> bool:
    """Check the provided `no` against the known small primes.

    Runs a fast pre-check before Miller-Rabin by using modulo division on our known frequent primes.

    Args:
         no: The number to check. Must be integer and non-negative.
         n: The number up to which to generate primes. Defaults to 10000.
           Passed to `get_pre_primes()`, without the `change` argument.

    Returns:
        False if `no` cannot be prime, True otherwise.
    """
    if no < 2:
        return False
    for prime in get_pre_primes(n):
        if prime**2 > no:
            return True
        if no % prime == 0:
            return False
    return True


def _miller_rabin(w: int, iters: int) -> bool:
    """Perform Miller-Rabin primality test.

    Performs the Miller-Rabin primality test as specified in FIPS 186-5.

    Args:
        w: Odd integer to be tested.
        iters: Number of Miller-Rabin iterations to perform.

    Returns:
        True if `w` is probably prime, False otherwise.
    """
    if w <= 3:
        return w == 2 or w == 3
    tw = w - 1
    a = (tw & -tw).bit_length() - 1
    m = tw // (2**a)  # Has to be exactly int, as we get "a" above.
    for _ in range(iters):
        b = secrets.randbelow(w - 3) + 2
        z = pow(b, m, w)
        if z == 1 or z == w - 1:
            continue
        for _ in range(1, a):
            z = pow(z, 2, w)
            if z == w - 1:
                break
            if z == 1:
                return False
        else:
            return False
    return True


def check_prime(candidate: int, iters: None | int = None, n: int = 10000) -> bool:
    """Performs a composite Primality test, using a limited amount of trial divisions, before a Miller-Rabin test.

    In interest of providing a result expediently we run a trial division with all primes up to `n`, before proceeding
    with a FIPS 186-5 based Miller-Rabin primality test.

    Args:
        candidate: The candidate prime to test.
        iters: Number of Miller-Rabin iterations to perform.
            If not provided will use defaults as per the FIPS 186-5 Table B.1.
        n: The number up to which to generate primes. Defaults to 10000.
            Passed to `_trial_division()`.

    Returns:
        True if `candidate` is probably prime, False otherwise.
    """
    if n < 2:
        return False
    if not _trial_division(candidate, n):
        return False
    if iters is None:
        iters = 5
        if candidate.bit_length() > 1536:
            iters = 4
    return _miller_rabin(candidate, iters)
