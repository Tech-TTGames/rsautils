"""Core Key Generation Utility, mainly focusing on the generation of random large primes.`

This module is responsible for generating IFC key pairs roughly based on FIPS 186-5. We will be focusing on probable
primes, but a later implementation of provable primes is not out of the question.
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import getpass
import hashlib
import platform

_SMALL_PRIMES: list[int] | None = None


def _sieve(n: int = 10000) -> list[int]:
    """Implements the Sieve of Eratosthenes.

    Uses the textbook Sieve of Eratosthenes to generate a set of primes up to `n`.
    Includes memory space optimization and sieving until root.

    Args:
        n: The number up to which to generate primes. Defaults to 10000. Must be >= 0.

    Returns:
        A list of primes up to `n`.
    """
    if n < 0:
        raise ValueError("n must be >= 0")
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

    Accesses the _SMALL_PRIMES global variable in accordance to style guides, using it as a cache if already generated.
    Passes data to Sieve of Eratosthenes if necessary.

    Args:
        n: The number up to which to generate primes. Defaults to 10000.
        change: Whether to force a recomputation of primes. Defaults to False.

    Returns:
        List of small primes in ascending order. Not guaranteed to be up to `n` unless change is `True`.
    """
    global _SMALL_PRIMES
    if change or _SMALL_PRIMES is None:
        _SMALL_PRIMES = _sieve(n)
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
           Passed to `get_pre_primes()`, this function won't cause a regeneration.

    Returns:
        False if `no` cannot be prime, True otherwise.
    """
    if no < 0:
        raise ValueError("Number to check must be non-negative.")
    if no < 2:
        return False
    for prime in get_pre_primes(n):
        if prime**2 > no:
            return True
        if no % prime == 0:
            return False
    return True
