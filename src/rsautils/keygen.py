"""Core Key Generation Utility, mainly focusing on the generation of random large primes.`

This module is responsible for generating IFC key pairs roughly based on FIPS 186-5. We will be focusing on probable
primes, but a later implementation of provable primes is not out of the question.

Typical usage example:

    get_pre_primes(12000)
    hs = hash_file("README.md", local=False)
    export_primes("primfile")
    import_primes("primfile")
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import getpass
import hashlib
import math
import pathlib
import platform
import secrets
from typing import Literal, overload

_SMALL_PRIMES: list[int] = []
_SMALL_PRIMES_CAP: int = 0
_MINIMUM_PRIME_SEPARATION: int = 100


def hash_file(file: pathlib.Path, local: bool = True) -> str:
    """Hash a file and return its hash.

    Args:
        file: Target file to hash.
        local: Whether the file is local or not. Defaults to True.
            If False, does not pepper.

    Returns:
        The hash of the file.
    """
    base = hashlib.sha384()
    if local:
        # Note! Peppering is intended to prevent less advanced users from accidentally importing compromised files.
        p = hashlib.sha384(f"RSALIB_RECIPE:{getpass.getuser()}@{platform.node()}+{platform.system()}".encode()).digest()
        base.update(p)
    with open(file, "rb") as f:
        base.update(f.read())
    return base.hexdigest()


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

    Accesses the `_SMALL_PRIMES` global variable in accordance to style guides, using it as a cache if available.
    Passes data to Sieve of Eratosthenes if necessary. Regeneration occurs if requested range is greater, forced by
    `change` or cache is empty.

    Args:
        n: The number up to which to generate primes. Defaults to 10000. Must be >= 0.
            Ignored if smaller or equal than `_SMALL_PRIMES_CAP`, `change` is False and `_SMALL_PRIMES` is non-empty.
        change: Whether to force a recomputation of primes. Defaults to False.

    Returns:
        List of primes in ascending order. All primes at least to `n` or more unless `change` is True.
    """
    if n < 0:
        raise ValueError("n must be >= 0")
    global _SMALL_PRIMES
    global _SMALL_PRIMES_CAP
    if n > _SMALL_PRIMES_CAP or change or not _SMALL_PRIMES:
        _SMALL_PRIMES = _sieve(n)
        _SMALL_PRIMES_CAP = n
    return _SMALL_PRIMES


def import_primes(file: pathlib.Path, sha: str, local: bool = True) -> None:
    """Imports primes from file, including SHA verification.

    Imports primes from specified file after verification of file integrity.

    Args:
        file: Path to the file to import.
        sha: SHA-384 hash of the file to verify.
        local: Whether the file is local or not. Defaults to True.
            If False, bypasses local pepper requirement.

    Raises:
        RuntimeError: SHA-384 hash does not match the SHA-384 hash of the file.
    """
    global _SMALL_PRIMES
    global _SMALL_PRIMES_CAP
    if hash_file(file, local) != sha:
        raise RuntimeError("SHA-384 file verification failed.")
    with open(file, "r", encoding="utf-8") as f:
        _SMALL_PRIMES_CAP = int(f.readline().strip())
        _SMALL_PRIMES = [int(line.strip()) for line in f]


def export_primes(file: pathlib.Path) -> tuple[str, str]:
    """Exports currently cached small primes to specified file.

    Args:
        file: Path to the file to export.

    Returns:
        Tuple of (Locally Peppered SHA-384, Standard SHA-384 hash).
    """
    with open(file, "w", encoding="utf-8") as f:
        f.write(f"{_SMALL_PRIMES_CAP}\n")
        for p in _SMALL_PRIMES:
            f.write(f"{p}\n")
    return hash_file(file, True), hash_file(file, False)


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
    Minor adjustments applied to make the code more efficient due to local utilities.

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
            If not provided will use defaults as per the FIPS 186-5 Appendix C.1
        n: The number up to which to generate primes. Defaults to 10000.
            Passed to `_trial_division()`.

    Returns:
        True if `candidate` is probably prime, False otherwise.
    """
    if candidate < 2:
        return False
    if not _trial_division(candidate, n):
        return False
    if iters is None:
        if candidate.bit_length() <= 512:
            iters = 40
        elif candidate.bit_length() <= 1024:
            iters = 56
        elif candidate.bit_length() <= 1536:
            iters = 64
        elif candidate.bit_length() <= 2048:
            iters = 70
        else:
            iters = 74

    return _miller_rabin(candidate, iters)


def _generate_probable_prime(size: int, pub: int = 65537, prm_p: int | None = None) -> int:
    """Generate a probable prime number of the specified bit size.

    Implements parts of the FIPS 186-5 protocol for generation of prime numbers that are probably prime.
    In this case we're using a multi-use function for both p and q.

    Args:
        size: The size of the prime to generate in bits.
        pub: The public exponent of the prime to generate in bits. Defaults (and recommended) to use 65537.
            Has to be odd and in range `(2**16, 2**256)` exclusive.
        prm_p: The other prime in the pair if this is the second generation. Adds tests as per specification.
            Optional, if not provided generates 1st prime.

    Returns:
        A probable prime number.

    Raises:
        RuntimeError if generation loops way beyond a reasonable time and a bit.
    """
    ml = 2
    if prm_p is None:
        ml = 1
    rep_cap = size * 5 * ml
    for _ in range(rep_cap):
        byts = secrets.randbits(size)
        # Set first two bits to 1 to ensure length.
        msk = (1 << size - 1) | (1 << size - 2)
        byts = byts | msk
        # We do not check if byts**2 < (1 << (2 * size - 1)) as the mask ensures it is impossible.
        if prm_p is not None and abs(prm_p - byts) <= (1 << (size - _MINIMUM_PRIME_SEPARATION)):
            continue
        # If required will move out GCD out of math.
        if math.gcd(byts - 1, pub) == 1 and check_prime(byts):
            return byts
    raise RuntimeError(
        f"Run an improbable {size * 5 * ml} amount of loops with no prime found. Check system random number generator.")


def generate_primes(size: int, pub: int = 65537) -> tuple[int, int]:
    """Generates and IFC-suitable pair of prime numbers.

    Completes the FIPS 186-5 protocol for generating prime numbers that are probably prime, with the main loops being
    in `_generate_probable_prime`.

    Args:
        size: The key size to generate the prime pair for. Must be even.
        pub: The public exponent of the prime to generate in bits. Defaults (and recommended) to use 65537.
            Has to be odd and in range `(2**16, 2**256)` exclusive.

    Returns:
        A pair of IFC-suitable prime numbers, against specified exponent.

    Raises:
        ValueError if `size` is an insecure size or `pub` does not meet requirements.
    """
    if size < 2048:
        raise ValueError("Size must be at least 2048.")
    if size % 2 != 0:
        raise ValueError("Size must be an even number.")
    if pub % 2 == 0 or not 2**16 < pub < 2**256:
        raise ValueError("Public exponent does not meet requirements.")
    p = _generate_probable_prime(size // 2, pub)
    q = _generate_probable_prime(size // 2, pub, p)
    while p == q:  # (Un)Likely story.
        q = _generate_probable_prime(size // 2, pub, p)
    return p, q


@overload
def generate_key_pair(size: int,
                      pub: int = 65537,
                      expose_primes: Literal[False] = False) -> tuple[tuple[int, int], tuple[int, int]]:
    ...


@overload
def generate_key_pair(size: int,
                      pub: int = 65537,
                      expose_primes: Literal[True] = False) -> tuple[tuple[int, int], tuple[int, int, int, int]]:
    ...


def generate_key_pair(
    size: int,
    pub: int = 65537,
    expose_primes: bool = False
) -> tuple[tuple[int, int], tuple[int, int]] | tuple[tuple[int, int], tuple[int, int, int, int]]:
    """Generates an RSA key pair.

    Fully generates a valid RSA Key, including generating the private exponent and public exponent.

    Args:
        size: The key size to generate the prime pair for. Must be even.
        pub: The public exponent of the prime to generate in bits. Defaults (and recommended) to use 65537.
            Has to be odd and in range `(2**16, 2**256)` exclusive.
        expose_primes: Whether to export the prime numbers as well or not. Defaults to False.
            Provides some acceleration for decryption if used correctly.

    Returns:
        A tuple of tuples of (public, private) sub-tuples (modulus, exponent) or if exposed for the private
        (modulus, exponent, p, q)
    """
    p, q = generate_primes(size, pub)
    n = p * q
    # If necessary, I'll move both out of builtins.
    totient = math.lcm(p - 1, q - 1)
    d = pow(pub, -1, totient)
    if not expose_primes:
        del p, q
        return (n, pub), (n, d)
    return (n, pub), (n, d, p, q)
