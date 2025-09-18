"""A man-in-the middle module, for proxying outgoing traffic to functions that may be implemented in the future.

Used as a transistor layer to designate not currently created functions, for possible future implementation.
Existence of a function in this module means it's a candidate for implementation, but makes no guarantee
regarding when or whether such implementation will happen at all. Functions implemented elsewhere will still be
available here via local proxy for a few versions but will issue a deprecation warning and be removed afterward.
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0


def eea(a: int, b: int) -> tuple[int, int, int]:
    """Implements the Extended Euclidean Algorithm.

    Such a that a*s0 + b*t0 = r0 = gcd(a, b).

    Args:
        a: The first natural number.
        b: The second natural number.

    Returns:
        Greatest common denominator of two integers.
        As well as the Bezout coefficients.
    """
    r0, r1 = a, b
    s0, s1, t0, t1 = 1, 0, 0, 1
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1
    return r0, s0, t0
