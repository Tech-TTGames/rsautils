"""Various RSA Utilities in an Academic Sense.

Provides RSA Utilities for Encryption, Decryption, Signing, Verification, Exporting Keys to PKCS1 (Public Key) and
PKCS8 (Private Key). Furthermore, provides various prime-generation utilities under-the-hood.

Typical usage example:

    p, q = generate_primes(2048)
    pk = RSAPrivKey.generate(3072)
    c = pk.pub.encrypt("Hi there!")
    r = pk.decrypt(c)
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
from rsautils.keygen import check_prime
from rsautils.keygen import export_primes
from rsautils.keygen import generate_key_pair
from rsautils.keygen import generate_primes
from rsautils.keygen import get_pre_primes
from rsautils.keygen import import_primes
from rsautils.rsa import RSAPrivKey
from rsautils.rsa import RSAPubKey

__version__ = "0.0.1"
__all__ = [
    "RSAPrivKey",
    "RSAPubKey",
    "export_primes",
    "import_primes",
    "get_pre_primes",
    "check_prime",
    "generate_primes",
    "generate_key_pair",
]
