"""Generates realistic items for Unit Testing."""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import os
import pickle

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

target_sizes = [1024, 2048, 3072, 4096]
primes = {}
e = 65537

if os.path.isfile("rsa_primes.pickle"):
    with open("rsa_primes.pickle", "rb") as f:
        primes = pickle.load(f)

for size in target_sizes:
    if size not in primes:
        print(f"Generating new {size} prime set.")
        pk = rsa.generate_private_key(public_exponent=e, key_size=size)
        primes[size] = (pk.private_numbers().p, pk.private_numbers().q)
    if not os.path.isfile(f"rsa_{size}"):
        print(f"Parting test primes into {size} key.")
        p, q = primes[size]
        d = rsa.rsa_recover_private_exponent(e, primes[size][0], primes[size][1])
        dmp1 = rsa.rsa_crt_dmp1(d, p)
        dmq1 = rsa.rsa_crt_dmq1(d, q)
        iqmp = rsa.rsa_crt_iqmp(p, q)
        pubpart = rsa.RSAPublicNumbers(e, p * q)
        fullkey = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pubpart).private_key()
        pld = fullkey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        with open(f"rsa_{size}", "wb") as f:
            f.write(pld)
    if not os.path.isfile(f"rsa_{size}.pub"):
        print(f"Parsing test primes into {size} public key.")
        p, q = primes[size]
        pubkey = rsa.RSAPublicNumbers(e, p * q).public_key()
        pld = pubkey.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        with open(f"rsa_{size}.pub", "wb") as f:
            f.write(pld)

with open("rsa_primes.pickle", "wb") as f:
    pickle.dump(primes, f, 5)

print("Unit test data up to date.")
