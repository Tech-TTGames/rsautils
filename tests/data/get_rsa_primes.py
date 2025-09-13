"""Generates realistic Primes for Unit Testing."""
import os
import pickle

from cryptography.hazmat.primitives.asymmetric import rsa

target_sizes = [2048, 3072, 4096]
primes = {}

if os.path.isfile("rsa_primes.pickle"):
    with open("rsa_primes.pickle", "rb") as f:
        primes = pickle.load(f)

for size in target_sizes:
    if size not in primes:
        print(f"Generating new {size} prime set.")
        pk = rsa.generate_private_key(public_exponent=65537, key_size=size)
        primes[size] = (pk.private_numbers().p, pk.private_numbers().q)

with open("rsa_primes.pickle", "wb") as f:
    pickle.dump(primes, f, 5)

print("Unit test data up to date.")
