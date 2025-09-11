"""Generates realistic Primes for Unit Testing."""
# Don't really rerun this.
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa

pkey2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pkey4096 = rsa.generate_private_key(public_exponent=65537, key_size=4096)

primes = {
    2048: (pkey2048.private_numbers().p, pkey2048.private_numbers().q),
    4096: (pkey4096.private_numbers().p, pkey4096.private_numbers().q),
}

with open("rsa_primes.pickle", "xb") as f:
    # Yes, intentionally xb to prevent needles regeneration.
    pickle.dump(primes, f, 5)
