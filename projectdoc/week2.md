**Time Spent:** ~16h

**Things done:**
 - Updated `specdoc.md` based on feedback regarding CLI/GUI and details on complexity section
 - Set up pylint, pytest configuration as well as their respective workflows + a CodeQL and dependency analysis one.
 - Implemented moderately time and space optimized Sieve of Eratosthenes.
 - Implemented trial division function, global cache of small primes.
 - Comprehensive and representative testing for functions.
 - Separated slow and extreme test cases. Slow ones are currently opt-out as testing with them takes roughly 2s.
Extreme are opt-in and the single case marked as such takes upwards of 20? minutes to complete. It is the highes currently
known prime number being put under Miller-Robin it is not fast.
 - Implemented Miller-Rabin test as well as Composite test with pretest using trial division.
 - Implemented Precomputed Prime Import/Export Utility, including SHA-384 verification of integrity, 2 variants for local
and non-local files (peppered and clean) files respectively.
 - Created some preset reliable testing data and an extensible script for it's generation if desired.

**Program Progress:**
All core components for the assurance that a number is prime has been implemented along with an extensive testing setup
to ensure code correctness. Current coverage of `keygen.py` is 100% (Coverage claims 99% despite a test case for the single line it marks as missed being included).

**New Information**:
I learned a lot regarding the usage of pytest as well as mocker, neither of which did I have any experience with beforehand.
The implementation of both Miller-Rabin and Sieve of Eratosthenes was quite interesting with the albeit basic but very
useful optimization to the Sieve providing an interesting view.

**Challenges:** As noted in *New Information* I was quite new to the usage of pytest so that presented a learning challenge
however after reading the documentation I have understood the way it works. Are the current tests representative and sufficient
however?

Another thing was the side tangent for the Import/Export of Prime Lists and the consideration of proper pepper use. Sources
seem to vary on whether a pepper should be before or after the message, which gave me quite a headache.


**Next Up:** Next week I'll be implementing some final functions for the generation of the keys and then moving towards
both the factual textbook RSA (which shouldn't take long) and implementation of the CLI/GUI in the `__main__.py` module.
As the updated Specification Document states the tool will support command line arguments as well as an interactive client
that will be automatically initiated either if data is missing or no arguments were provided (excluding while running
with other `--non-interactive` flags.)

