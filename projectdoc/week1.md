**Time Spent:** 6h

**Things done:**
Reading project rules and guidance. I have conducted baseline setup and research regarding the algorithms to be used in the project along with the decision to
take up this particular project topic. As a main goal I have found reliable sources regarding the implementation of RSA key
generation as well as the implementation of RSA, settling on a few of the sources such as PKCS #1 and FIPS 186-5 as guidance.
Though simplifications may be applied to all the standards.

**Program Progress:**
Set up the development environment in the current state (poetry, GitHub repo) to facilitate development next week. Added
a few placeholder files to use as a baseline for development, though no structure inside them is present at the moment.

**New Information**:
Basic knowledge regarding the practical implementation of RSA as well as the large prime generation methods.
Such as the baseline Miller-Rabin Primality test as described in FIPS 186-5.
Some research on optional RSA features to such as OEAP padding or AES-based key encryption.
Most importantly found the "standards" I should use as a good reference for realistic implementations of all algorithms.

**Challenges:**
Due to the more planning stage of this week no particular challenges were present. However, some notable issues included
finding the space complexity for some algorithms as well as determining a fitting range of features to plan in the specification
document.

**Next Up:**
As per the suggested schedule next week I'll begin core feature implementation such as the Miller-Rabin Primality test
as well as the method for prime generation using it. Furthermore unit tests will be created alongside them to ensure mathematical correctness.
