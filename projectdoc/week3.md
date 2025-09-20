**Time Spent:** ~24h?

**Things done:**
 - More testing
 - Final functions for keygen. Finalized keygen.
 - Testing for said functions.
 - Core RSA functions with Classes!
 - Package details and imports!
 - More tests for RSA Classes!
 - Mixed-use Command Line Interface with automatic fallback to Interactive mode.
 - Drafting Testing Documentation

**Program Progress:**
I made great progress this week with finishing up all the core utilities and throwing together a
rather satisfying CLI/ICLI setup. A lot of the testing was added and we're more or less at 100% coverage! (Unsused
`placholders.py` not included)

**New Information**:
The standards for private and public key formatting was very complex while also being very interesting.
ASN.1 is some very new information for me and I had to use it.

**Challenges:**
ASN.1 was very uncooperative and took a while to figure out. Signing is... very particular right now as I
wrap the hash and everything in a correct ASN.1 construct but do not implement any padding said construct should require.

**Next Up:**
I would be curious regarding the evaluation of the current testing setup and whether it requires any improvements.
However, from other improvements planned it would have to be either OEAP or PSS for padded encryption or signing respectively.

Would "Presentation of possible empirical testing results in graphical form" be relevant here?
