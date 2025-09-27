**Time Spent:** 20h~

**Things done:**
 - OAEP Implementation!
 - PKCS v1.5 Signature implementation!
 - Packaging to TestPyPi
 - CRT Implementation for PrivateKeys
 - Added tests
 - Updated and patched ICLI/CLI

**Program Progress:**
Implemented better encryption and signing, both of which are now PKCS #1 v2.2. 
Made core RSA operation accelerated for private keys which have the required components for Chinese Reminder Theorem.

**New Information**:
OAEP and PKCS v1.5 implementation how-to. Also, how to package to the repository, resulting in the TestPyPi.

**Challenges:**
Time management :P
Also writing documentation outside the core files.

**Next Up:**
Final tests and cleanup. Maybe better signing scheme (PSS).
