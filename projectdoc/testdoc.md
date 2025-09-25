## Testing Document
### Coverage
| Name                         |   Stmts |  Miss | Branch | BrPart |    Cover |
|------------------------------|--------:|------:|-------:|-------:|---------:|
| src\rsautils\\_\_init\_\_.py |      10 |     0 |      0 |      0 |     100% |
| src\rsautils\keygen.py       |     124 |     0 |     64 |      0 |     100% |
| src\rsautils\rsa.py          |     145 |     0 |     22 |      0 |     100% |
| **TOTAL**                    | **279** | **0** | **86** |  **0** | **100%** |

### What was tested?
We tested every function in `keygen.py` for correctness and reliability over small and representative
inputs, using constant inputs where possible based on known-good generation results.

In contrast, a lot of the tests for `rsa.py` approach testing in a much more integration-testing approach
checking for end-to-end or interoperability testing rather than providing unit tests for each of the smaller
test functions.
This is due to the overall needs for such approach in encryption, decryption and such justifying our favor
towards such testing rather than unit tests and the current tests provide sufficient detail to test our implementation.

### Test Inputs
All test inputs are preset and depending on the test are either known-good lists of the smaller
primes or larger primes generated using `get_test_data.py` using a known good implementation of the
python `cryptography` library for that as well as exporting to template PKCS1 public key files
and PKCS8 private key files.

### Test Reproduction
All fo the tests can be reproduced using the information placed in the repository, outside the
issues present due to the probabilistic nature of the Miller-Rabin algorithm, but they should remain consistent
if not always cover all the branches in the function.
