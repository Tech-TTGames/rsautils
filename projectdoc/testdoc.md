## Testing Document
### Coverage
| Name                         |   Stmts |  Miss |  Branch | BrPart |    Cover |
|------------------------------|--------:|------:|--------:|-------:|---------:|
| src\rsautils\\_\_init\_\_.py |      10 |     0 |       0 |      0 |     100% |
| src\rsautils\keygen.py       |     132 |     0 |      70 |      0 |     100% |
| src\rsautils\rsa.py          |     274 |     0 |      62 |      0 |     100% |
| **TOTAL**                    | **416** | **0** | **132** |  **0** | **100%** |

### What was tested?
We tested every function in `keygen.py` for correctness and reliability over small and representative
inputs, using constant inputs where possible based on known-good generation results.

In contrast, a lot of the tests for `rsa.py` approach testing in a much more integration-testing approach
checking for end-to-end or interoperability testing rather than providing unit tests for each of the smaller
test functions.
This is due to the overall needs for such approach in encryption, decryption and such justifying our favor
towards such testing rather than unit tests and the current tests provide sufficient detail to test our implementation.

More specific fail-correctly unit tests have been made for `rsa.py` to expand branch coverage and ensure that all functions
fail in correct places due to the importance of said failures.

### Test Inputs
All test inputs are preset and depending on the test are either known-good lists of the smaller
primes or larger primes generated using `get_test_data.py` using a known good implementation of the
python `cryptography` library for that as well as exporting to template PKCS1 public key files
and PKCS8 private key files.

### Test Reproduction
All fo the tests can be reproduced using the information placed in the repository, outside the
issues present due to the probabilistic nature of the Miller-Rabin algorithm, but they should remain consistent
if not always cover all the branches in the function.

#### Test Run Command
```shell
pytest
```
with optional arguments to specify skipping of slow, running of extreme tests, coverage checks and coverage report format.
They follow the standard pytest conventions with the addition of these two shortcuts.
```shell
pytest --skip-slow 
```
Shortcut to skip slower (more than a second or two) tests
```shell
pytest --run-extreme
```
Shortcut to run extreme tests that are not practical and may take an unknown amount of time to run.