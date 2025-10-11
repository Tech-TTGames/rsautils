## User Guide
Welcome to `rsautils`, an experimental & academic toolkit/library for RSA cryptography. This user guide will help you get
started with the library, covering installation, basic usage, and examples, separated into different sections based on
the usage model.

### Installation
You can install `rsautils` via pip from the TestPyPI repository. Use the following command:
```shell
pip install rsautils --extra-index-url https://test.pypi.org/simple/
```

For solely command-line usage in an isolated environment, you can use pipx:
```shell
pipx install rsautils --pip-args="--extra-index-url https://test.pypi.org/simple/"
```
requires [pipx](https://pipx.pypa.io/stable/).

For development purposes, see the instructions in the [README](../README.md).

### The Different Usage Models
`rsautils` can be used in two main ways:
1. **As a Command-Line Tool**: You can use `rsautils` directly from the command line to perform a variety of RSA-related tasks.
   However, this further subdivides into two modes:
   1. ***[Interactive Command-Line Interface (iCLI)](#interactive-command-line-interface-icli)***: This mode provides an
      interactive environment where users are provided with the options and descriptions for each input. It is ideal for
      less experienced users or those who prefer a guided experience. It does not provide all the features of CLI by
      default (requiring additional flags), but it is more user-friendly.
   2. ***[Command-Line Interface (CLI)](#command-line-interface-cli)***: This mode is for users who prefer to interact
      with the tool via command-line arguments and options. It is suitable for quick tasks and automation via scripts or
      more advanced users who are comfortable with command-line operations.
2. **As a Python Library**: You can import `rsautils` into your Python projects and use its features programmatically.
   This mode exposes more than either CLI or iCLI, allowing for more complex and customized operations, so it may be
   optimal for scripts or users who have a good understanding of Python programming. This is only briefly covered
   in this guide ([Library Usage](#library-usage)), and we recommend referring to the in-code documentation
   (docstrings) for more details. Requires a full (non-pipx) installation.

### Interactive Command-Line Interface (iCLI)
The iCLI mode is a guided, interactive interface for users less experienced with RSA or command-line tools. It provides
explanations and prompts for each input, making it easier to navigate the various functionalities of `rsautils`.
To start the iCLI, simply run:
```shell
rsauitls
```
This will launch the interactive interface, where you will be presented with a menu of options. Follow the prompts to
perform tasks such as key generation, encryption, decryption, signing, and verification. For more details on the available
options and their usage, refer to the [Command-Line Interface (CLI)](#command-line-interface-cli) section below, as the
options are similar.

#### Specific iCLI Options
The iCLI mode has one unique option:
- `--advanced`: Enables advanced options in the iCLI, providing access to more complex functionalities, which were
  hidden, and provided default, safe values, in the standard iCLI mode. This may be useful for more experienced users who
  want to explore all the features but still want the guided experience of the iCLI. This flag brings the iCLI to
  feature-parity with the CLI mode.

  ***WARNING:*** Some advanced options may   result in insecure results, due to academic or experimental features. Use with caution.

### Command-Line Interface (CLI)
The CLI mode allows users to interact with `rsautils` via command-line arguments and options, as is standard for
command-line tools. By default, if any required arguments are missing, the CLI will fall back to the iCLI mode to prompt
for the missing inputs. This provides a balance between flexibility and user-friendliness. See the arguments below on
how to disable this behavior.

To use the CLI, you can run commands in the following format:
```shell
rsautils <command> [options]
```
Where `<command>` is one of the available commands (e.g., `keygen`, `encrypt`, `decrypt`, `sign`, `verify`), and
`[options]` are the specific options for that command. See below for details on each command and its options.

#### Common Options
Theis option is available for all commands:
- `-h`, `--help`: Displays help information for the command or general usage if no command is specified.

#### Root Options
These options apply to the `rsautils` command itself and must be specified before any subcommands or subcommand options:
- `-n`, `--non-interactive`: Disables iCLI fallback. If any required arguments are missing, the command will fail with an error instead of prompting for input.
- `-v`, `--version`: Displays the version of `rsautils` and exits.
Additionally, the iCLI-specific `--advanced` flag is also available in CLI mode to enable advanced options.
 - `--advanced`: Enables advanced options, providing access to more complex functionalities.
For example, `rsautils --version keygen` will display the version, while `rsautils keygen --version` will result in an error.

#### Available Commands
The following commands are available in the CLI mode:
- `keygen`: Generates RSA key pairs.
- `encrypt`: Encrypts a message using a public key.
- `decrypt`: Decrypts a message using a private key.
- `sign`: Signs a message using a private key.
- `verify`: Verifies a signature using a public key.

For details on each command, see below.
##### Key Generation
Generates RSA key pairs. You can specify the key size and other parameters.
```shell
rsautils keygen [options]
```
Options:
- `--private-key, -P <file>`: Specifies the output location for the private key file.
- `--public-key, -p <file>`: Specifies the output location for the public key file.
- `--keysize, -k <size>`: Specifies the size of the RSA key in bits (acceptable values: 2048, 3072, 4096). Default is 3072.
- `--pub-exponent, -e <exponent>`: Specifies the public exponent (e.g., 3, 65537). Default is 65537.
- `--overwrite, -o`: Overwrites existing key files if they already exist.

##### Encryption
Encrypts a message using a public key.
```shell
rsautils encrypt [options]
```
Options:
 - `--public-key, -p <file>`: Specifies the public key file to use for encryption.
 - `--message, -m <file>`: Specifies the input messsage, either as a file path or a direct string.
   To input a path, prefix it with `P:` (e.g, `P:message.txt`), otherwise, it is treated as a direct string.
 - `--label, -l <label>`: Specifies an optional label for OAEP padding. Default is an empty string.
 - `--sha, -s <hash>`: Specifies the hash algorithm to use (acceptable values: sha256, sha384, sha512). Default is sha384.
 - `--encoding, -c <encoding>`: Specifies the encoding to use for the message (acceptable values: utf-8, utf-16, ascii). Default is utf-8.
 - `--academic, -A`: Uses academic encryption (textbook RSA). This is insecure and should only be used for educational purposes.

##### Decryption
Decrypts a message using a private key.
```shell
rsautils decrypt [options]
```
Options:
 - `--private-key, -P <file>`: Specifies the private key file to use
 - `--message, -m <file>`: Specifies the input messsage, either as a file path or a direct string.
   To input a path, prefix it with `P:` (e.g, `P:message.txt`), otherwise, it is treated as a direct string.
 - `--label, -l <label>`: Specifies an optional label for OAEP padding, verifying it matches the one used during encryption. Default is an empty string.
 - `--encoding, -c <encoding>`: Specifies the encoding to use for the output message (acceptable values: utf-8, utf-16, ascii). Default is utf-8.
Thanks to some magic we do under-the-hood, the encryption method and SHA function are automatically detected, so you don't need to specify them.

##### Signing
Signs a message using a private key. (Uses PKCS#1 v1.5 scheme)
```shell
rsautils sign [options]
```
Options:
 - `--private-key, -P <file>`: Specifies the private key file to use
 - `--message, -m <file>`: Specifies the input messsage, either as a file path or a direct string.
   To input a path, prefix it with `P:` (e.g, `P:message.txt`), otherwise, it is treated as a direct string.
 - `--sha, -s <hash>`: Specifies the hash algorithm to use (acceptable values: sha256, sha384, sha512). Default is sha384.
Encoding is not applicable for signing, as the message is hashed before signing (we always use UTF-8 for hashing).

##### Verification
Verifies a signature using a public key. (Uses PKCS#1 v1.5 scheme)
```shell
rsautils verify [options]
```
Options:
 - `--public-key, -p <file>`: Specifies the public key file to use
 - `--message, -m <file>`: Specifies the input messsage, either as a file path or a direct string.
   To input a path, prefix it with `P:` (e.g, `P:message.txt`), otherwise, it is treated as a direct string.
 - `--signature, -S <string>`: Specifies the signature to verify, as a base64-encoded string.
As per PKCS#1 v1.5, the hash algorithm is encoded within the signature, so it is automatically detected during verification.

### Library Usage
You can also use `rsautils` as a Python library in your own projects. This allows for more complex and customized operations.
To use `rsautils` as a library, you can import it into your Python code:
```python
import rsautils
```
You can then use the various functions and classes provided by `rsautils` to perform RSA operations programmatically.
Some features that are not available in the CLI/iCLI modes may be accessible via the library, such as storing generated
small primes in-between runs, or specifying in more detail how to generate primes. Refer to the in-code documentation
(docstrings) for more details on the available functions and classes.
