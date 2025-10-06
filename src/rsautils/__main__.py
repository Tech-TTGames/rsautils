"""The Command Line Interface for the utility, including Interactive elements.

What I would call a hybrid CLI/ICLI (Command Line Interface/Interactive Command Lice Interface) that automagically
generates the INTERACTIVE part on-the-fly based on the missing components of the CLI interaction, including the
option that none are included.

Typical usage example:

    rsautils
    OR
    python -m rsautils
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import argparse
import pathlib
import sys
import typing

import rsautils


class HelpData(typing.NamedTuple):
    description: str
    format: typing.Type = str
    choices: list[str] | None = None
    default: typing.Any = None
    advanced: bool = False


help_dict: dict[str, HelpData] = {
    "subcommand":
        HelpData(
            description="The available subcommands in RSA Utils.",
            choices=["keygen", "encrypt", "decrypt", "sign", "verify"],
        ),
    "keygen":
        HelpData("Key generation utility."),
    "encrypt":
        HelpData("Encryption utility."),
    "decrypt":
        HelpData("Decryption utility."),
    "sign":
        HelpData("Signing utility."),
    "verify":
        HelpData("Signature verification utility."),
    "public_key":
        HelpData(
            description="Location of the public key file.",
            format=pathlib.Path,
        ),
    "private_key":
        HelpData(
            description="Location of the private key file.",
            format=pathlib.Path,
        ),
    "message":
        HelpData(
            description="Message or path to file containing payload. If Path start with `P:`",
            format=str,
        ),
    "label":
        HelpData(
            description="Encrypted payload label. Used to verify during decryption.",
            format=str,
            advanced=True,
            default="",
        ),
    "encoding":
        HelpData(description="Payload encoding.", choices=["utf-8", "utf-16", "ascii"], advanced=True, default="utf-8"),
    "academic":
        HelpData(
            description="Whether to use academic encryption. Warning! Unsecure.",
            format=bool,
            advanced=True,
            default=False,
        ),
    "keysize":
        HelpData(
            description="Key size (in bits).",
            choices=["2048", "3072", "4096"],
            default="3072",
        ),
    "pub_exponent":
        HelpData(
            description="Exponent for the public key.",
            format=int,
            advanced=True,
            default=65537,
        ),
    "sha":
        HelpData(description="Specific SHA algorithm to use",
                 choices=["sha256", "sha384", "sha512"],
                 advanced=True,
                 default="sha384"),
    "signature":
        HelpData(
            description="The signature to validate against the payload and public certificate.",
            format=str,
        ),
    "overwrite":
        HelpData(
            description="Overwrite specified destination files if they exist?",
            choices=["Y", "N"],
            default="N",
        )
}

needs = {
    "keygen": ("public_key", "private_key", "keysize", "pub_exponent"),
    "encrypt": ("public_key", "message", "label", "sha", "academic", "encoding"),
    "decrypt": ("private_key", "message", "label", "encoding"),
    "sign": ("private_key", "message", "sha"),
    "verify": ("public_key", "message", "signature")
}

pubkey = argparse.ArgumentParser(add_help=False)
pubkey.add_argument("--public_key", "-p", type=help_dict["public_key"].format, help=help_dict["public_key"].description)
privkey = argparse.ArgumentParser(add_help=False)
privkey.add_argument("--private_key",
                     "-P",
                     type=help_dict["private_key"].format,
                     help=help_dict["private_key"].description)
payloads = argparse.ArgumentParser(add_help=False)
payloads.add_argument("--message", type=help_dict["message"].format, help=help_dict["message"].description)
encp = argparse.ArgumentParser(add_help=False)
encp.add_argument("--encoding", "-e", choices=help_dict["encoding"].choices, help=help_dict["encoding"].description)
sha = argparse.ArgumentParser(add_help=False)
sha.add_argument("--sha", "-s", choices=help_dict["sha"].choices, help=help_dict["sha"].description)
label = argparse.ArgumentParser(add_help=False)
label.add_argument("--label", "-l", type=help_dict["label"].format, help=help_dict["label"].description)
corep = argparse.ArgumentParser(prog="rsautils")
corep.add_argument("--version", "-v", action="version", version=f"%(prog)s {rsautils.__version__}")
corep.add_argument("--non-interactive", "-n", action="store_true", help="Enable non-interactive mode")
corep.add_argument("--advanced", "-a", action="store_true", help="Enable advanced mode, for interactive mode")
commands = corep.add_subparsers(dest="subcommand", title="Subcommands")

keygen = commands.add_parser("keygen", parents=[privkey, pubkey], help=help_dict["keygen"].description)
keygen.add_argument("--keysize", choices=help_dict["keysize"].choices, help=help_dict["keysize"].description)
keygen.add_argument("--pub-exponent", type=help_dict["pub_exponent"].format, help=help_dict["pub_exponent"].description)
keygen.add_argument("--overwrite", "-o", action="store_const", const="Y", help=help_dict["overwrite"].description)

encrypt = commands.add_parser("encrypt",
                              parents=[pubkey, payloads, label, sha, encp],
                              help=help_dict["encrypt"].description)
encrypt.add_argument("--academic", "-A", action="store_true", help=help_dict["academic"].description)
decrypt = commands.add_parser("decrypt",
                              parents=[privkey, payloads, label, encp],
                              help=help_dict["decrypt"].description)

sign = commands.add_parser("sign", parents=[privkey, payloads, sha], help=help_dict["sign"].description)
verify = commands.add_parser("verify", parents=[pubkey, payloads], help=help_dict["verify"].description)
verify.add_argument("--signature", "-S", type=help_dict["signature"].format, help=help_dict["signature"].description)


def checkmodes(arg: str, mode: tuple[bool, bool]):
    helper_data = help_dict[arg]
    if (mode[0] or (helper_data.advanced and not mode[1])) and helper_data.default:
        return helper_data.default
    if mode[0]:
        raise IOError(f"Argument {arg} is missing and non-interactive mode is active.")
    return helper_data


def choice_handler(arg: str, mode: tuple[bool, bool], prntr: typing.Callable = print):
    helper_data = checkmodes(arg, mode)
    if not isinstance(helper_data, HelpData):
        return helper_data
    prntr(f"Please specify the {arg}!")
    prntr("Description: ", helper_data.description)
    choices = helper_data.choices
    vald = set(choices)
    for choice in choices:
        defstring = " (Default)" if choice == helper_data.default else ""
        if help_dict.get(choice, None):
            prntr(f"{choice} - {help_dict[choice].description}" + defstring)
        else:
            prntr(f"{choice}" + defstring)
    if helper_data.default is not None:
        prntr("To accept default just click enter. Otherwise specify value.")
    while True:
        ch = input(f"{arg}: ")
        if ch in vald:
            return ch
        if not ch and helper_data.default is not None:
            return helper_data.default
        prntr("Please select an option from the list.")


def input_handler(arg: str, mode: tuple[bool, bool], prntr: typing.Callable = print):
    helper_data = checkmodes(arg, mode)
    if not isinstance(helper_data, HelpData):
        return helper_data
    prntr(f"Please specify the {arg}!")
    prntr("Description: " + helper_data.description)
    if helper_data.default is not None:
        prntr(f"Default value: {helper_data.default}")
        prntr("To accept default just click enter. Otherwise specify value.")
    cls = helper_data.format
    while True:
        ch = input(f"{arg}: ")
        if not ch and helper_data.default is not None:
            return helper_data.default
        if ch == "":
            prntr("Please provide a value.")
            continue
        try:
            return cls(ch)
        except ValueError:
            prntr(f"We could not convert your value to {cls.__name__}.")


def check_message(mess: str, enc) -> str:
    """Parse message for path-notice."""
    if mess.startswith("P:"):
        mess = mess[2:]
        with open(mess, "r", encoding=enc) as f:
            mess = f.read()
    return mess


def main():
    """Core Hybrid CLI/ICLI (Command Line Interface/Interactive Command Lice Interface)"""
    args = corep.parse_args()
    pstatus = (args.non_interactive, args.advanced)

    def pspr(text: str):
        """Print only if not in non-interactive mode."""
        if not pstatus[0]:
            print(text)

    pspr("Welcome to RSA Utils!\n")
    if not args.subcommand:
        args.subcommand = choice_handler("subcommand", pstatus)
    for reqs in needs[args.subcommand]:
        if getattr(args, reqs, None) is None:
            if help_dict[reqs].choices is not None:
                res = choice_handler(reqs, pstatus)
            else:
                res = input_handler(reqs, pstatus)
            setattr(args, reqs, res)
        else:
            pspr(f"{reqs}: {getattr(args, reqs)}")
    pspr("\nInput Complete! Executing...")
    match args.subcommand:
        case "keygen":
            if args.private_key.exists() or args.public_key.exists():
                rs = getattr(args, "overwrite", None)
                if rs is None:
                    rs = choice_handler("overwrite", pstatus, pspr)
                if rs == "N":
                    print("Destination private or public key already exists!")
                    return
            rpk = rsautils.RSAPrivKey.generate(int(args.keysize), args.pub_exponent)
            rpk.export(args.private_key)
            rpk.pub.export(args.public_key)
            pspr("\nKey pair generated!")
        case "encrypt":
            args.message = check_message(args.message, args.encoding)
            rpu = rsautils.RSAPubKey.import_key(args.public_key)
            encm, enlb = args.message.encode(args.encoding), args.label.encode(args.encoding)
            ciph = rpu.encrypt(encm, enlb, args.sha, args.academic)
            pspr("Ciphertext:")
            print(ciph.decode("ascii"))
        case "decrypt":
            args.message = check_message(args.message, "ascii")
            rpk = rsautils.RSAPrivKey.import_key(args.private_key)
            encm, enlb = args.message.encode("ascii"), args.label.encode(args.encoding)
            clear = rpk.decrypt(encm, enlb)
            clear = clear.decode(args.encoding)
            pspr("Cleartext:")
            print(clear)
        case "sign":
            args.message = check_message(args.message, "utf-8")
            rpk = rsautils.RSAPrivKey.import_key(args.private_key)
            signature = rpk.sign(args.message, args.sha)
            pspr("Signature:")
            print(signature)
        case "verify":
            args.message = check_message(args.message, "utf-8")
            rpu = rsautils.RSAPubKey.import_key(args.public_key)
            if rpu.verify(args.message, args.signature):
                pspr("Signature Verified!")
            else:
                print("Signature Verification Failed!")
                sys.exit(1)
    pspr("Thank you for using RSA Utils!")
    pspr("Goodbye!")


if __name__ == "__main__":
    main()
