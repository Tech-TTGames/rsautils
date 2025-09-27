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

# key: subcommand or parameter
# value: "Brief Description", type/choices or None if a subcommand, ("Advanced Parameter?", Default Value)
help_dict: dict[str, tuple[str, list[str] | type | None, tuple[bool, typing.Any]]] = {
    "subcommand": ("The available subcommands in RSA Utils", ["keygen", "encrypt", "decrypt", "sign",
                                                              "verify"], (False, None)),
    "public_key": ("Location of the public key file", pathlib.Path, (False, None)),
    "private_key": ("Location of the private key file", pathlib.Path, (False, None)),
    "message": ("Message or path to file containing payload. If Path start with `P:`", str, (False, None)),
    "label": ("Ecrypted payload label. Used to verify during decryption.", str, (True, "")),
    "encoding": ("Payload encoding", ["utf-8", "utf-16", "ascii"], (True, "utf-8")),
    "academic": ("Whether to use academic encryption. Warning! Unsecure.", bool, (True, False)),
    "keygen": ("Key generation utility", None, (False, None)),
    "keysize": ("Size of key in bits.", ["2048", "3072", "4096"], (False, "3072")),
    "pub_exponent": ("Exponent for public key", int, (True, 65537)),
    "encrypt": ("Encryption utility", None, (False, None)),
    "decrypt": ("Decryption utility", None, (False, None)),
    "sign": ("Signature utility", None, (False, None)),
    "sha": ("Specific SHA algorithm to use", ["sha256", "sha384", "sha512"], (True, "sha384")),
    "verify": ("Signature Verification utility", None, (False, None)),
    "signature": ("The signature to validate against the payload and public certificate.", str, (False, None)),
    "overwrite": ("Overwrite specified destination files if they exist?", str, ["Y", "N"], (False, "N")),
}

needs = {
    "keygen": ("public_key", "private_key", "keysize", "pub_exponent"),
    "encrypt": ("public_key", "message", "label", "sha", "academic", "encoding"),
    "decrypt": ("private_key", "message", "label", "encoding"),
    "sign": ("private_key", "message", "sha"),
    "verify": ("public_key", "message", "signature")
}


class SpecPrint:

    def __init__(self, mode: bool):
        self.mode = mode

    def __call__(self, mess: str):
        if not self.mode:
            print(mess)


pubkey = argparse.ArgumentParser(add_help=False)
pubkey.add_argument("--public_key", "-s", type=pathlib.Path, help=help_dict["public_key"][0])
privkey = argparse.ArgumentParser(add_help=False)
privkey.add_argument("--private_key", "-p", type=pathlib.Path, help=help_dict["private_key"][0])
payloads = argparse.ArgumentParser(add_help=False)
payloads.add_argument("--message", type=str, help=help_dict["message"][0])
encp = argparse.ArgumentParser(add_help=False)
encp.add_argument("--encoding", "-e", type=str, choices=help_dict["encoding"][1], help=help_dict["encoding"][0])
sha = argparse.ArgumentParser(add_help=False)
sha.add_argument("--sha", "-s", type=str, choices=help_dict["sha"][1], help=help_dict["sha"][0])
label = argparse.ArgumentParser(add_help=False)
label.add_argument("--label", "-l", type=str, choices=help_dict["label"][1], help=help_dict["label"][0])
corep = argparse.ArgumentParser(prog="rsautils")
corep.add_argument("--version", "-v", action="version", version=f"%(prog)s {rsautils.__version__}")
corep.add_argument("--non-interactive", "-n", action="store_true", help="Enable non-interactive mode")
corep.add_argument("--advanced", "-a", action="store_true", help="Enable advanced mode, for interactive mode")
commands = corep.add_subparsers(dest="subcommand", title="Subcommands")

keygen = commands.add_parser("keygen", parents=[privkey, pubkey], help=help_dict["keygen"][0])
keygen.add_argument("--keysize", type=str, choices=help_dict["keysize"][1], help=help_dict["keysize"][0])
keygen.add_argument("--pub-exponent", type=int, help=help_dict["pub_exponent"][0])
keygen.add_argument("--overwrite", "-o", action="store_const", const="Y", help=help_dict["overwrite"][0])

encrypt = commands.add_parser("encrypt", parents=[pubkey, payloads, label, sha, encp], help=help_dict["encrypt"][0])
encrypt.add_argument("--academic", "-A", action="store_true", help=help_dict["academic"][0])
decrypt = commands.add_parser("decrypt", parents=[privkey, payloads, label, encp], help=help_dict["decrypt"][0])

sign = commands.add_parser("sign", parents=[privkey, payloads, sha], help=help_dict["sign"][0])
verify = commands.add_parser("verify", parents=[pubkey, payloads], help=help_dict["verify"][0])
verify.add_argument("--signature", "-S", type=str, help=help_dict["signature"][0])


def checkmodes(arg: str, mode: tuple[bool, bool]):
    rw = help_dict[arg]
    if ((not mode[1]) or mode[0]) and rw[2][0]:
        return rw[2][1]
    if mode[0]:
        raise IOError("An argument is missing and non-interactive mode is active.")
    return rw


def choice_handler(arg: str, mode: tuple[bool, bool], prntr: typing.Callable = print):
    rw = checkmodes(arg, mode)
    if not isinstance(rw, tuple):
        return rw
    prntr(f"Please specify the {arg}!")
    prntr("Description: ", rw[0])
    choices = rw[1]
    vald = set(choices)
    for choice in choices:
        defstring = " (Default)" if choice == rw[2][1] else ""
        if help_dict.get(choice, None):
            prntr(f"{choice} - {help_dict[choice][0]}", defstring)
        else:
            prntr(f"{choice}", defstring)
    if rw[2][1] is not None:
        prntr("To accept default just click enter. Otherwise specify value.")
    while True:
        ch = input(f"{arg}: ")
        if ch in vald:
            return ch
        if not ch and rw[2][1] is not None:
            return rw[2][1]
        prntr("Please select an option from the list.")


def input_handler(arg: str, mode: tuple[bool, bool], prntr: typing.Callable = print):
    rw = checkmodes(arg, mode)
    if not isinstance(rw, tuple):
        return rw
    prntr(f"Please specify the {arg}!")
    prntr("Description: ", rw[0])
    if rw[2][1] is not None:
        prntr(f"Default value: {rw[2][1]}")
        prntr("To accept default just click enter. Otherwise specify value.")
    cls = rw[1]
    while True:
        ch = input(f"{arg}: ")
        if not ch and rw[2][1] is not None:
            return rw[2][1]
        if ch == "":
            prntr("Please provide a value.")
            continue
        try:
            return cls(ch)
        except ValueError:
            prntr(f"We could not convert your value to {cls.__name__}.")


def check_message(mess: str, enc) -> str:
    if mess.startswith("P:"):
        mess = mess[2:]
        with open(mess, "r", encoding=enc) as f:
            mess = f.read()
    return mess


def main():
    """Core Hybrid CLI/ICLI (Command Line Interface/Interactive Command Lice Interface)"""
    args = corep.parse_args()
    pstatus = (args.non_interactive, args.advanced)
    pspr = SpecPrint(pstatus[0])
    pspr("Welcome to RSA Utils!\n")
    if not args.subcommand:
        args.subcommand = choice_handler("subcommand", pstatus)
    for reqs in needs[args.subcommand]:
        if getattr(args, reqs, None) is None:
            if isinstance(help_dict[reqs][1], list):
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
            args.message = check_message(args.message, args.encoding)
            rpk = rsautils.RSAPrivKey.import_key(args.private_key)
            signature = rpk.sign(args.message, args.sha)
            pspr("Signature:")
            print(signature)
        case "verify":
            args.message = check_message(args.message, args.encoding)
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
