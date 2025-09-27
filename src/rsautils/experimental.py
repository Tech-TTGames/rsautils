"""Experimental functions' module. Currently, covers: Non-Academic RSA

This module is the temporary home for any functions that are not yet finished or otherwise Work-In-Progress and are
not covered in specdoc.md as a "Core" function, but a stretch goal.
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import base64
import hashlib
import math
from secrets import token_bytes

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1_modules import rfc4055
from pyasn1_modules import rfc8017

from rsautils.rsa import bytes_to_integer
from rsautils.rsa import integer_to_bytes
from rsautils.rsa import RSAPrivKey
from rsautils.rsa import RSAPubKey

HASH_TLL = {
    "sha256": (hashlib.sha256, rfc4055.rSAES_OAEP_SHA256_Identifier, 32, 2**61 - 1),
    "sha384": (hashlib.sha384, rfc4055.rSAES_OAEP_SHA384_Identifier, 48, 2**125 - 1),
    "sha512": (hashlib.sha512, rfc4055.rSAES_OAEP_SHA512_Identifier, 64, 2**125 - 1),
}  # TODO: Update sign when moving to core

HASH_OID = {
    rfc8017.id_sha256: "sha256",
    rfc8017.id_sha384: "sha384",
    rfc8017.id_sha512: "sha512",
}  # TODO: Update verify when moving to core

# No real OID exists for pure RSAEP, so we extend the "baseline" rsaEncryption (PKCS v1.5 padded) to branch 0
id_RSAES_pure = rfc8017.rsaEncryption + (0,)


class RSAMessage(univ.Sequence):
    """Due to the unfortunate fact that no RSA-based encryption wrapper exists we make our own!"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("encryptionAlgorithm", rfc8017.AlgorithmIdentifier()),
        namedtype.NamedType("encryptedData", univ.OctetString()),
    )


def xorbytes(a: bytes, b: bytes) -> bytes:
    """XOR bitwise for bytes.

    Requires two byte strings of equal length.

    Args:
        a: byte string
        b: byte string

    Returns:
        xor byte string
    """
    return bytes(a ^ b for a, b in zip(a, b, strict=True))


def mgf1(mgfseed: bytes, masklen: int, hashf: str = "sha384") -> bytes:
    """The PKCS#1 v2.2 Mask Generation Function 1.

    Implemented according to the spec, does what says on the tin, generates a mask based on provided data,
    using the specified hash function.

    Args:
        mgfseed: Seed for mask generation
        masklen: Intended length of mask
        hashf: Hash function (Implemented for sha256, sha384, sha512)

    Returns:
        The mask in form of bytes of length masklen.

    Raises:
        ValueError: If mask too long for the combination of values.
    """
    fun, _, hlen, _ = HASH_TLL[hashf]
    if masklen > 2**32 * hlen:
        raise ValueError("Mask too long for the specified hash function")
    t = b""
    for cnt in range(math.ceil(masklen / hlen)):
        c = integer_to_bytes(cnt, 32)
        t += fun(mgfseed + c).digest()
    return t[:masklen]


class ExperimentalPubKey(RSAPubKey):
    """Experimental RSA Public Key.

    Implements all functions of the RSAPubKey class, with a set of overrides or extra functionality.
    Is not considered stable or at all finished.
    """

    def enc_oaep(self, message: bytes, label: bytes = b"", hashf: str = "sha384") -> bytes:
        """Encrypts the message according to the RSAES-OAEP algorithm.

        Args:
            message: Message to be encrypted
            label: Optional label for the message
            hashf: Hash function (Implemented for sha256, sha384, sha512)

        Returns:
            Padded and encrypted message

        Raises:
            ValueError: If label or message too long for the hash function.
        """
        fun, _, hlen, hcap = HASH_TLL[hashf]
        if len(label) > hcap:
            raise ValueError("Label too long for the specified hash function")
        if len(message) > self.bsize - 2 * (hlen + 1):
            raise ValueError("Message too long for the specified hash function")
        lh = fun(label).digest()
        pad = b"\x00" * (self.bsize - len(message) - 2 * (hlen + 1))
        db: bytes = lh + pad + b"\x01" + message
        seed = token_bytes(hlen)
        db_msk = mgf1(seed, self.bsize - hlen - 1)
        mdb = xorbytes(db, db_msk)
        seed_msk = mgf1(mdb, hlen)
        mseed = xorbytes(seed, seed_msk)
        em = bytes_to_integer(b"\x00" + mseed + mdb)
        cm = self.c_rsa(em)
        return integer_to_bytes(cm, self.bsize)

    # pylint: disable-next=arguments-renamed
    def encrypt(self, message: bytes, label: bytes = b"", hashf: str = "sha384", academic: bool = False) -> bytes:
        """Use the public key to encrypt the message.

        Args:
            message: The message to encrypt.
            label: Optional label for the message. Used to authenticate the message during decryption.
            hashf: Hash function (Implemented for sha256, sha384, sha512)
            academic: If true, use academic encryption.
                Warning! Unsecure!

        Returns:
            Base64 encoded encrypted message.
        """
        if academic:
            enco = bytes_to_integer(message)
            ciphertext = integer_to_bytes(self.c_rsa(enco), self.bsize)
            enc_id = rfc8017.AlgorithmIdentifier()
            enc_id["algorithm"] = id_RSAES_pure
            enc_id["parameters"] = univ.Null("")
        else:
            _, ident, _, _ = HASH_TLL[hashf]
            ciphertext = self.enc_oaep(message, label, hashf)
            enc_id = ident
        pld = RSAMessage()
        pld["encryptionAlgorithm"] = enc_id
        pld["encryptedData"] = ciphertext
        encoded = encoder.encode(pld)
        return base64.b64encode(encoded)


class ExperimentalPrivKey(RSAPrivKey):
    """Experimental RSA Private Key.

    Implements all functions of the RSAPrivKey class, with a set of overrides or extra functionality.
    Is not considered stable or at all finished.
    """

    def oaep_decrypt(self, ciphertext: bytes, label: bytes = b"", hashf: str = "sha384") -> bytes:
        """Decrypts the message according to the RSAES-OAEP algorithm.

        Args:
            ciphertext: Message to be decrypted.
            label: Optional label for the message
            hashf: Hash function (Implemented for sha256, sha384, sha512)

        Returns:
            Decrypted message

        Raises:
            RuntimeError: If decryption fails.
        """
        fun, _, hlen, hcap = HASH_TLL[hashf]
        if len(label) > hcap:
            raise RuntimeError("Label too long for specified hash function.")
        if len(ciphertext) != self.bsize:
            raise RuntimeError("Message does not match expected length.")
        if self.bsize < 2 * (hlen + 1):
            raise RuntimeError("Message too long for specified hash function.")
        ci = bytes_to_integer(ciphertext)
        m = self.c_rsa(ci)
        em = integer_to_bytes(m, self.bsize)
        lh = fun(label).digest()
        if em[0:1] != b"\x00":
            raise RuntimeError("Decryption error.")
        mseed = em[1:hlen + 1]
        mdb = em[hlen + 1:]
        seed_msk = mgf1(mdb, hlen)
        seed = xorbytes(mseed, seed_msk)
        db_msk = mgf1(seed, self.bsize - hlen - 1)
        db = xorbytes(mdb, db_msk)
        if db[0:hlen] != lh:
            raise RuntimeError("Decryption error.")
        mrkr = None
        for by in range(hlen, len(db)):
            if db[by:by + 1] == b"\x01":
                mrkr = by
                break
            if db[by:by + 1] != b"\x00":
                break
        if mrkr is None:
            raise RuntimeError("Decryption error.")
        return db[mrkr + 1:]

    # pylint: disable-next=arguments-renamed
    def decrypt(self, message: bytes, label: bytes = b"") -> bytes:
        """Decrypts the message using the private key.

        Runs standard RSA decryption on the provided message.

        Args:
            message: Base64 encoded message to decrypt
            label: Optional label for the message to authenticate validity.

        Returns:
            The decrypted message.
        """
        ctext = base64.b64decode(message)
        pld, _ = decoder.decode(ctext, asn1Spec=RSAMessage())
        ctx = pld["encryptedData"]
        if pld["encryptionAlgorithm"]["algorithm"] == id_RSAES_pure:
            payload = self.c_rsa(bytes_to_integer(ctx))
            bts = integer_to_bytes(payload, self.bsize).lstrip(b"\x00")
        elif pld["encryptionAlgorithm"]["algorithm"] == rfc8017.id_RSAES_OAEP:
            params, _ = decoder.decode(pld["encryptionAlgorithm"]["parameters"], asn1Spec=rfc8017.RSAES_OAEP_params())
            hashf = HASH_OID[params["hashFunc"]["algorithm"]]
            bts = self.oaep_decrypt(ctx, label, hashf)
        else:
            raise RuntimeError("Unknown encryption algorithm.")
        return bts
