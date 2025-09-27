"""Provides core RSA functionalities, such as encryption, decryption, signing and verification.

Facilitates core RSA, currently solely under "textbook" RSA conditions. Handles the general key handling as well as
some supporting functions such as key import/export and miscellaneous preset functions to handle encoding and
marshalling.

Typical usage example:

    pk = RSAPrivKey.generate(3072)
    c = pk.pub.encrypt("Hi there!")
    r = pk.decrypt(c)
"""
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import base64
import hashlib
from math import ceil
import pathlib
from secrets import token_bytes
import warnings

from pyasn1 import error
from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.codec.native import encoder as localize
from pyasn1.type import namedtype
from pyasn1.type import univ
from pyasn1_modules import rfc4055
from pyasn1_modules import rfc5208
from pyasn1_modules import rfc8017

from rsautils import keygen

HASH_TLL = {
    "sha256": (hashlib.sha256, rfc8017.id_sha256, 32, 2**61 - 1),
    "sha384": (hashlib.sha384, rfc8017.id_sha384, 48, 2**125 - 1),
    "sha512": (hashlib.sha512, rfc8017.id_sha512, 64, 2**125 - 1),
}

HASH_OID = {
    rfc8017.id_sha256: ("sha256", rfc4055.rSAES_OAEP_SHA256_Identifier),
    rfc8017.id_sha384: ("sha384", rfc4055.rSAES_OAEP_SHA384_Identifier),
    rfc8017.id_sha512: ("sha512", rfc4055.rSAES_OAEP_SHA512_Identifier),
}

PEM_TYPES = {
    "PKCS1_PRIV": ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
    "PKCS1_PUB": ("-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"),
    "PKCS8": ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
}

# No real OID exists for pure RSAEP, so we extend the "baseline" rsaEncryption (PKCS v1.5 padded) to branch 0
id_RSAES_pure = rfc8017.rsaEncryption + (0,)


class RSAMessage(univ.Sequence):
    """Due to the unfortunate fact that no RSA-based encryption wrapper exists we make our own!"""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("encryptionAlgorithm", rfc8017.AlgorithmIdentifier()),
        namedtype.NamedType("encryptedData", univ.OctetString()),
    )


class RSAKey:
    """The overall RSA key class implementation.

    Acts mostly as a template for the "core" components of a RSA Key that are strictly mandatory in both a public
    and a private key.

    Attributes:
        mod: The modulus of the keypair.
        expo: The exponent of the key, whether private or public.
    """

    def __init__(self, mod: int, expo: int) -> None:
        self.mod = mod
        self.expo = expo
        self.bsize = (self.mod.bit_length() + 7) // 8

    def c_rsa(self, message: int) -> int:
        """Performs core RSA operation. (Encrypt/Decrypt/Sign/Verify).

        Baseline RSA Primitive for encryption purposes.

        Args:
            message: The int-marshalled message to encrypt

        Returns:
            The encrypted message

        Raises:
            ValueError: If the message is out of range for the current key.
        """
        if not 0 <= message < self.mod:
            raise ValueError("Message representative must be in range [0, mod-1]")
        return pow(message, self.expo, self.mod)


class RSAPubKey(RSAKey):
    """A rather straightforward subclass of RSAKey, for Public Keys.

    The init is not overwritten as a Public Key consists solely of a modulus and exponent.
    But provides the general functions expected of a public key.
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
        db_msk = mgf1(seed, self.bsize - hlen - 1, hashf)
        mdb = xorbytes(db, db_msk)
        seed_msk = mgf1(mdb, hlen, hashf)
        mseed = xorbytes(seed, seed_msk)
        em = bytes_to_integer(b"\x00" + mseed + mdb)
        cm = self.c_rsa(em)
        return integer_to_bytes(cm, self.bsize)

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
            warnings.warn("Academic encryption is unsecure! Please use with care.", RuntimeWarning)
            enco = bytes_to_integer(message)
            ciphertext = integer_to_bytes(self.c_rsa(enco), self.bsize)
            enc_id = rfc8017.AlgorithmIdentifier()
            enc_id["algorithm"] = id_RSAES_pure
            enc_id["parameters"] = univ.Null("")
        else:
            ident = HASH_OID[HASH_TLL[hashf][1]][1]
            ciphertext = self.enc_oaep(message, label, hashf)
            enc_id = ident
        pld = RSAMessage()
        pld["encryptionAlgorithm"] = enc_id
        pld["encryptedData"] = ciphertext
        encoded = encoder.encode(pld)
        return base64.b64encode(encoded)

    def verify(self, message: str, signature: str) -> bool:
        """Verify the signature of the message.

        In a prep-step for us, we are using a wrapped-signature, so here we decode it do "get" which SHA algorithm is
        used to generate the hash that was signed.

        Args:
            message: The message to verify the signature against.
            signature: The base64 encoded signature to verify.

        Returns:
            True if the signature matches the signature of the message, False otherwise.
        """
        signature_int = b64_dec(signature)
        decr_int = self.c_rsa(signature_int)
        rec_bytes = integer_to_bytes(decr_int, self.bsize)
        if rec_bytes[0:2] != b"\x00\x01":
            return False
        rec_bytes = rec_bytes[2:]
        try:
            li = rec_bytes.index(b"\x00")
        except ValueError:
            return False
        ps = rec_bytes[0:li]
        if not ps or not all(b == 0xff for b in ps) or len(ps) < 8:
            return False
        en_payload = rec_bytes[li + 1:]
        try:
            payload, _ = decoder.decode(en_payload, asn1Spec=rfc8017.DigestInfo())
            hasher = HASH_TLL[HASH_OID[payload["digestAlgorithm"]["algorithm"]][0]][0]
            hashd = payload["digest"]
            return hasher(message.encode()).digest() == hashd
        except (error.PyAsn1Error, KeyError):
            return False

    def export(self, file: pathlib.Path) -> None:
        """Export the Public RSA key to file.

        We use the PKCS1 export standard for the public key, due to its lack of information regarding identity.

        Args:
            file: The file to export the public key to.
        """
        keydata = rfc8017.RSAPublicKey()
        keydata["modulus"] = self.mod
        keydata["publicExponent"] = self.expo
        encdata = encoder.encode(keydata)
        write_pem(file, "PKCS1_PUB", encdata)

    @classmethod
    def import_key(cls, file: pathlib.Path) -> "RSAPubKey":
        """Import the Public RSA key from file.

        As with the export we use the PKCS1 export standard.

        Args:
            file: The file to import the public key from.

        Returns:
            An RSAPubKey object with the imported public key.
        """
        payload = read_pem(file, "PKCS1_PUB")
        keydata, _ = decoder.decode(payload, asn1Spec=rfc8017.RSAPublicKey())
        pykeyd = localize.encode(keydata)
        return cls(pykeyd["modulus"], pykeyd["publicExponent"])


class RSAPrivKey(RSAKey):
    """RSA Private Key class implementation.

    Modifies the baseline RSAKey class to provide private-key specific attributes, even if they are not strictly
    necessary for it's functioning but are considered the "industry standard" for private keys. Implements
    both functions expected of a private key and exposes its connected public key.

    Attributes:
        mod: The modulus of the keypair.
        expo: The private exponent of the key.
        pub: The public key of the key.
        p: Private Prime 1.
        q: Private Prime 2.
    """

    def __init__(self,
                 mod: int,
                 pub_exp: int,
                 priv_exp: int,
                 p: int | None = None,
                 q: int | None = None,
                 exp1: int | None = None,
                 exp2: int | None = None,
                 coeff: int | None = None) -> None:
        """Initialize the RSA Private Key.

        Args:
            mod: The modulus of the keypair.
            pub_exp: The public exponent of the key.
            priv_exp: The private exponent of the key.
            p: The private prime 1.
            q: The private prime 2.
            exp1: CRT Component dmp1.
            exp2: CRT Component dmq1.
            coeff: CRT Component iqmp.
        """
        super().__init__(mod, priv_exp)
        self.pub: RSAPubKey = RSAPubKey(mod, pub_exp)
        self.p: int | None = None
        self.q: int | None = None
        self.exp1: int | None = None
        self.exp2: int | None = None
        self.coeff: int | None = None
        if p and q:
            self.p = p
            self.q = q
            self.exp1 = exp1 if exp1 is not None else priv_exp % (p - 1)
            self.exp2 = exp2 if exp2 is not None else priv_exp % (q - 1)
            self.coeff = coeff if coeff is not None else pow(q, -1, p)

    def c_rsa(self, message: int) -> int:
        """Performs core RSA operation accelerated with CRT. (Decrypt/Sign)

        The underlying RSA primitive to decrypt/sing the message.

        Args:
            message: The int-marshalled message to encrypt

        Returns:
            The encrypted message

        Raises:
            ValueError: If the message is out of range for the current key.
        """
        if not self.p or not self.q:
            return super().c_rsa(message)
        if not 0 <= message < self.mod:
            raise ValueError("Message representative must be in range [0, mod-1]")
        m_1 = pow(message, self.exp1, self.p)
        m_2 = pow(message, self.exp2, self.q)
        h = ((m_1 - m_2) * self.coeff) % self.p
        m = m_2 + self.q * h
        return m

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
        valid = True
        if em[0:1] != b"\x00":
            valid = False
        mseed = em[1:hlen + 1]
        mdb = em[hlen + 1:]
        seed_msk = mgf1(mdb, hlen, hashf)
        seed = xorbytes(mseed, seed_msk)
        db_msk = mgf1(seed, self.bsize - hlen - 1, hashf)
        db = xorbytes(mdb, db_msk)
        if db[0:hlen] != lh:
            valid = False
        mrkr = None
        for by in range(hlen, len(db)):
            if db[by:by + 1] == b"\x01" and mrkr is None:
                mrkr = by
            if db[by:by + 1] != b"\x00" and mrkr is None:
                valid = False
        if mrkr is None or not valid:
            raise RuntimeError("Decryption error.")
        return db[mrkr + 1:]

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
            hashf = HASH_OID[params["hashFunc"]["algorithm"]][0]
            bts = self.oaep_decrypt(ctx, label, hashf)
        else:
            raise RuntimeError("Unknown encryption algorithm.")
        return bts

    def sign(self, message: str, sha: str = "sha384") -> str:
        """Signs the message using the private key.

        As noted in verify, we pack our signature in a wrapper to specify the details of our SHA algorithm.

        Args:
            message: Base64 encoded message to sign
            sha: The SHA algorithm to use.

        Returns:
            The base64 encoded message signature.
        """
        hasher, ident, _, _ = HASH_TLL[sha]
        hashed = hasher(message.encode()).digest()
        algid = rfc8017.DigestAlgorithm()
        algid["algorithm"] = ident
        algid["parameters"] = univ.Null("")
        payload = rfc8017.DigestInfo()
        payload["digestAlgorithm"] = algid
        payload["digest"] = hashed
        encoded = encoder.encode(payload)
        if self.bsize < len(encoded) + 11:
            raise RuntimeError("Hash function too large for current key.")
        ps = b"\xFF" * (self.bsize - len(encoded) - 3)
        em = bytes_to_integer(b"\x00\x01" + ps + b"\x00" + encoded)
        signature = self.c_rsa(em)
        return b64_enc(signature, self.bsize)

    def export(self, file: pathlib.Path) -> None:
        """Exports the RSA Private Key to a file.

        Here we follow the PKCS8 private key export convention, to allow for interoperability with different RSA
        key consumption apps.

        Args:
            file: The file to export to.
        """
        if not self.p or not self.q:
            raise NotImplementedError("Due to lack of specifications CRT-less key export is currently not supported.")
        interkey = rfc8017.RSAPrivateKey()
        interkey["version"] = 0
        interkey["modulus"] = self.mod
        interkey["publicExponent"] = self.pub.expo
        interkey["privateExponent"] = self.expo
        interkey["prime1"] = self.p
        interkey["prime2"] = self.q
        interkey["exponent1"] = self.exp1
        interkey["exponent2"] = self.exp2
        interkey["coefficient"] = self.coeff
        encoded = encoder.encode(interkey)
        pkalgo = rfc5208.AlgorithmIdentifier()
        pkalgo["algorithm"] = rfc8017.rsaEncryption
        pkalgo["parameters"] = univ.Null("")
        pkraw = rfc5208.PrivateKeyInfo()
        pkraw["version"] = 0
        pkraw["privateKeyAlgorithm"] = pkalgo
        pkraw["privateKey"] = encoded
        final = encoder.encode(pkraw)
        write_pem(file, "PKCS8", final)

    @classmethod
    def import_key(cls, file: pathlib.Path) -> "RSAPrivKey":
        """Imports the RSA Private Key from a file.

        Recognizes solely PKCS8 RSA files, without multi-prime handling. Those are the keys we handle so all is well.

        Args
            file: The file to import.

        Returns:
            The imported RSA Private Key.
        """
        payload = read_pem(file, "PKCS8")
        decdata, _ = decoder.decode(payload, asn1Spec=rfc5208.PrivateKeyInfo())
        if decdata["version"] != 0:
            raise IOError("Unsupported version of private key information wrapper")
        if decdata["privateKeyAlgorithm"][0] != rfc8017.rsaEncryption:
            raise IOError("Private Key Algorithm not supported.")
        keydata, _ = decoder.decode(decdata["privateKey"], asn1Spec=rfc8017.RSAPrivateKey())
        if keydata["version"] != 0:
            raise IOError("Multi-prime keys are not supported.")
        pykeyd = localize.encode(keydata)
        return cls(pykeyd["modulus"], pykeyd["publicExponent"], pykeyd["privateExponent"], pykeyd["prime1"],
                   pykeyd["prime2"], pykeyd["exponent1"], pykeyd["exponent2"], pykeyd["coefficient"])

    @classmethod
    def generate(cls, size: int, pub_exp: int = 65537) -> "RSAPrivKey":
        """Generates an RSA Private Key, and it's respective Public Key.

        Generates a whole RSA Keypair within the RSAPrivKey instance.

        Args:
            size: The size of the RSA Key.
            pub_exp: The public exponent of the key.

        Returns:
            A new generated RSA Private Key.
        """
        (n, pub), (_, d, p, q) = keygen.generate_key_pair(size, pub_exp, True)
        return cls(n, pub, d, p, q)


def read_pem(file: pathlib.Path, subtype: str) -> bytes:
    """Reads a PEM encoded file.

    Handles reading of PEM files to allow for more copiable keys!

    Args:
        file: The file to read.
        subtype: The subtype of PEM encoding to accept.

    Returns:
        The decoded PEM encoded file.

    Raises:
        IOError: If the file has invalid PEM encoding.
    """
    curr_type = PEM_TYPES[subtype]
    with open(file, "r", encoding="ascii") as f:
        headline = f.readline().strip()
        if headline != curr_type[0]:
            raise IOError(f"PEM Headline {headline} does not match {curr_type[0]}")
        parcel = []
        while True:
            line = f.readline().strip()
            if not line:
                raise IOError(f"PEM File does not contain footer: {curr_type[1]}")
            if line == curr_type[1]:
                break
            parcel.append(line)
    return base64.b64decode("".join(parcel))


def write_pem(file: pathlib.Path, subtype: str, data: bytes) -> None:
    """Writes a PEM encoded file.

    Allows for standardized movement of keys etc.

    Args:
        file: The file to write.
        subtype: The subtype of PEM encoding to write.
        data: The data to write.
    """
    curr_type = PEM_TYPES[subtype]
    payload = base64.b64encode(data).decode()
    with open(file, "w", encoding="ascii") as f:
        f.write(curr_type[0] + "\n")
        res = "\n".join(payload[i:i + 64] for i in range(0, len(payload), 64))
        res += "\n" if res else ""
        f.write(res)
        f.write(curr_type[1] + "\n")


def bytes_to_integer(msg: bytes) -> int:
    """Converts a byte string to an integer in accordance to preset procedures.

    Args:
        msg: The bytes (AKA Octet String) to convert.

    Returns:
        The representative integer.
    """
    return int.from_bytes(msg, byteorder="big", signed=False)


def integer_to_bytes(msg: int, fixedlen: int) -> bytes:
    """Converts an integer to a string, using a fixed-length byte representation.

    Args:
        msg: The integer to unmarshal.
        fixedlen: The target length of the byte string.

    Returns:
        The representative bytes. (AKA Octet String)
    """
    return msg.to_bytes(fixedlen, byteorder="big", signed=False)


def b64_enc(msg: int, msg_size: int) -> str:
    """Encodes an integer into a base64 string.

    Args:
        msg: The message to encode.
        msg_size: The size of the encoded message in bits.

    Returns:
        A base64 encoded string.
    """
    return base64.b64encode(integer_to_bytes(msg, msg_size)).decode("ascii")


def b64_dec(msg: str) -> int:
    """Decodes a base64 encoded string into an int.

    Args:
        msg: The base64 encoded string.

    Returns:
        The decoded int.
    """
    return bytes_to_integer(base64.b64decode(msg.encode("ascii")))


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
    for cnt in range(ceil(masklen / hlen)):
        c = integer_to_bytes(cnt, 4)
        t += fun(mgfseed + c).digest()
    return t[:masklen]
