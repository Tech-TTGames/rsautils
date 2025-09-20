"""Provides core RSA functionalities, such as encryption, decryption, signing and verification.

Facilitates core RSA, currently solely under "textbook" RSA conditions. Handles the general key handling as well as
some supporting functions such as key import/export and miscellaneous preset functions to handle encoding and
marshalling.
"""
import base64
import hashlib
import pathlib

from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.codec.native import decoder as translate
from pyasn1.type import univ
from pyasn1_modules import rfc5208
from pyasn1_modules import rfc8017

from rsautils import keygen

HASH_TLL = {
    "sha256": (hashlib.sha256, rfc8017.id_sha256),
    "sha384": (hashlib.sha384, rfc8017.id_sha384),
    "sha512": (hashlib.sha512, rfc8017.id_sha512),
}
HASH_OID = {
    rfc8017.id_sha256: hashlib.sha256,
    rfc8017.id_sha384: hashlib.sha384,
    rfc8017.id_sha512: hashlib.sha512,
}

PEM_TYPES = {
    "PKCS1_PRIV": ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
    "PKCS1_PUB": ("-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"),
    "PKCS8": ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
}


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


class RSAPubKey(RSAKey):
    """A rather straightforward subclass of RSAKey, for Public Keys.

    The init is not overwritten as a Public Key consists solely of a modulus and exponent.
    But provides the general functions expected of a public key.
    """

    def encrypt(self, message: str, enc: str = "utf-8") -> str:
        """Use the public key to encrypt the message.

        Args:
            message: The message to encrypt.
            enc: The encoding standard to use.

        Returns:
            Base64 encoded encrypted message.
        """
        enco = marshal_str(message, enc)
        ciphertext = _encrypt(enco, self)
        return b64_enc(ciphertext, self.mod.bit_length())

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
        decr_int = _decrypt(signature_int, self)
        rec_bytes = decr_int.to_bytes(((decr_int.bit_length() + 7) // 8), byteorder="big")
        payload, _ = decoder.decode(rec_bytes, asn1Spec=rfc8017.DigestInfo())
        hasher = HASH_OID[payload["digestAlgorithm"]["algorithm"]]
        hashd = payload["digest"]
        return hasher(message.encode()).digest() == hashd

    def export(self, file: pathlib.Path) -> None:
        """Export the Public RSA key to file.

        We use the PKCS1 export standard for the public key, due to its lack of information regarding identity.

        Args:
            file: The file to export the public key to.
        """
        keydata = {"modulus": self.mod, "publicExponent": self.expo}
        translated = translate.decode(keydata, asn1Spec=rfc8017.RSAPublicKey())
        encdata = encoder.encode(translated)
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
        return cls(keydata["modulus"], keydata["publicExponent"])


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
                 p: int,
                 q: int,
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
        self.p: int = p
        self.q: int = q
        self.exp1: int = exp1 if exp1 is not None else priv_exp % (p - 1)
        self.exp2: int = exp2 if exp2 is not None else priv_exp % (q - 1)
        self.coeff: int = coeff if coeff is not None else pow(q, -1, p)

    def decrypt(self, message: str, enc: str = "utf-8") -> str:
        """Decrypts the message using the private key.

        Runs standard RSA decryption on the provided message.

        Args:
            message: Base64 encoded message to decrypt
            enc: The encoding to use.

        Returns:
            The decrypted message.
        """
        ctext = b64_dec(message)
        payload = _decrypt(ctext, self)
        return unmarshal_int(payload, enc)

    def sign(self, message: str, sha: str = "sha384") -> str:
        """Signs the message using the private key.

        As noted in verify, we pack our signature in a wrapper to specify the details of our SHA algorithm.

        Args:
            message: Base64 encoded message to sign
            sha: The SHA algorithm to use.

        Returns:
            The base64 encoded message signature.
        """
        hasher, ident = HASH_TLL[sha]
        hashed = hasher(message.encode()).digest()
        algid = {"algorithm": ident, "parameters": univ.Null("")}
        tld_algid = translate.decode(algid, asn1Spec=rfc8017.DigestAlgorithm())
        payload = {"digestAlgorithm": tld_algid, "digest": hashed}
        tld = translate.decode(payload, asn1Spec=rfc8017.DigestInfo())
        encoded = int.from_bytes(encoder.encode(tld), byteorder="big")
        signature = _encrypt(encoded, self)
        return b64_enc(signature, self.mod.bit_length())

    def export(self, file: pathlib.Path) -> None:
        """Exports the RSA Private Key to a file.

        Here we follow the PKCS8 private key export convention, to allow for interoperability with different RSA
        key consumption apps.

        Args:
            file: The file to export to.
        """
        interkey = {
            "version": 0,
            "modulus": self.mod,
            "publicExponent": self.pub.expo,
            "privateExponent": self.expo,
            "prime1": self.p,
            "prime2": self.q,
            "exponent1": self.exp1,
            "exponent2": self.exp2,
            "coefficient": self.coeff,
        }
        translated = translate.decode(interkey, asn1Spec=rfc8017.RSAPrivateKey())
        encoded = encoder.encode(translated)
        pkalgo = {"algorithm": rfc8017.rsaEncryption, "parameters": univ.Null("")}
        tl_pkalgo = translate.decode(pkalgo, asn1Spec=rfc5208.AlgorithmIdentifier())
        pkraw = {"version": 0, "privateKeyAlgorithm": tl_pkalgo, "privateKey": encoded}
        f_translate = translate.decode(pkraw, asn1Spec=rfc5208.PrivateKeyInfo())
        final = encoder.encode(f_translate)
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
        return cls(keydata["modulus"], keydata["publicExponent"], keydata["privateExponent"], keydata["prime1"],
                   keydata["prime2"], keydata["exponent1"], keydata["exponent2"], keydata["coefficient"])

    @classmethod
    def generate(cls, size: int, pub_exp: int =65537) -> "RSAPrivKey":
        """Generates a RSA Private Key, and it's respective Public Key.

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


def _encrypt(plaintext: int, key: RSAKey) -> int:
    """Performs core RSA encryption.

    Placed as a separate function to allow for easier global enhancement to encryption protocol.
    If a private key is provided this acts as a signature, if a public key is provided, as the name suggest this will
    be the colloquial encryption.

    Args:
        plaintext: The int-marshalled plaintext to encrypt
        key: The RSA key to use

    Returns:
        The encrypted plaintext
    """
    return pow(plaintext, key.expo, key.mod)


def _decrypt(ciphertext: int, key: RSAKey) -> int:
    """Performs core RSA decryption.

    Placed as a separate function to allow for easier expansion if we later add padded-signing options.
    If a public key is provided this acts as a verification of signature, if a private key is provided as the name
    suggest a standard decryption occurs.

    Args:
        ciphertext: The int-marshalled ciphertext to be decrypted.
        key: The RSA key to use.

    Returns:
        The decrypted message.
    """
    return pow(ciphertext, key.expo, key.mod)


def marshal_str(msg: str, enc: str = "utf-8") -> int:
    """Marshals a specified message to an int.

    Due to the predominant use of english we just use UTF-8 rather than 16, for both good handling of any non-english
    characters (unlike ASCII) and moderately decent at storing data effectively.

    Args:
        msg: The message to marshal into an int.
        enc: The encoding to use. Default is "utf-8".

    Returns:
        int: The marshalled message.
    """
    encd = msg.encode(enc)
    return int.from_bytes(encd, byteorder="big")


def unmarshal_int(msg: int, enc: str = "utf-8") -> str:
    """Unmarshal a specified message from an int.

    The inverse of the `marshal_str` function above. Not much more to say.

    Args:
        msg: The message to unmarshal from an int.
        enc: The encoding to use. Default is "utf-8".

    Returns:
        str: The unmarshalled message.
    """
    decd = msg.to_bytes((msg.bit_length() + 7) // 8, byteorder="big")
    return str(decd.decode(enc))


def b64_enc(msg: int, msg_size: int) -> str:
    """Encodes an integer into a base64 string.

    Args:
        msg: The message to encode.
        msg_size: The size of the encoded message in bits.

    Returns:
        A base64 encoded string.
    """
    bvtesize = (msg_size + 7) // 8
    return base64.b64encode(msg.to_bytes(bvtesize, "big", signed=False)).decode("ascii")


def b64_dec(msg: str) -> int:
    """Decodes a base64 encoded string into an int.

    Args:
        msg: The base64 encoded string.

    Returns:
        The decoded int.
    """
    return int.from_bytes(base64.b64decode(msg.encode("ascii")), "big", signed=False)
