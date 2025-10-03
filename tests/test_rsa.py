# pylint: disable=missing-module-docstring,redefined-outer-name
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import base64
import binascii
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

import rsautils
import rsautils.rsa as rsau

TARGET_SIZES = [1024, 2048, 3072, 4096]
e = 65537
standard_payload = "The quick brown fox jumps over the lazy dog1234567890!@#$%^&*()-_=+[{}];:\\|<>,./?~`'\""
location = pathlib.Path(__file__).parent
known_keys = {}
for target in TARGET_SIZES:
    loc = location / "data" / f"rsa_{target}"
    with open(loc, "rb") as f:
        known_keys[target] = (serialization.load_pem_private_key(f.read(), None), loc)


@pytest.fixture(scope="module", params=TARGET_SIZES)
def keyset(request) -> tuple[rsa.RSAPrivateKey, pathlib.Path]:
    return known_keys[request.param]


@pytest.fixture(scope="module", params=rsau.HASH_TLL.keys())
def hashf(request) -> str:
    return request.param


@pytest.fixture(scope="module", params=[True, False])
def crt(request) -> bool:
    return request.param


def localize_keys(pk: rsa.RSAPrivateKey, crt: bool = True) -> tuple[rsau.RSAPubKey, rsau.RSAPrivKey]:
    privs = pk.private_numbers()
    pubs = pk.public_key().public_numbers()
    if crt:
        pkey = rsau.RSAPrivKey(pubs.n, pubs.e, privs.d, privs.p, privs.q, privs.dmp1, privs.dmq1, privs.iqmp)
    else:
        pkey = rsau.RSAPrivKey(pubs.n, pubs.e, privs.d)
    pubk = rsau.RSAPubKey(pubs.n, pubs.e)
    return pubk, pkey


def capload(hashf: str, keysz: int):
    """Returns a capped payload in bytes."""
    hlen = rsau.HASH_TLL[hashf][2]
    max_len = keysz - 2 * (hlen + 1)
    if max_len <= 0:
        pytest.skip(f"Key size {keysz} is too small for {hashf}.")
    return standard_payload.encode("utf-8")[:max_len]


def assert_pkeys_equal(rsautils_key: rsau.RSAPrivKey, crypto_key: rsa.RSAPrivateKey) -> None:
    """Multi-use equality assertion suite."""
    privs = crypto_key.private_numbers()
    pubs = crypto_key.public_key().public_numbers()
    pubkey = rsautils_key.pub
    assert pubkey.mod == pubs.n
    assert pubkey.expo == pubs.e
    assert rsautils_key.expo == privs.d
    assert rsautils_key.p == privs.p
    assert rsautils_key.q == privs.q
    assert rsautils_key.exp1 == privs.dmp1
    assert rsautils_key.exp2 == privs.dmq1
    assert rsautils_key.coeff == privs.iqmp


@pytest.mark.parametrize("keysize", TARGET_SIZES)
def test_private_generation(mocker, keysize):
    template_key = known_keys[keysize][0]
    pubs = template_key.public_key().public_numbers()
    privs = template_key.private_numbers()
    mocker.patch("rsautils.keygen.generate_key_pair",
                 return_value=((pubs.n, pubs.e), (pubs.n, privs.d, privs.p, privs.q)))
    reskey = rsau.RSAPrivKey.generate(keysize, pubs.e)
    assert_pkeys_equal(reskey, template_key)


def test_private_import(keyset):
    template_key, source = keyset
    reskey = rsau.RSAPrivKey.import_key(source)
    assert_pkeys_equal(reskey, template_key)


@pytest.mark.parametrize("errtp", ["pkalgo", "pkver", "wrapperver"])
def test_private_import_validates(errtp):
    fil = location / "data" / f"lie_{errtp}"
    with pytest.raises(IOError):
        rsautils.RSAPrivKey.import_key(fil)


def test_public_import(keyset):
    template_key, source = keyset
    pubs = template_key.public_key().public_numbers()
    pubkey = rsau.RSAPubKey.import_key(source.with_suffix(".pub"))
    assert pubkey.mod == pubs.n
    assert pubkey.expo == pubs.e


def test_private_export(keyset, tmp_path):
    template_key, pt = keyset
    pubs = template_key.public_key().public_numbers()
    privs = template_key.private_numbers()
    _, key = localize_keys(template_key)
    des = tmp_path / f"testkey_{pt.name}"
    key.export(des)
    with open(des, "rb") as fi:
        interkey = serialization.load_pem_private_key(fi.read(), None)
    assert interkey.private_numbers() == privs
    assert interkey.public_key().public_numbers() == pubs


def test_private_export_noncrt(keyset, tmp_path):
    _, priv = localize_keys(keyset[0], crt=False)
    with pytest.raises(NotImplementedError):
        priv.export(tmp_path)


def test_public_export(keyset, tmp_path):
    template_key, pt = keyset
    pubs = template_key.public_key().public_numbers()
    key = rsau.RSAPubKey(pubs.n, pubs.e)
    des = tmp_path / f"testkey_{pt.name}.pub"
    key.export(des)
    with open(des, "rb") as fi:
        interkey = serialization.load_pem_public_key(fi.read())
    assert interkey.public_numbers() == pubs


def test_encrypt_oaep(keyset, hashf):
    template_key = keyset[0]
    pubkey = localize_keys(template_key)[0]
    payload = capload(hashf, pubkey.bsize)
    ciphtext = pubkey.enc_oaep(payload, hashf=hashf)
    cr_hashf = getattr(hashes, hashf.upper())
    dec = template_key.decrypt(ciphtext,
                               padding.OAEP(mgf=padding.MGF1(algorithm=cr_hashf()), algorithm=cr_hashf(), label=None))
    assert dec == payload


def test_decrypt_oaep(keyset, hashf, crt):
    template_key = keyset[0]
    priv = localize_keys(template_key, crt=crt)[1]
    payload = capload(hashf, priv.bsize)
    cr_hashf = getattr(hashes, hashf.upper())
    ciphtext = template_key.public_key().encrypt(
        payload, padding.OAEP(mgf=padding.MGF1(algorithm=cr_hashf()), algorithm=cr_hashf(), label=None))
    dec = priv.dec_oaep(ciphtext, hashf=hashf)
    assert dec == payload


@pytest.mark.parametrize("public", [True, False])
def test_oaep_actions_validate(mocker, keyset, hashf, public):
    pubkey, priv = localize_keys(keyset[0])
    e1, e2, hlen, _ = rsau.HASH_TLL[hashf]
    fakehcap = pubkey.bsize + 1
    mocker.patch("rsautils.rsa.HASH_TLL", {hashf: (e1, e2, hlen, fakehcap)})
    if public:
        key = pubkey
        action = key.enc_oaep
        exp_exception = ValueError
        val = "long"
        overflower = b"A" * (key.bsize - 2 * hlen - 1)
    else:
        key = priv
        action = key.dec_oaep
        exp_exception = RuntimeError
        val = "short"
        overflower = b"A" * (2 * (hlen + 1))
        with pytest.raises(exp_exception, match="Message does not match expected length."):
            action(overflower, hashf=hashf)
        overflower = b"A" * (hlen + 1)
    with pytest.raises(exp_exception, match=f"Message too {val} for the specified hash function"):
        action(overflower, hashf=hashf)
    label = b"A" * (fakehcap + 1)
    with pytest.raises(exp_exception, match="Label too long for the specified hash function"):
        action(overflower, label, hashf)


def test_encrypt_decrypt(keyset, hashf, crt):
    pubkey, priv = localize_keys(keyset[0], crt)
    payload = capload(hashf, pubkey.bsize)
    ciphtext = pubkey.encrypt(payload, hashf=hashf)
    cleartext = priv.decrypt(ciphtext)
    assert cleartext == payload


def test_encrypt_decrypt_academic(keyset, crt):
    pubkey, priv = localize_keys(keyset[0], crt=crt)
    with pytest.warns(RuntimeWarning, match="Academic encryption is unsecure! Please use with care."):
        ciphtext = pubkey.encrypt(standard_payload.encode("utf-8"), academic=True)
    cleartext = priv.decrypt(ciphtext).decode("utf-8")
    assert cleartext == standard_payload


def test_encrypt_academic_verifies(keyset):
    pubkey = localize_keys(keyset[0])[0]
    with pytest.raises(ValueError, match="Label cannot be used with academic encryption"), pytest.warns(
            RuntimeWarning, match="Academic encryption is unsecure!"):
        pubkey.encrypt(standard_payload.encode("utf-8"), b"ALIE", academic=True)


def test_decrypt_validates(mocker, keyset, crt):
    priv = localize_keys(keyset[0], crt=crt)[1]
    # We use dict-like interface for this so for simplicity we provide dicts!
    mocker.patch("rsautils.rsa.decoder.decode",
                 return_value=({
                     "encryptedData": None,
                     "encryptionAlgorithm": {
                         "algorithm": "Wrong Data."
                     }
                 }, None))
    with pytest.raises(RuntimeError, match="Unknown encryption algorithm."):
        priv.decrypt(b"")


def test_sign(keyset, hashf, crt):
    template_key = keyset[0]
    priv = localize_keys(template_key, crt=crt)[1]
    signature = base64.b64decode(priv.sign(standard_payload, sha=hashf))
    cr_hashf = getattr(hashes, hashf.upper())
    template_key.public_key().verify(signature, standard_payload.encode("utf-8"), padding.PKCS1v15(), cr_hashf())


def test_sign_validates(mocker, keyset, hashf):
    priv = localize_keys(keyset[0])[1]
    fakeasn1 = b"A" * (priv.bsize - 10)
    mocker.patch("rsautils.rsa.encoder.encode", return_value=fakeasn1)
    with pytest.raises(RuntimeError, match="Hash function too large for current key."):
        priv.sign("ABBA", hashf)


def test_verify(keyset, hashf):
    template_key = keyset[0]
    pubkey = localize_keys(template_key)[0]
    cr_hashf = getattr(hashes, hashf.upper())
    signature = template_key.sign(standard_payload.encode("utf-8"), padding.PKCS1v15(), cr_hashf())
    assert pubkey.verify(standard_payload, base64.b64encode(signature).decode("utf-8"))


def test_sign_verify(keyset, hashf, crt):
    pubkey, priv = localize_keys(keyset[0], crt=crt)
    signature = priv.sign(standard_payload, hashf)
    assert pubkey.verify(standard_payload, signature)


@pytest.mark.parametrize("flow", [-1, 1])
def test_overflow_underflow_c_rsa(keyset, flow):
    pubkey, priv = localize_keys(keyset[0])
    with pytest.raises(ValueError):
        priv.c_rsa(priv.mod * flow)
    with pytest.raises(ValueError):
        pubkey.c_rsa(pubkey.mod * flow)


@pytest.mark.parametrize("payload", [b"", b"Quick!", b"A" * 64, standard_payload.encode("utf-8")])
def test_pem_read_write(payload, tmp_path):
    pld = tmp_path / "testpem.pem"
    rsau.write_pem(pld, "PKCS8", payload)
    res = rsau.read_pem(pld, "PKCS8")
    assert res == payload


def test_pem_read_validates_subtype(tmp_path):
    pld = tmp_path / "testpem.pem"
    with open(pld, "w", encoding="ascii") as fi:
        fi.write("-----BEGIN GARBAGE DATA-----\n")
        fi.write("This is a thesis on the legality of... hm... legality of what?\n")
        fi.write("-----END RSA PUBLIC KEY-----\n")
    with pytest.raises(IOError):
        rsau.read_pem(pld, "PKCS1_PUB")


def test_pem_read_validates_end(tmp_path):
    pld = tmp_path / "testpem.pem"
    with open(pld, "w", encoding="ascii") as fi:
        fi.write("-----BEGIN RSA PRIVATE KEY-----\n")
        fi.write("Does the carpet?\n")
        fi.write("Match the drapes?\n")
        fi.write("\n" * 80)
        fi.write("No really. Think about it.")
        fi.write("\n" * 100)
        fi.write("Bye now.")
    with pytest.raises(IOError):
        rsau.read_pem(pld, "PKCS1_PRIV")


def test_pem_read_nonbase64(tmp_path):
    pld = tmp_path / "testpem.pem"
    with open(pld, "w", encoding="ascii") as fi:
        fi.write("-----BEGIN RSA PUBLIC KEY-----\n")
        fi.write("woah woah woah\n")
        fi.write("pipebomb\n")
        fi.write("so cool\n")
        fi.write("I wonder what happens if I-\n")
        fi.write("-----END RSA PUBLIC KEY-----\n")
    with pytest.raises(binascii.Error):
        rsau.read_pem(pld, "PKCS1_PUB")


def test_mgf1_validates(hashf):
    hlen = rsau.HASH_TLL[hashf][2]
    seed = b"\x00" * hlen
    with pytest.raises(ValueError, match="Mask too long for the specified hash function"):
        rsau.mgf1(seed, 2**32 * (hlen + 1), hashf)
