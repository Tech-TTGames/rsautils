# pylint: disable=protected-access,missing-module-docstring
# Copyright (c) 2025-present Tech. TTGames
# SPDX-License-Identifier: EPL-2.0
import binascii
import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

import rsautils
import rsautils.rsa as rsau
from rsautils.rsa import HASH_TLL

TARGET_SIZES = [1024, 2048, 3072, 4096]
e = 65537
standard_payload = "The quick brown fox jumps over the lazy dog1234567890!@#$%^&*()-_=+[{}];:\\|<>,./?~`'\""
location = pathlib.Path(__file__).parent
known_keys = {}
for target in TARGET_SIZES:
    loc = location / "data" / f"rsa_{target}"
    with open(loc, "rb") as f:
        known_keys[target] = (serialization.load_pem_private_key(f.read(), None), loc)


def localize_keys(pk: rsa.RSAPrivateKey, crt: bool = True) -> tuple[rsau.RSAPubKey, rsau.RSAPrivKey]:
    privs = pk.private_numbers()
    pubs = pk.public_key().public_numbers()
    if crt:
        pkey = rsau.RSAPrivKey(pubs.n, pubs.e, privs.d, privs.p, privs.q, privs.dmp1, privs.dmq1, privs.iqmp)
    else:
        pkey = rsau.RSAPrivKey(pubs.n, pubs.e, privs.d)
    pubk = rsau.RSAPubKey(pubs.n, pubs.e)
    return pubk, pkey


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
    template_key, _ = known_keys[keysize]
    pubs = template_key.public_key().public_numbers()
    privs = template_key.private_numbers()
    mocker.patch("rsautils.keygen.generate_key_pair",
                 return_value=((pubs.n, pubs.e), (pubs.n, privs.d, privs.p, privs.q)))
    reskey = rsau.RSAPrivKey.generate(keysize, pubs.e)
    assert_pkeys_equal(reskey, template_key)


@pytest.mark.parametrize("keysize", TARGET_SIZES)
def test_private_import(keysize):
    template_key, source = known_keys[keysize]
    reskey = rsau.RSAPrivKey.import_key(source)
    assert_pkeys_equal(reskey, template_key)


@pytest.mark.parametrize("errtp", ["pkalgo", "pkver", "wrapperver"])
def test_private_import_validates(errtp):
    fil = location / "data" / f"lie_{errtp}"
    with pytest.raises(IOError):
        rsautils.RSAPrivKey.import_key(fil)


@pytest.mark.parametrize("keysize", TARGET_SIZES)
def test_public_import(keysize):
    template_key, source = known_keys[keysize]
    pubs = template_key.public_key().public_numbers()
    pubkey = rsau.RSAPubKey.import_key(source.with_suffix(".pub"))
    assert pubkey.mod == pubs.n
    assert pubkey.expo == pubs.e


@pytest.mark.parametrize("keysize", TARGET_SIZES)
def test_private_export(keysize, tmp_path):
    template_key, _ = known_keys[keysize]
    pubs = template_key.public_key().public_numbers()
    privs = template_key.private_numbers()
    _, key = localize_keys(template_key)
    des = tmp_path / f"testkey_{keysize}"
    key.export(des)
    with open(des, "rb") as fi:
        interkey = serialization.load_pem_private_key(fi.read(), None)
    assert interkey.private_numbers() == privs
    assert interkey.public_key().public_numbers() == pubs


@pytest.mark.parametrize("keysize", TARGET_SIZES)
def test_private_export_noncrt(keysize, tmp_path):
    template_key, _ = known_keys[keysize]
    _, key = localize_keys(template_key, crt=False)
    with pytest.raises(NotImplementedError):
        key.export(tmp_path)


@pytest.mark.parametrize("keysize", TARGET_SIZES)
def test_public_export(keysize, tmp_path):
    template_key, _ = known_keys[keysize]
    pubs = template_key.public_key().public_numbers()
    key = rsau.RSAPubKey(pubs.n, pubs.e)
    des = tmp_path / f"testkey_{keysize}.pub"
    key.export(des)
    with open(des, "rb") as fi:
        interkey = serialization.load_pem_public_key(fi.read())
    assert interkey.public_numbers() == pubs


@pytest.mark.parametrize("keysize", TARGET_SIZES)
@pytest.mark.parametrize("hashf", rsau.HASH_TLL.keys())
@pytest.mark.parametrize("crt", [True, False])
def test_encrypt_decrypt(keysize, hashf, crt):
    template_key, _ = known_keys[keysize]
    pubkey, priv = localize_keys(template_key, crt)
    hlen = HASH_TLL[hashf][2]
    max_len = pubkey.bsize - 2 * (hlen + 1)
    if max_len <= 0:
        pytest.skip(f"Key size {keysize} is too small for {hashf}.")
    payload = standard_payload.encode("utf-8")[:max_len]
    ciphtext = pubkey.encrypt(payload, hashf=hashf)
    cleartext = priv.decrypt(ciphtext)
    assert cleartext == payload


@pytest.mark.parametrize("keysize", TARGET_SIZES)
@pytest.mark.parametrize("crt", [True, False])
def test_encrypt_decrypt_academic(keysize, crt):
    with pytest.warns(RuntimeWarning, match="Academic encryption is unsecure! Please use with care."):
        template_key, _ = known_keys[keysize]
        pubkey, priv = localize_keys(template_key, crt=crt)
        ciphtext = pubkey.encrypt(standard_payload.encode("utf-8"), academic=True)
        cleartext = priv.decrypt(ciphtext).decode("utf-8")
        assert cleartext == standard_payload


@pytest.mark.parametrize("keysize", TARGET_SIZES)
@pytest.mark.parametrize("sha", rsau.HASH_TLL.keys())
def test_sign_verify(keysize, sha):
    template_key, _ = known_keys[keysize]
    pubkey, priv = localize_keys(template_key)
    signature = priv.sign(standard_payload, sha)
    assert pubkey.verify(standard_payload, signature)


@pytest.mark.parametrize("keysize", TARGET_SIZES)
@pytest.mark.parametrize("flow", [-1, 1])
def test_overflow_underflow_c_rsa(keysize, flow):
    template_key, _ = known_keys[keysize]
    pubkey, priv = localize_keys(template_key)
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
