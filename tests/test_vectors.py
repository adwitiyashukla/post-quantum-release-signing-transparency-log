import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from pqsign import note

RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
]
ACVP = json.loads((Path(__file__).parent / "vectors" / "acvp_mldsa.json").read_text())
PRIVATE = {"ML-DSA-44": mldsa.MLDSA44PrivateKey, "ML-DSA-65": mldsa.MLDSA65PrivateKey}
PUBLIC = {"ML-DSA-44": mldsa.MLDSA44PublicKey, "ML-DSA-65": mldsa.MLDSA65PublicKey}


@pytest.mark.parametrize("seed,public,message,signature", RFC8032)
def test_rfc8032_ed25519(seed, public, message, signature):
    sk = note.SecretKey("rfc8032", note.ED25519, bytes.fromhex(seed))
    assert sk.public.key.hex() == public
    assert sk.sign(bytes.fromhex(message)).payload.hex() == signature


@pytest.mark.parametrize("case", ACVP["keyGen"], ids=lambda c: f"{c['parameterSet']}-{c['tcId']}")
def test_acvp_mldsa_keygen_from_seed(case):
    key = PRIVATE[case["parameterSet"]].from_seed_bytes(bytes.fromhex(case["seed"]))
    assert key.public_key().public_bytes_raw().hex() == case["pk"]
    if case["parameterSet"] == "ML-DSA-44":
        assert note.SecretKey("acvp", note.MLDSA44, bytes.fromhex(case["seed"])).public.key.hex() == case["pk"]


@pytest.mark.parametrize("case", ACVP["sigVer"], ids=lambda c: f"{c['parameterSet']}-{c['tcId']}")
def test_acvp_mldsa_sigver_with_context(case):
    key = PUBLIC[case["parameterSet"]].from_public_bytes(bytes.fromhex(case["pk"]))
    try:
        key.verify(bytes.fromhex(case["signature"]), bytes.fromhex(case["message"]), bytes.fromhex(case["context"]))
        ok = True
    except InvalidSignature:
        ok = False
    assert ok is case["testPassed"]


def test_ed25519_rejects_other_message():
    seed, _, message, signature = RFC8032[1]
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key()
    with pytest.raises(InvalidSignature):
        key.verify(bytes.fromhex(signature), bytes.fromhex(message) + b"x")
