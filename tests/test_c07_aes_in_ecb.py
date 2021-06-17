from cryptopals.bintext import b64dec
from tests.fixtures import data_file_contents
from cryptopals.aes import ecb_decrypt
from cryptopals.padding import pkcs7_unpad


def test_challenge() -> None:
    ct = b64dec(data_file_contents("c07_aes_in_ecb.txt"))

    key = b"YELLOW SUBMARINE"

    pt = ecb_decrypt(ct, key)

    # this is definitely of an error by the cryptopals folks:
    # this challenge doesn't mention anything about padding, but there are 4 b"\x04"
    # bytes at the end of the plaintext above.
    pt = pkcs7_unpad(pt)

    assert pt.startswith(b"I'm back and I'm ringin' the bell \n")
    assert len(pt) == 2876
