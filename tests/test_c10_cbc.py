from cryptopals.padding import pkcs7_unpad
from tests.fixtures import data_file_contents
from cryptopals.bintext import b64dec
from cryptopals.aes import BLK_SZ_BYTES, cbc_decrypt


def test_challenge() -> None:
    ct = b64dec(data_file_contents("c10_cbc.txt"))
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * BLK_SZ_BYTES

    decrypted = cbc_decrypt(ct, key, iv)
    unpadded = pkcs7_unpad(decrypted)

    assert unpadded.startswith(b"I'm back and I'm ringin' the bell \n")
    assert len(unpadded) == 2876