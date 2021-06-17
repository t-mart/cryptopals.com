from cryptopals.bintext import b64dec
from cryptopals.xor import find_repeating_xor_key, repeating_key_xor
from tests.fixtures import data_file_contents
from cryptopals.hamming import hamming_distance


def test_challenge() -> None:
    ct = b64dec(data_file_contents("c06_breaking_repeating_key_xor.txt"))

    key = find_repeating_xor_key(ct)

    pt = repeating_key_xor(ct, key)

    assert key == b'Terminator X: Bring the noise'
    assert pt.startswith(b"I'm back and I'm ringin' the bell \n")


def test_hamming() -> None:
    a = b"this is a test"
    b = b"wokka wokka!!!"
    expected = 37

    assert hamming_distance(a, b) == expected
