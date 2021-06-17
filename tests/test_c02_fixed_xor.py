from cryptopals.bintext import b16dec, b16enc
from cryptopals.xor import xor_bytes


def test_challenge() -> None:
    a = "1c0111001f010100061a024b53535009181c"
    b = "686974207468652062756c6c277320657965"
    expected = "746865206b696420646f6e277420706c6179".upper()

    actual = b16enc(xor_bytes(b16dec(a), b16dec(b)))

    assert expected == actual
