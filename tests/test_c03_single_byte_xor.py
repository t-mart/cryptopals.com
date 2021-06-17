from cryptopals.bintext import b16dec
from cryptopals.xor import score_single_byte_xor_keys


def test_challenge() -> None:
    ct = b16dec("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    best = next(iter(score_single_byte_xor_keys(ct)))

    # cryptopals doesn't reveal the answers, i only know that these are correct because
    # i solved the challenge before writing the test.
    assert best.msg == b"Cooking MC's like a pound of bacon"
    assert best.key == b"X"
