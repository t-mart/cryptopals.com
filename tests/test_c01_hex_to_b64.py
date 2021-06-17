from cryptopals.bintext import b16dec, b64enc


def test_challenge() -> None:
    input_str = (
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573"
        "206d757368726f6f6d"
    )
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    actual = b64enc(b16dec(input_str))

    assert expected == actual
